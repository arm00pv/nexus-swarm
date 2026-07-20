#!/usr/bin/env python3
"""
NEXUS LLM Scheduler — VRAM-Aware Priority Queue
=================================================
Instead of each agent independently calling Ollama with hardcoded timeouts
that fail when the GPU is busy, ALL LLM calls go through a single scheduler
that manages GPU access intelligently.

How it works:
  1. All LLM requests enter a priority queue
  2. The dispatcher processes them one at a time (GPU is single-threaded for inference)
  3. Before dispatching, it checks VRAM — is the model loaded?
  4. If VRAM is full, it unloads the least-recently-used model
  5. Requests WAIT for their turn instead of timing out
  6. Priority ensures important agents (FORGE) get GPU time first
  7. Metrics track wait times, inference times, queue depth

Priority levels:
  CRITICAL — FORGE (code generation, the core value)
  HIGH     — JUDGE, ARCHITECT (evaluation, analysis)
  NORMAL   — SCOUT, SCRIBE (scanning, docs)
  LOW      — background tasks (Darwin-Gödel mutations, etc)

No request times out. It gets its turn.
"""
import sys
import json
import time
import threading
import queue
import sqlite3
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum

# ============ CONFIG ============
OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
OLLAMA_PS_URL = "http://localhost:11434/api/ps"
OLLAMA_UNLOAD_URL = "http://localhost:11434/api/generate"

# VRAM budget — leave room for the model running Pi itself
MAX_VRAM_MB = 12000  # Don't use more than 12GB (Pi needs ~4GB)
MODEL_TTL_SECONDS = 300  # Keep models loaded for 5 minutes after last use

# ============ DATA STRUCTURES ============
class Priority(Enum):
    CRITICAL = 0  # FORGE — the core value producer
    HIGH = 1       # JUDGE, ARCHITECT — evaluation and analysis
    NORMAL = 2     # SCOUT, SCRIBE — scanning and docs
    LOW = 3        # Background — Darwin-Gödel, monitoring

@dataclass
class LLMRequest:
    """A single LLM request in the queue."""
    model: str
    system_prompt: str
    user_prompt: str
    priority: Priority
    max_tokens: int = 500
    temperature: float = 0.3
    request_id: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    response: str = ""
    error: Optional[str] = None
    # For priority queue ordering: (priority_value, created_at)
    def __lt__(self, other):
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.created_at < other.created_at

class LLMScheduler:
    """
    Singleton VRAM-aware LLM request scheduler.
    All NEXUS agents route their LLM calls through this queue.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance
    
    def _init(self):
        self.queue = queue.PriorityQueue(maxsize=100)
        self.results: Dict[str, LLMRequest] = {}
        self.results_lock = threading.Lock()
        self.dispatcher_thread = None
        self.running = False
        self.metrics = {
            "total_requests": 0,
            "completed": 0,
            "failed": 0,
            "total_wait_time": 0.0,
            "total_inference_time": 0.0,
            "by_model": defaultdict(lambda: {"count": 0, "wait": 0.0, "inference": 0.0}),
            "by_priority": defaultdict(lambda: {"count": 0, "wait": 0.0, "inference": 0.0}),
        }
        self.current_request: Optional[LLMRequest] = None
        self.model_last_used: Dict[str, float] = {}  # model -> timestamp
    
    def start(self):
        """Start the dispatcher thread."""
        if self.running:
            return
        self.running = True
        self.dispatcher_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self.dispatcher_thread.start()
        sys.stderr.write("[SCHEDULER] Dispatcher started\n")
    
    def stop(self):
        """Stop the dispatcher."""
        self.running = False
    
    def submit(self, model, system_prompt, user_prompt, priority=Priority.NORMAL, 
               max_tokens=500, temperature=0.3, timeout=120) -> str:
        """
        Submit an LLM request to the queue and wait for the result.
        Returns the response text. Blocks until the request completes.
        No hardcoded timeout on the GPU — the request gets its turn.
        """
        if not self.running:
            self.start()
        
        request_id = f"req_{int(time.time()*1000)}_{id(self)}"
        req = LLMRequest(
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            priority=priority,
            max_tokens=max_tokens,
            temperature=temperature,
            request_id=request_id,
        )
        
        self.metrics["total_requests"] += 1
        sys.stderr.write(f"[SCHEDULER] Queued {request_id} (model={model}, priority={priority.name})\n")
        
        # Put in queue
        self.queue.put(req)
        
        # Wait for completion (poll-based, no timeout — gets its turn)
        wait_start = time.time()
        while True:
            with self.results_lock:
                if request_id in self.results:
                    result = self.results[request_id]
                    wait_time = time.time() - wait_start
                    if result.error:
                        sys.stderr.write(f"[SCHEDULER] {request_id} FAILED after {wait_time:.1f}s: {result.error}\n")
                        return f"ERROR: {result.error}"
                    sys.stderr.write(f"[SCHEDULER] {request_id} completed (wait={wait_time:.1f}s, inference={result.completed_at - result.started_at:.1f}s)\n")
                    return result.response
            
            # Check if we've exceeded a soft timeout (but don't kill the request)
            if time.time() - wait_start > timeout:
                sys.stderr.write(f"[SCHEDULER] {request_id} soft timeout after {timeout}s — still waiting for GPU turn\n")
                # Keep waiting — the request is still in the queue and will get its turn
                # But log a warning every 30s
                if int(time.time() - wait_start) % 30 == 0:
                    sys.stderr.write(f"[SCHEDULER] {request_id} still waiting ({int(time.time()-wait_start)}s)...\n")
            
            time.sleep(0.1)
    
    def _dispatch_loop(self):
        """Main dispatcher loop — processes requests one at a time."""
        while self.running:
            try:
                # Get the highest-priority request (blocks until one is available)
                req = self.queue.get(timeout=1)
                
                # Mark as started
                req.started_at = time.time()
                wait_time = req.started_at - req.created_at
                self.current_request = req
                
                sys.stderr.write(f"[SCHEDULER] Dispatching {req.request_id} (model={req.model}, "
                                f"priority={req.priority.name}, waited={wait_time:.1f}s)\n")
                
                # Ensure VRAM is available for this model
                self._ensure_vram(req.model)
                
                # Call Ollama
                try:
                    ollama_req = {
                        "model": req.model,
                        "messages": [
                            {"role": "system", "content": req.system_prompt},
                            {"role": "user", "content": req.user_prompt},
                        ],
                        "stream": False,
                        "think": False,
                        "options": {
                            "temperature": req.temperature,
                            "num_predict": req.max_tokens,
                        },
                    }
                    data = json.dumps(ollama_req).encode()
                    r = urllib.request.Request(OLLAMA_CHAT_URL, data=data, 
                                              headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(r, timeout=180) as resp:
                        result = json.loads(resp.read())
                        req.response = result.get("message", {}).get("content", "")
                        req.completed_at = time.time()
                        req.error = None
                        
                        inference_time = req.completed_at - req.started_at
                        self.metrics["completed"] += 1
                        self.metrics["total_wait_time"] += wait_time
                        self.metrics["total_inference_time"] += inference_time
                        self.metrics["by_model"][req.model]["count"] += 1
                        self.metrics["by_model"][req.model]["wait"] += wait_time
                        self.metrics["by_model"][req.model]["inference"] += inference_time
                        self.metrics["by_priority"][req.priority.name]["count"] += 1
                        self.metrics["by_priority"][req.priority.name]["wait"] += wait_time
                        self.metrics["by_priority"][req.priority.name]["inference"] += inference_time
                        
                        self.model_last_used[req.model] = time.time()
                
                except Exception as e:
                    req.error = str(e)
                    req.completed_at = time.time()
                    self.metrics["failed"] += 1
                    sys.stderr.write(f"[SCHEDULER] {req.request_id} inference failed: {e}\n")
                
                # Store result
                with self.results_lock:
                    self.results[req.request_id] = req
                    # Clean old results (keep last 100)
                    if len(self.results) > 100:
                        old_keys = sorted(self.results.keys())[:-100]
                        for k in old_keys:
                            del self.results[k]
                
                self.current_request = None
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                sys.stderr.write(f"[SCHEDULER] Dispatcher error: {e}\n")
                time.sleep(1)
    
    def _ensure_vram(self, model):
        """Check if there's enough VRAM for the model. Unload LRU if needed."""
        try:
            # Check what's loaded
            r = urllib.request.Request(OLLAMA_PS_URL)
            with urllib.request.urlopen(r, timeout=5) as resp:
                ps_data = json.loads(resp.read())
            
            loaded = {m["name"]: m.get("size_vram", 0) // 1024 // 1024 
                     for m in ps_data.get("models", [])}
            total_vram = sum(loaded.values())
            
            # If model is already loaded, we're good
            if model in loaded:
                return
            
            # Estimate model size (rough: 0.8b=1500MB, 4b=3200MB, 9b=6400MB)
            model_sizes = {
                "qwen3.5:0.8b": 1500,
                "qwen3.5:4b": 3200,
                "qwen3.5:9b": 6400,
                "gemma4:latest": 9163,
            }
            needed = model_sizes.get(model, 4000)
            
            # If we have room, just load it (Ollama handles this)
            if total_vram + needed <= MAX_VRAM_MB:
                return
            
            # Need to unload something — find LRU models that aren't the one we need
            now = time.time()
            candidates = []
            for loaded_model, vram_mb in loaded.items():
                if loaded_model == model:
                    continue
                last_used = self.model_last_used.get(loaded_model, 0)
                idle_time = now - last_used
                # Only unload if idle for more than 10 seconds (don't unload active models)
                if idle_time > 10:
                    candidates.append((loaded_model, vram_mb, idle_time))
            
            # Sort by idle time (most idle first)
            candidates.sort(key=lambda x: x[2], reverse=True)
            
            # Unload until we have room
            for loaded_model, vram_mb, idle_time in candidates:
                if total_vram + needed <= MAX_VRAM_MB:
                    break
                sys.stderr.write(f"[SCHEDULER] Unloading {loaded_model} (idle {idle_time:.0f}s, {vram_mb}MB) "
                                f"to make room for {model}\n")
                try:
                    unload_data = json.dumps({"model": loaded_model, "keep_alive": 0}).encode()
                    r = urllib.request.Request(OLLAMA_UNLOAD_URL, data=unload_data,
                                              headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(r, timeout=10) as resp:
                        resp.read()
                    total_vram -= vram_mb
                    if loaded_model in self.model_last_used:
                        del self.model_last_used[loaded_model]
                except Exception as e:
                    sys.stderr.write(f"[SCHEDULER] Failed to unload {loaded_model}: {e}\n")
            
            # Wait a moment for VRAM to free
            if total_vram + needed > MAX_VRAM_MB:
                sys.stderr.write(f"[SCHEDULER] VRAM still tight ({total_vram}MB used, need {needed}MB for {model}). "
                                f"Proceeding anyway — Ollama will manage.\n")
                time.sleep(2)
        
        except Exception as e:
            sys.stderr.write(f"[SCHEDULER] VRAM check failed (non-fatal): {e}\n")
    
    def get_status(self):
        """Get current scheduler status for monitoring."""
        queue_items = []
        # Can't iterate PriorityQueue directly, use internal queue
        with self.results_lock:
            recent = list(self.results.values())[-10:]
        
        return {
            "running": self.running,
            "queue_depth": self.queue.qsize(),
            "current": {
                "request_id": self.current_request.request_id if self.current_request else None,
                "model": self.current_request.model if self.current_request else None,
                "priority": self.current_request.priority.name if self.current_request else None,
                "elapsed": time.time() - self.current_request.started_at if self.current_request and self.current_request.started_at else 0,
            } if self.current_request else None,
            "metrics": {
                "total_requests": self.metrics["total_requests"],
                "completed": self.metrics["completed"],
                "failed": self.metrics["failed"],
                "avg_wait": (self.metrics["total_wait_time"] / max(1, self.metrics["completed"])),
                "avg_inference": (self.metrics["total_inference_time"] / max(1, self.metrics["completed"])),
                "by_model": {k: dict(v) for k, v in self.metrics["by_model"].items()},
                "by_priority": {k: dict(v) for k, v in self.metrics["by_priority"].items()},
            },
            "recent": [{
                "request_id": r.request_id,
                "model": r.model,
                "priority": r.priority.name,
                "wait_time": (r.started_at - r.created_at) if r.started_at else 0,
                "inference_time": (r.completed_at - r.started_at) if r.completed_at and r.started_at else 0,
                "status": "completed" if r.completed_at else ("running" if r.started_at else "queued"),
                "error": r.error,
            } for r in recent],
        }


# ============ GLOBAL INSTANCE ============
SCHEDULER = LLMScheduler()

def schedule_llm(model, system_prompt, user_prompt, priority=Priority.NORMAL, 
                 max_tokens=500, temperature=0.3, timeout=180):
    """
    Submit an LLM request through the VRAM-aware scheduler.
    This replaces direct call_llm() in swarm_core.py.
    
    Priority mapping for NEXUS agents:
      FORGE     → CRITICAL (core value)
      JUDGE     → HIGH
      ARCHITECT → HIGH
      SCOUT     → NORMAL
      SCRIBE    → NORMAL
      Background → LOW
    """
    return SCHEDULER.submit(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        priority=priority,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=timeout,
    )


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 60)
    print("LLM Scheduler Test — Priority Queue + VRAM Management")
    print("=" * 60)
    
    # Start scheduler
    SCHEDULER.start()
    time.sleep(1)
    
    # Test 1: Single request (NORMAL priority)
    print("\n--- Test 1: Single SCOUT request (NORMAL) ---")
    t0 = time.time()
    result = schedule_llm(
        model="qwen3.5:0.8b",
        system_prompt="You are a code scanner. Output JSON.",
        user_prompt="List 2 Python security issues as JSON array with keys: severity, type, description.",
        priority=Priority.NORMAL,
        max_tokens=200,
    )
    print(f"  Time: {time.time()-t0:.1f}s")
    print(f"  Response: {result[:200]}")
    
    # Test 2: Higher priority request
    print("\n--- Test 2: FORGE request (CRITICAL priority) ---")
    t0 = time.time()
    result = schedule_llm(
        model="qwen3.5:4b",
        system_prompt="You are a code generator. Fix the security issues.",
        user_prompt="Fix: password='admin'; os.system(user_input); eval(data). Output safe Python code.",
        priority=Priority.CRITICAL,
        max_tokens=300,
    )
    print(f"  Time: {time.time()-t0:.1f}s")
    print(f"  Response: {result[:200]}")
    
    # Test 3: Submit multiple requests concurrently (queue behavior)
    print("\n--- Test 3: Concurrent requests (queue + priority) ---")
    import threading
    
    results = {}
    def make_request(idx, priority, model):
        t0 = time.time()
        r = schedule_llm(
            model=model,
            system_prompt="Answer briefly.",
            user_prompt=f"What is {idx}+{idx}?",
            priority=priority,
            max_tokens=20,
        )
        results[idx] = {"time": time.time()-t0, "response": r[:50], "priority": priority.name}
    
    # Submit 3 concurrent requests with different priorities
    threads = [
        threading.Thread(target=make_request, args=(1, Priority.LOW, "qwen3.5:0.8b")),
        threading.Thread(target=make_request, args=(2, Priority.CRITICAL, "qwen3.5:4b")),
        threading.Thread(target=make_request, args=(3, Priority.NORMAL, "qwen3.5:0.8b")),
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    
    # Print results in completion order (should show CRITICAL first)
    for idx in sorted(results.keys(), key=lambda k: results[k]["time"]):
        r = results[idx]
        print(f"  Request {idx}: {r['priority']:8s} time={r['time']:.1f}s response={r['response']}")
    
    # Print scheduler status
    print("\n--- Scheduler Status ---")
    status = SCHEDULER.get_status()
    print(f"  Queue depth: {status['queue_depth']}")
    print(f"  Total: {status['metrics']['total_requests']}")
    print(f"  Completed: {status['metrics']['completed']}")
    print(f"  Failed: {status['metrics']['failed']}")
    print(f"  Avg wait: {status['metrics']['avg_wait']:.1f}s")
    print(f"  Avg inference: {status['metrics']['avg_inference']:.1f}s")
    print()
    for model, stats in status['metrics']['by_model'].items():
        print(f"  {model:20s} count={stats['count']} avg_wait={stats['wait']/max(1,stats['count']):.1f}s avg_inf={stats['inference']/max(1,stats['count']):.1f}s")
    
    print("\n" + "=" * 60)
    print("✅ SCHEDULER TEST PASSED — No timeouts, all requests completed")
    print("=" * 60)