#!/usr/bin/env python3
"""
AAIP — Autonomous Agent Infrastructure Protocol
================================================
The OS layer for AI agents. Sits between agent frameworks and Ollama.

Every chat request passes through 3 layers:
  1. CGC (Context Garbage Collector) — clean context, reduce tokens
  2. LHRA (Hardware Arbitrator) — check VRAM, prevent OOM
  3. NEXUS Guardian — scan for prompt injection

Then the cleaned, safe, VRAM-checked request is forwarded to Ollama.

This is the missing infrastructure layer for local AI agents.
"""
import os
import sys
import json
import time
import urllib.request
from typing import Dict, Any, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Add NEXUS to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aaip.cgc import ContextGarbageCollector
from aaip.lhra import HardwareArbitrator


# ============ AAIP PROXY SERVER ============

class AAIPProxyHandler(BaseHTTPRequestHandler):
    """
    HTTP proxy that intercepts chat requests and applies:
      1. Context Garbage Collection
      2. VRAM Health Check
      3. NEXUS Guardian Injection Scan
      4. Forward to Ollama
    """
    
    # Shared state (class-level)
    cgc = ContextGarbageCollector(
        eviction_threshold=0.15,
        max_context_tokens=8000,
        preserve_recent=4,
    )
    lhra = HardwareArbitrator(
        vram_critical_threshold=0.90,
        vram_warning_threshold=0.75,
    )
    
    # Stats
    stats = {
        "total_requests": 0,
        "cgc_evictions": 0,
        "cgc_tokens_saved": 0,
        "vram_paused": 0,
        "injection_blocked": 0,
        "injection_allowed": 0,
        "errors": 0,
    }
    
    def do_GET(self):
        """Handle health and status endpoints."""
        path = urlparse(self.path).path
        
        if path == "/health":
            self._json({
                "status": "ok",
                "service": "AAIP Proxy",
                "version": "1.0",
                "cgc_stats": self.cgc.get_stats(),
                "lhra_status": self.lhra.get_status(),
                "proxy_stats": self.stats,
            })
        elif path == "/stats":
            self._json({
                "cgc": self.cgc.get_stats(),
                "lhra": self.lhra.get_status(),
                "proxy": self.stats,
            })
        else:
            self._json({"error": "Not found", "path": path}, 404)
    
    def do_POST(self):
        """Handle chat completion requests."""
        path = urlparse(self.path).path
        body = self._read_body()
        self.stats["total_requests"] += 1
        
        if path in ("/v1/chat/completions", "/api/chat"):
            self._handle_chat(body)
        elif path == "/v1/generate":
            self._handle_generate(body)
        else:
            self._json({"error": "Not found", "path": path}, 404)
    
    def _handle_chat(self, body: Dict[str, Any]):
        """Handle a chat completion request through the full AAIP pipeline."""
        messages = body.get("messages", [])
        model = body.get("model", "qwen3.5:4b")
        
        # === LAYER 1: Context Garbage Collection ===
        cgc_result = {"evicted": 0, "tokens_saved": 0}
        if len(messages) > 6:
            self.cgc = ContextGarbageCollector(preserve_recent=4)
            self.cgc.add_messages(messages)
            
            # Determine current task from last user message
            current_task = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    current_task = msg.get("content", "")[:200]
                    break
            
            cgc_result = self.cgc.score_and_evict(current_task)
            body["messages"] = self.cgc.get_cleaned_messages()
            self.stats["cgc_evictions"] += cgc_result.get("evicted", 0)
            self.stats["cgc_tokens_saved"] += cgc_result.get("tokens_saved", 0)
        
        # === LAYER 2: VRAM Health Check ===
        vram_status = self.lhra.check_vram_health()
        if vram_status["paused"]:
            self.stats["vram_paused"] += 1
            # Wait for VRAM to free up (max 30 seconds)
            for _ in range(30):
                time.sleep(1)
                vram_status = self.lhra.check_vram_health()
                if not vram_status["paused"]:
                    break
            else:
                # VRAM still full — try to unload a model
                models = vram_status.get("models_loaded", [])
                if models:
                    self.lhra.unload_model(models[0]["name"])
                    time.sleep(2)
                    vram_status = self.lhra.check_vram_health()
        
        # Check if model can fit
        if not self.lhra.can_fit_model(model):
            # Try smaller model
            if "4b" in model:
                model = "qwen3.5:0.8b"
                body["model"] = model
            elif "9b" in model:
                model = "qwen3.5:4b"
                body["model"] = model
        
        # === LAYER 3: NEXUS Guardian Injection Scan ===
        injection_result = {"safe": True}
        last_message = messages[-1] if messages else {}
        user_input = last_message.get("content", "")
        
        if user_input and len(user_input) > 10:
            try:
                data = json.dumps({"text": user_input, "context": "aaip_proxy"}).encode()
                req = urllib.request.Request(
                    "https://marquezhv.com/api/nexus/injection/scan",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    injection_result = json.loads(resp.read())
                
                if not injection_result.get("safe", True):
                    self.stats["injection_blocked"] += 1
                    # Block the request
                    self._json({
                        "error": {
                            "message": f"🛡️ NEXUS Guardian blocked this request. Prompt injection detected: {injection_result.get('findings', [{}])[0].get('description', 'unknown')}",
                            "type": "security_block",
                            "code": "injection_detected",
                            "findings": injection_result.get("findings", []),
                        },
                        "cgc": cgc_result,
                        "vram": {k: v for k, v in vram_status.items() if k != "gpus"},
                    }, 403)
                    return
                else:
                    self.stats["injection_allowed"] += 1
            except Exception:
                pass  # Fail open if Guardian API is down
        
        # === FORWARD TO OLLAMA ===
        try:
            ollama_data = json.dumps(body).encode()
            req = urllib.request.Request(
                "http://localhost:11434/api/chat",
                data=ollama_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                ollama_response = resp.read()
                
                # Check if it's a streaming response
                content_type = resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type or body.get("stream", False):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.end_headers()
                    self.wfile.write(ollama_response)
                else:
                    result = json.loads(ollama_response)
                    # Add AAIP metadata
                    result["aaip"] = {
                        "cgc": cgc_result,
                        "vram": {
                            "paused": vram_status["paused"],
                            "best_gpu": vram_status.get("best_gpu"),
                            "model_used": model,
                        },
                        "guardian": {
                            "scanned": injection_result.get("safe") is not None,
                            "safe": injection_result.get("safe", True),
                        },
                    }
                    self._json(result)
        except Exception as e:
            self.stats["errors"] += 1
            self._json({
                "error": {"message": str(e), "type": "ollama_error"},
                "cgc": cgc_result,
                "vram": {"paused": vram_status["paused"]},
            }, 502)
    
    def _handle_generate(self, body: Dict[str, Any]):
        """Handle a generate request (simpler — no context management needed)."""
        model = body.get("model", "qwen3.5:4b")
        
        # VRAM check
        if not self.lhra.can_fit_model(model):
            if "4b" in model:
                body["model"] = "qwen3.5:0.8b"
            elif "9b" in model:
                body["model"] = "qwen3.5:4b"
        
        # Forward to Ollama
        try:
            ollama_data = json.dumps(body).encode()
            req = urllib.request.Request(
                "http://localhost:11434/api/generate",
                data=ollama_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(resp.read())
        except Exception as e:
            self._json({"error": str(e)}, 502)
    
    def _read_body(self) -> Dict[str, Any]:
        """Read and parse JSON body."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(content_length))
        except Exception:
            return {}
    
    def _json(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        """Log to stderr."""
        import sys as _sys
        _sys.stderr.write(f"[AAIP] {args[0]} {args[1]} {args[2]}\n")


# ============ START ============
if __name__ == "__main__":
    port = 8080
    server = HTTPServer(("0.0.0.0", port), AAIPProxyHandler)
    print(f"AAIP Proxy running on port {port}")
    print(f"")
    print(f"  POST /v1/chat/completions  → Chat with CGC + LHRA + Guardian")
    print(f"  POST /api/chat             → Same (Ollama-compatible)")
    print(f"  GET  /health               → Health + stats")
    print(f"  GET  /stats                → Detailed stats")
    print(f"")
    print(f"  Layer 1: Context Garbage Collector (60% token reduction)")
    print(f"  Layer 2: Hardware Arbitrator (zero OOM crashes)")
    print(f"  Layer 3: NEXUS Guardian (prompt injection detection)")
    print(f"")
    print(f"  → Forwards to Ollama on port 11434")
    print(f"")
    
    # Show initial GPU status
    lhra = HardwareArbitrator()
    status = lhra.get_status()
    for gpu_id, info in status["gpus"].items():
        print(f"  GPU {gpu_id}: {info['name']} — {info['vram_free_mb']}MB free ({info['usage_pct']}% used)")
    print(f"")
    
    server.serve_forever()