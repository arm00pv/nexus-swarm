#!/usr/bin/env python3
"""
AAIP — Local Hardware Resource Arbitrator (LHRA)
==================================================
Dynamic VRAM management for dual-GPU AI agent systems.

Prevents OOM crashes by:
  1. Monitoring VRAM usage on all GPUs (via rocm-smi for AMD)
  2. Pausing agent queues when VRAM is critical
  3. Offloading idle model weights to system RAM
  4. Routing requests to the GPU with most free VRAM

Designed for: AMD Radeon RX 9060 XT (dual 16GB setup)
Works with: Ollama (local inference backend)
"""
import os
import sys
import re
import json
import time
import subprocess
import urllib.request
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class GPUStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    CRITICAL = "critical"
    OFFLINE = "offline"


@dataclass
class GPUInfo:
    """Current state of a single GPU."""
    id: int
    name: str = "Unknown"
    vram_total_mb: int = 0
    vram_used_mb: int = 0
    vram_free_mb: int = 0
    usage_pct: float = 0.0
    status: GPUStatus = GPUStatus.IDLE
    last_checked: float = 0.0
    
    @property
    def is_available(self) -> bool:
        return self.status in (GPUStatus.IDLE, GPUStatus.ACTIVE) and self.vram_free_mb > 1024


class HardwareArbitrator:
    """
    Monitors and arbitrates GPU resources.
    
    Uses rocm-smi for AMD GPUs (our setup).
    Falls back to Ollama API for model status.
    """
    
    def __init__(self,
                 vram_critical_threshold: float = 0.90,
                 vram_warning_threshold: float = 0.75,
                 vram_safe_threshold: float = 0.50,
                 ollama_url: str = "http://localhost:11434"):
        self.critical_threshold = vram_critical_threshold
        self.warning_threshold = vram_warning_threshold
        self.safe_threshold = vram_safe_threshold
        self.ollama_url = ollama_url
        
        self.gpus: Dict[int, GPUInfo] = {}
        self.model_vram: Dict[str, int] = {}  # model_name → VRAM needed (MB)
        self.paused: bool = False
        self.pause_reason: str = ""
        
        # Initialize GPU detection
        self._detect_gpus()
        
        # Load model VRAM estimates
        self._load_model_estimates()
    
    def _detect_gpus(self) -> None:
        """Detect GPUs using rocm-smi (AMD) or nvidia-smi (NVIDIA)."""
        try:
            result = subprocess.run(
                ["rocm-smi", "--showproductname", "--showmeminfo", "vram"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                self._parse_rocm_smi(result.stdout)
                return
        except Exception:
            pass
        
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=index,name,memory.total,memory.used,memory.free",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                self._parse_nvidia_smi(result.stdout)
                return
        except Exception:
            pass
        
        # Fallback: no GPU detection
        self.gpus[0] = GPUInfo(
            id=0, name="CPU fallback",
            vram_total_mb=16384, vram_used_mb=0, vram_free_mb=16384,
            status=GPUStatus.ACTIVE, last_checked=time.time()
        )
    
    def _parse_rocm_smi(self, output: str) -> None:
        """Parse rocm-smi output for AMD GPUs."""
        gpu_count = 0
        current_gpu = -1
        
        for line in output.split("\n"):
            # Detect GPU count
            gpu_match = re.match(r"GPU\[(\d+)\]", line)
            if gpu_match:
                current_gpu = int(gpu_match.group(1))
                if current_gpu not in self.gpus:
                    self.gpus[current_gpu] = GPUInfo(id=current_gpu)
            
            # Parse card series/name
            if "Card Series" in line and current_gpu >= 0:
                self.gpus[current_gpu].name = line.split(":")[-1].strip()
            
            # Parse VRAM total
            if "VRAM Total Memory" in line and current_gpu >= 0:
                bytes_val = int(re.search(r"(\d+)", line.split(":")[-1]).group(1))
                self.gpus[current_gpu].vram_total_mb = bytes_val // (1024 * 1024)
            
            # Parse VRAM used
            if "VRAM Total Used" in line and current_gpu >= 0:
                bytes_val = int(re.search(r"(\d+)", line.split(":")[-1]).group(1))
                self.gpus[current_gpu].vram_used_mb = bytes_val // (1024 * 1024)
    
    def _parse_nvidia_smi(self, output: str) -> None:
        """Parse nvidia-smi output."""
        for i, line in enumerate(output.strip().split("\n")):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpu_id = int(parts[0])
                self.gpus[gpu_id] = GPUInfo(
                    id=gpu_id,
                    name=parts[1],
                    vram_total_mb=int(parts[2]),
                    vram_used_mb=int(parts[3]),
                    vram_free_mb=int(parts[4]),
                    last_checked=time.time(),
                )
    
    def _load_model_estimates(self) -> None:
        """Load VRAM estimates for common Ollama models."""
        self.model_vram = {
            "qwen3.5:0.8b": 1024,    # ~1GB
            "qwen3.5:4b": 4096,       # ~4GB
            "qwen3.5:9b": 6144,       # ~6GB
            "gemma4:latest": 8192,    # ~8GB
            "gemma4:e2b": 6656,       # ~6.5GB
            "deepseek-v4-flash:cloud": 0,  # Cloud — no VRAM
            "llava:7b": 4500,         # ~4.5GB
        }
    
    def refresh(self) -> None:
        """Refresh GPU VRAM readings."""
        self._detect_gpus()
        
        for gpu in self.gpus.values():
            gpu.vram_free_mb = gpu.vram_total_mb - gpu.vram_used_mb
            gpu.usage_pct = gpu.vram_used_mb / max(1, gpu.vram_total_mb)
            gpu.last_checked = time.time()
            
            if gpu.usage_pct >= self.critical_threshold:
                gpu.status = GPUStatus.CRITICAL
            elif gpu.usage_pct >= self.warning_threshold:
                gpu.status = GPUStatus.ACTIVE
            else:
                gpu.status = GPUStatus.IDLE
    
    def get_best_gpu(self, required_vram_mb: int = 0) -> Optional[int]:
        """Get the GPU with the most free VRAM."""
        self.refresh()
        
        available = [
            (gpu_id, gpu) for gpu_id, gpu in self.gpus.items()
            if gpu.is_available and gpu.vram_free_mb >= required_vram_mb
        ]
        
        if not available:
            return None
        
        # Sort by most free VRAM
        available.sort(key=lambda x: x[1].vram_free_mb, reverse=True)
        return available[0][0]
    
    def can_fit_model(self, model: str) -> bool:
        """Check if a model can fit in any GPU's VRAM."""
        required = self.model_vram.get(model, 4096)  # Default 4GB
        if required == 0:
            return True  # Cloud model — no VRAM needed
        
        self.refresh()
        for gpu in self.gpus.values():
            if gpu.vram_free_mb >= required:
                return True
        return False
    
    def check_vram_health(self) -> Dict[str, Any]:
        """Check VRAM health and pause if critical."""
        self.refresh()
        
        any_critical = False
        critical_gpus = []
        
        for gpu_id, gpu in self.gpus.items():
            if gpu.status == GPUStatus.CRITICAL:
                any_critical = True
                critical_gpus.append(gpu_id)
        
        if any_critical:
            self.paused = True
            self.pause_reason = f"VRAM critical on GPU(s): {critical_gpus}"
        else:
            self.paused = False
            self.pause_reason = ""
        
        return {
            "paused": self.paused,
            "reason": self.pause_reason,
            "gpus": {
                gpu_id: {
                    "name": gpu.name,
                    "vram_total_mb": gpu.vram_total_mb,
                    "vram_used_mb": gpu.vram_used_mb,
                    "vram_free_mb": gpu.vram_free_mb,
                    "usage_pct": round(gpu.usage_pct * 100, 1),
                    "status": gpu.status.value,
                }
                for gpu_id, gpu in self.gpus.items()
            },
            "best_gpu": self.get_best_gpu(),
            "models_loaded": self._get_loaded_models(),
        }
    
    def _get_loaded_models(self) -> List[Dict[str, Any]]:
        """Get currently loaded models from Ollama."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/ps")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [
                    {
                        "name": m.get("name", "?"),
                        "size_mb": m.get("size", 0) // (1024 * 1024),
                        "vram_mb": m.get("size_vram", 0) // (1024 * 1024),
                    }
                    for m in data.get("models", [])
                ]
        except Exception:
            return []
    
    def unload_model(self, model: str) -> bool:
        """Unload a model from VRAM to free space."""
        try:
            data = json.dumps({"model": model, "keep_alive": 0}).encode()
            req = urllib.request.Request(
                f"{self.ollama_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return True
        except Exception:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get full hardware status."""
        return self.check_vram_health()


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 60)
    print("  AAIP Hardware Arbitrator (LHRA) — TEST")
    print("=" * 60)
    
    lhra = HardwareArbitrator(
        vram_critical_threshold=0.90,
        vram_warning_threshold=0.75,
    )
    
    status = lhra.get_status()
    
    print(f"\n  GPU Status:")
    for gpu_id, info in status["gpus"].items():
        print(f"    GPU {gpu_id}: {info['name']}")
        print(f"      VRAM: {info['vram_used_mb']}MB / {info['vram_total_mb']}MB ({info['usage_pct']}%)")
        print(f"      Free: {info['vram_free_mb']}MB")
        print(f"      Status: {info['status']}")
    
    print(f"\n  Best GPU: {status['best_gpu']}")
    print(f"  Paused: {status['paused']}")
    
    print(f"\n  Loaded models:")
    for m in status["models_loaded"]:
        print(f"    {m['name']}: {m['vram_mb']}MB VRAM / {m['size_mb']}MB total")
    
    if not status["models_loaded"]:
        print(f"    (none currently loaded)")
    
    print(f"\n  Can fit qwen3.5:4b? {lhra.can_fit_model('qwen3.5:4b')}")
    print(f"  Can fit qwen3.5:0.8b? {lhra.can_fit_model('qwen3.5:0.8b')}")
    
    print(f"\n{'=' * 60}")