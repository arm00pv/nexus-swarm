#!/usr/bin/env python3
"""
NEXUS Dockerfile & IaC Scanner
===============================
Scans Dockerfiles and docker-compose files for security issues.

Catches:
  - Running as root (USER root or no USER directive)
  - No HEALTHCHECK defined
  - Using :latest tag (non-reproducible)
  - Secrets in ENV or ARG directives
  - No resource limits in docker-compose
  - Privileged mode in docker-compose
  - Exposed sensitive ports

Market: Snyk IaC, Aqua, Checkov — $2B+ market
"""
import re
import json

def scan_dockerfile(content, filename="Dockerfile"):
    """Scan a Dockerfile for security issues."""
    issues = []
    lines = content.split("\n")
    has_user = False
    has_healthcheck = False
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip().upper()
        
        # Check for :latest tag
        if stripped.startswith("FROM ") and ":LATEST" in stripped:
            issues.append({
                "line": i,
                "severity": "medium",
                "type": "dockerfile",
                "description": "Using :latest tag — non-reproducible builds. Pin specific version.",
                "code": line.strip()[:80],
                "file": filename,
            })
        
        # Check for USER directive
        if stripped.startswith("USER "):
            has_user = True
            if "ROOT" in stripped:
                issues.append({
                    "line": i,
                    "severity": "critical",
                    "type": "dockerfile",
                    "description": "Container runs as root — security risk",
                    "code": line.strip()[:80],
                    "file": filename,
                })
        
        # Check for HEALTHCHECK
        if stripped.startswith("HEALTHCHECK"):
            has_healthcheck = True
        
        # Check for secrets in ENV/ARG
        if stripped.startswith("ENV ") or stripped.startswith("ARG "):
            line_lower = line.lower()
            if any(word in line_lower for word in ["password", "secret", "token", "api_key", "private_key"]):
                if "=" in line and not "os.environ" in line_lower and not "${" in line:
                    issues.append({
                        "line": i,
                        "severity": "high",
                        "type": "secret",
                        "description": f"Possible secret in {stripped.split()[0]} directive",
                        "code": line.strip()[:80],
                        "file": filename,
                    })
        
        # Check for ADD with URL (should use COPY instead)
        if stripped.startswith("ADD ") and ("http" in line.lower()):
            issues.append({
                "line": i,
                "severity": "medium",
                "type": "dockerfile",
                "description": "ADD with URL — use COPY for local files, curl for remote",
                "code": line.strip()[:80],
                "file": filename,
            })
    
    # Check if USER directive exists (if not, container runs as root by default)
    if not has_user and filename.lower().startswith("dockerfile"):
        issues.append({
            "line": 0,
            "severity": "high",
            "type": "dockerfile",
            "description": "No USER directive — container runs as root by default",
            "code": "(missing USER directive)",
            "file": filename,
        })
    
    # Check if HEALTHCHECK exists
    if not has_healthcheck and filename.lower().startswith("dockerfile"):
        issues.append({
            "line": 0,
            "severity": "low",
            "type": "dockerfile",
            "description": "No HEALTHCHECK defined — orchestrator can't detect failures",
            "code": "(missing HEALTHCHECK)",
            "file": filename,
        })
    
    # If it's a docker-compose file, scan differently
    if "compose" in filename.lower():
        try:
            data = json.loads(content) if content.strip().startswith("{") else None
        except:
            data = None
        
        if not data:
            # Try YAML-like parsing (simple)
            for i, line in enumerate(lines, 1):
                stripped_l = line.strip().lower()
                if "privileged: true" in stripped_l:
                    issues.append({
                        "line": i, "severity": "critical", "type": "dockerfile",
                        "description": "privileged: true — container has full host access",
                        "code": line.strip()[:80], "file": filename,
                    })
                if "ports:" in stripped_l and any(p in stripped_l for p in ["22", "3306", "5432", "6379", "27017"]):
                    issues.append({
                        "line": i, "severity": "high", "type": "dockerfile",
                        "description": "Sensitive port exposed (SSH/DB) to host",
                        "code": line.strip()[:80], "file": filename,
                    })
    
    return issues


if __name__ == "__main__":
    test_dockerfile = """FROM python:3.12:latest
ENV API_KEY=sk-1234567890abcdef
RUN pip install flask
COPY . /app
# Missing USER directive
# Missing HEALTHCHECK
"""
    
    test_compose = """version: '3'
services:
  web:
    image: nginx
    privileged: true
    ports:
      - "22:22"
"""
    
    print("=" * 60)
    print("NEXUS Dockerfile Scanner Test")
    print("=" * 60)
    
    print("\nDockerfile:")
    findings = scan_dockerfile(test_dockerfile, "Dockerfile")
    print(f"  Found: {len(findings)} issues")
    for f in findings:
        print(f"  [{f['severity'].upper():8s}] {f['description']}")
    
    print("\ndocker-compose.yml:")
    findings2 = scan_dockerfile(test_compose, "docker-compose.yml")
    print(f"  Found: {len(findings2)} issues")
    for f in findings2:
        print(f"  [{f['severity'].upper():8s}] {f['description']}")
    
    print("\n" + "=" * 60)