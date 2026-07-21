#!/usr/bin/env python3
"""
NEXUS Swarm API — Size 2: HTTP API Server
=========================================
Exposes the 7-agent swarm as REST endpoints on marquezhv.com.

Endpoints:
  POST /api/nexus/analyze    — Run full swarm on code snippet
  GET  /api/nexus/sessions    — List past sessions from ALEPH
  GET  /api/nexus/session/:id — Get session details
  POST /api/nexus/github      — Analyze a GitHub repo
  GET  /api/nexus/health      — Health check
  GET  /api/nexus/agents       — List agent info

Runs on port 8002 locally, proxied via marquezhv.com.
"""
import sys
import os
import json
import time
import sqlite3
import urllib.request

sys.path.insert(0, "/home/zixen15/nexus")
sys.path.insert(0, "/home/zixen15/brains")

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import swarm core
from swarm_core import (
    swarm_analyze, aleph_inject, aleph_query,
    AGENT_MODELS, call_llm, lean4_verify, conscience_validate,
    ALEPH_DB
)
from llm_scheduler import SCHEDULER, Priority
from nexus_integration import (
    MAMBA_SCANNER, EGO_TRACKER,
    sophia_distill, boif_select_brain, hivemind_consensus,
    pi_health_check, get_mcp_tools, semb_status, ocl_status,
    get_full_system_status,
)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# ============ GITHUB INTEGRATION ============
def fetch_github_file(repo, path, branch="main"):
    """Fetch a file from a GitHub repo."""
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    try:
        r = urllib.request.Request(url, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3.raw",
        })
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.read().decode()
    except Exception as e:
        sys.stderr.write(f"[NEXUS API] GitHub fetch failed: {e}\n")
        return None

def list_repo_python_files(repo, branch="main"):
    """List Python files in a GitHub repo using the API."""
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    try:
        r = urllib.request.Request(url, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(r, timeout=30) as resp:
            data = json.loads(resp.read())
            return [item["path"] for item in data.get("tree", []) 
                    if item["path"].endswith(".py") and item["type"] == "blob"]
    except Exception as e:
        sys.stderr.write(f"[NEXUS API] GitHub list failed: {e}\n")
        return []

def create_github_pr(repo, branch, title, body, head_branch="nexus-fix"):
    """Create a pull request on GitHub."""
    url = f"https://api.github.com/repos/{repo}/pulls"
    try:
        data = json.dumps({
            "title": title,
            "body": body,
            "head": head_branch,
            "base": branch,
        }).encode()
        r = urllib.request.Request(url, data=data, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(r, timeout=30) as resp:
            result = json.loads(resp.read())
            return {"pr_url": result.get("html_url", ""), "pr_number": result.get("number", 0)}
    except Exception as e:
        return {"error": str(e)}

# ============ HTTP HANDLER ============
class NexusAPIHandler(BaseHTTPRequestHandler):
    def _json(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def do_OPTIONS(self):
        self._json({"status": "ok"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/nexus/health":
            self._json({
                "status": "healthy",
                "service": "NEXUS Swarm",
                "version": "3.0.0",
                "agents": 7,
                "aleph_edges": self._aleph_count(),
            })

        elif path == "/api/nexus/agents":
            # Public agent info — NO internal model names exposed
            agents = [
                {"name": "SCOUT", "role": "Fast code scanning", "icon": "🔍"},
                {"name": "ARCHITECT", "role": "Deep code analysis", "icon": "🏗️"},
                {"name": "FORGE", "role": "Code generation + iterative refinement", "icon": "🔨"},
                {"name": "JUDGE", "role": "Fix evaluation", "icon": "⚖️"},
                {"name": "PROVER", "role": "Formal verification (Lean4)", "icon": "📐"},
                {"name": "GUARDIAN", "role": "Anti-hallucination (50K verified claims)", "icon": "🛡️"},
                {"name": "SCRIBE", "role": "PR documentation", "icon": "📝"},
            ]
            self._json({"agents": agents, "count": len(agents)})

        elif path == "/api/nexus/sessions":
            sessions = aleph_query("nexus_session", limit=20)
            self._json({"sessions": sessions, "count": len(sessions)})

        elif path == "/api/nexus/queue":
            # LLM scheduler status
            status = SCHEDULER.get_status()
            self._json(status)

        elif path == "/api/nexus/darwin/status":
            # NEXUS-DARWIN evolution status
            from nexus_darwin import get_evolution_status
            self._json(get_evolution_status())

        elif path == "/api/nexus/darwin/prompts":
            # View current evolved prompts
            from nexus_darwin import load_prompts
            prompts = load_prompts()
            self._json({"prompts": prompts, "count": len(prompts)})

        elif path == "/api/nexus/darwin/history":
            # View mutation history
            from nexus_darwin import nexus_query
            results = nexus_query("darwin_cycle", limit=50)
            self._json({"history": results, "count": len(results)})

        elif path == "/api/nexus/system":
            # Full system status — ALL integrated components
            self._json(get_full_system_status())

        elif path == "/api/nexus/mamba/scan":
            # Mamba-3 SSM fast code scanner (CPU, no GPU needed)
            code = parse_qs(urlparse(self.path).query).get("code", [""])[0]
            if not code:
                self._json({"error": "code parameter required"}, 400)
            else:
                self._json(MAMBA_SCANNER.scan(code))

        elif path == "/api/nexus/semb":
            self._json(semb_status())

        elif path == "/api/nexus/ocl":
            self._json(ocl_status())

        elif path == "/api/nexus/pi":
            self._json(pi_health_check())

        elif path == "/api/nexus/mamba-gpu/status":
            from mamba_gpu_bridge import get_mamba_gpu_status
            self._json(get_mamba_gpu_status())

        elif path == "/api/nexus/omni/brain":
            # OMNI-BRAIN modules — direct access to 448 brain files
            self._json({
                "status": "connected",
                "modules": {
                    "mcp_tools": 96,
                    "boif_brain_files": 139,
                    "swarm_modules": 6,
                    "running_daemons": ["prometheus", "autonomos", "semb", "ocl"],
                }
            })

        elif path == "/api/nexus/omni/signals":
            # PROMETHEUS/ATLAS trading signals (live from ALEPH)
            import sqlite3 as sq
            conn = sq.connect(ALEPH_DB, timeout=5)
            rows = conn.execute("SELECT source, target FROM edges WHERE domain='trading_insights' ORDER BY created_at DESC LIMIT 10").fetchall()
            conn.close()
            self._json({"signals": [{"source": r[0], "signal": r[1][:200]} for r in rows], "count": len(rows)})

        elif path == "/api/nexus/omni/research":
            # AUTONOMOS research findings (live from ALEPH)
            import sqlite3 as sq
            conn = sq.connect(ALEPH_DB, timeout=5)
            rows = conn.execute("SELECT source, target FROM edges WHERE domain='autonomous' ORDER BY created_at DESC LIMIT 10").fetchall()
            conn.close()
            self._json({"research": [{"source": r[0], "finding": r[1][:200]} for r in rows], "count": len(rows)})

        elif path == "/api/nexus/ast/info":
            code_param = parse_qs(parsed.query).get("code", [""])[0]
            if code_param:
                from nexus_ast import analyze_code
                self._json(analyze_code(code_param))
            else:
                self._json({"error": "code parameter required"}, 400)

        elif path == "/api/nexus/scan/status":
            from nexus_unified import get_unified_status
            self._json(get_unified_status())

        elif path == "/api/nexus/sbom/status":
            from nexus_sbom import get_sbom_status
            self._json(get_sbom_status())

        elif path == "/api/nexus/diff/status":
            from nexus_diff_scanner import get_diff_scan_status
            self._json(get_diff_scan_status())

        elif path == "/api/nexus/supabase/status":
            from nexus_supabase import get_sync_status
            self._json(get_sync_status())

        elif path == "/api/nexus/autonomos/status":
            from nexus_autonomos import get_status
            self._json(get_status())

        elif path == "/api/nexus/injection/info":
            from nexus_injection import INJECTION_PATTERNS
            self._json({
                "scanner": "prompt_injection",
                "patterns": len(INJECTION_PATTERNS),
                "categories": ["override", "jailbreak", "smuggling", "escape", "social",
                              "capability", "exfiltration", "tool_abuse", "encoding", "statistical"],
                "endpoints": {
                    "scan": "POST /api/nexus/injection/scan {text, context}",
                },
            })

        elif path == "/api/nexus/agent/info":
            self._json({
                "scanner": "ai_agent_security",
                "checks": ["unrestricted_tool", "injection_surface", "no_human_loop",
                          "shell_execution", "shell_injection", "unrestricted_file",
                          "no_error_handling", "no_output_validation", "pickle_deserialization"],
                "endpoints": {
                    "scan": "POST /api/nexus/agent/scan {code, filename}",
                    "aibom": "POST /api/nexus/aibom {code, system_name}",
                },
            })

        elif path == "/api/nexus/mcp":
            self._json(get_mcp_tools())

        elif path.startswith("/api/nexus/session/"):
            session_id = path.split("/")[-1]
            results = aleph_query(session_id, limit=10)
            self._json({"session_id": session_id, "edges": results, "count": len(results)})

        elif path == "/api/nexus/guardian/check":
            # NEXUS GUARDIAN — AI Agent Firewall
            from nexus_guardian import Guardian
            tool_name = body.get("tool_name", "")
            tool_input = body.get("tool_input", "")
            agent_reasoning = body.get("agent_reasoning", "")
            agent_code = body.get("agent_code", "")
            agent_name = body.get("agent_name", "api_agent")
            
            # Create or reuse guardian
            if not hasattr(self, '_guardian') or self._guardian.agent_name != agent_name:
                self._guardian = Guardian(agent_name=agent_name, agent_code=agent_code, aleph_logging=True)
            
            decision = self._guardian.check(tool_name, tool_input, agent_reasoning)
            self._json(decision)

        elif path == "/api/nexus/guardian/stats":
            from nexus_guardian import Guardian
            if hasattr(self, '_guardian'):
                self._json(self._guardian.get_stats())
            else:
                self._json({"error": "No guardian active. Call /api/nexus/guardian/check first."})

        elif path == "/api/nexus/guardian/audit":
            from nexus_guardian import Guardian
            if hasattr(self, '_guardian'):
                limit = int(body.get("limit", 50))
                self._json({"audit_log": self._guardian.get_audit_log(limit)})
            else:
                self._json({"audit_log": []})

        else:
            self._json({"error": "Not found", "path": path}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_body()
        except Exception:
            self._json({"error": "Invalid JSON body"}, 400)
            return
        if not body:
            self._json({"error": "Empty body"}, 400)
            return

        if path == "/api/nexus/analyze":
            code = body.get("code", "")
            language = body.get("language", "python")
            
            if not code:
                self._json({"error": "No code provided"}, 400)
                return
            
            sys.stderr.write(f"\n[NEXUS API] Analyze request: {len(code)} chars, {language}\n")
            
            result = swarm_analyze(code, language)
            
            self._json({
                "session_id": result["session_id"],
                "summary": result["summary"],
                "issues": result["agents"]["scout"].get("issues", []),
                "fixed_code": result["agents"]["forge"].get("fixed_code", ""),
                "verdict": result["agents"]["judge"].get("verdict", {}),
                "pr_description": result["agents"]["scribe"].get("pr_description", ""),
                "lean4_verification": result["agents"]["prover"].get("verified_claims", []),
                "conscience_validation": result["agents"]["guardian"].get("validations", []),
            })

        elif path == "/api/nexus/github":
            repo = body.get("repo", "")  # e.g. "arm00pv/propkeep"
            file_path = body.get("path", "")
            branch = body.get("branch", "main")
            
            if not repo or not file_path:
                self._json({"error": "repo and path required"}, 400)
                return
            
            # Fetch file from GitHub
            code = fetch_github_file(repo, file_path, branch)
            if not code:
                self._json({"error": f"Could not fetch {file_path} from {repo}"}, 404)
                return
            
            # Determine language
            lang = "python" if file_path.endswith(".py") else "text"
            
            sys.stderr.write(f"\n[NEXUS API] GitHub analyze: {repo}/{file_path} ({len(code)} chars)\n")
            
            result = swarm_analyze(code, lang)
            
            self._json({
                "repo": repo,
                "file": file_path,
                "branch": branch,
                "session_id": result["session_id"],
                "summary": result["summary"],
                "issues": result["agents"]["scout"].get("issues", []),
                "verdict": result["agents"]["judge"].get("verdict", {}),
                "pr_description": result["agents"]["scribe"].get("pr_description", ""),
            })

        elif path == "/api/nexus/github/scan":
            # Scan all Python files in a repo
            repo = body.get("repo", "")
            branch = body.get("branch", "main")
            max_files = body.get("max_files", 3)
            
            if not repo:
                self._json({"error": "repo required"}, 400)
                return
            
            files = list_repo_python_files(repo, branch)
            if not files:
                self._json({"error": "No Python files found or repo not accessible"}, 404)
                return
            
            results = []
            for f in files[:max_files]:
                code = fetch_github_file(repo, f, branch)
                if code:
                    r = swarm_analyze(code, "python")
                    results.append({
                        "file": f,
                        "issues": r["summary"]["issues_found"],
                        "verdict": r["summary"]["verdict"],
                        "score": r["summary"]["judge_score"],
                    })
            
            self._json({
                "repo": repo,
                "files_scanned": len(results),
                "total_files": len(files),
                "results": results,
            })

        elif path == "/api/nexus/github/create-fix":
            # Create a fix branch and commit the fixed code
            repo = body.get("repo", "")
            file_path = body.get("path", "")
            branch = body.get("branch", "main")
            fixed_code = body.get("fixed_code", "")
            pr_description = body.get("pr_description", "NEXUS auto-fix")
            
            if not repo or not file_path or not fixed_code:
                self._json({"error": "repo, path, and fixed_code required"}, 400)
                return
            
            # Create a new branch
            branch_name = f"nexus-fix-{int(time.time())}"
            try:
                # Get the SHA of the base branch
                url = f"https://api.github.com/repos/{repo}/git/refs/heads/{branch}"
                r = urllib.request.Request(url, headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"})
                with urllib.request.urlopen(r, timeout=30) as resp:
                    ref_data = json.loads(resp.read())
                    base_sha = ref_data["object"]["sha"]
                
                # Create new branch
                url = f"https://api.github.com/repos/{repo}/git/refs"
                data = json.dumps({"ref": f"refs/heads/{branch_name}", "sha": base_sha}).encode()
                r = urllib.request.Request(url, data=data, headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"})
                with urllib.request.urlopen(r, timeout=30) as resp:
                    json.loads(resp.read())
                
                # Get current file SHA
                url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch_name}"
                r = urllib.request.Request(url, headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"})
                with urllib.request.urlopen(r, timeout=30) as resp:
                    file_data = json.loads(resp.read())
                    file_sha = file_data.get("sha", "")
                
                # Update file on new branch
                import base64
                url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
                data = json.dumps({
                    "message": f"NEXUS: Auto-fix security issues in {file_path}\n\n{pr_description[:500]}",
                    "content": base64.b64encode(fixed_code.encode()).decode(),
                    "sha": file_sha,
                    "branch": branch_name,
                }).encode()
                r = urllib.request.Request(url, data=data, headers={"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"})
                r.get_method = lambda: "PUT"
                with urllib.request.urlopen(r, timeout=30) as resp:
                    commit_data = json.loads(resp.read())
                
                # Create PR
                pr_result = create_github_pr(repo, branch, f"NEXUS: Fix {file_path}", pr_description, branch_name)
                
                self._json({
                    "status": "success",
                    "branch": branch_name,
                    "commit_sha": commit_data.get("commit", {}).get("sha", ""),
                    "pr": pr_result,
                })
            except Exception as e:
                self._json({"error": str(e), "status": "failed"}, 500)

        elif path == "/api/nexus/mamba/scan":
            # Mamba-3 SSM scan via POST
            code = body.get("code", "")
            if not code:
                self._json({"error": "code required"}, 400)
            else:
                self._json(MAMBA_SCANNER.scan(code))

        elif path == "/api/nexus/hivemind":
            # Multi-agent consensus on fix quality
            self._json(hivemind_consensus(
                body.get("original", ""),
                body.get("fixed", ""),
                body.get("issues", []),
            ))

        elif path == "/api/nexus/boif/delegate":
            # BOIF trust-weighted brain selection
            self._json(boif_select_brain(
                body.get("capability", "code_analysis"),
                body.get("task", ""),
            ))

        elif path == "/api/nexus/mamba-gpu/scan":
            # GPU-accelerated Mamba-3 SSM scan
            from mamba_gpu_bridge import GpuMambaRunner
            runner = GpuMambaRunner()
            if runner.load(force_gpu=True):
                result = runner.scan(body.get("code", ""))
                runner.unload()
                self._json(result)
            else:
                self._json({"error": "Failed to load Mamba model on GPU"}, 500)

        elif path == "/api/nexus/mamba-gpu/train":
            # Train Mamba LoRA on code patterns (GPU)
            from mamba_gpu_bridge import train_mamba_lora
            steps = body.get("steps", 50)
            result = train_mamba_lora(steps=steps, lr=3e-4)
            self._json(result)

        elif path == "/api/nexus/omni/orchestrate":
            # BOIF Agent Orchestrator — delegate task to best brain
            sys.path.insert(0, "/home/zixen15/brains")
            from boif_agent_orchestrator import orchestrate
            task = body.get("task", "")
            capability = body.get("capability", "")
            if not task:
                self._json({"error": "task required"}, 400)
                return
            result = orchestrate(task, capability, verify=True, fold=True)
            self._json(result)

        elif path == "/api/nexus/omni/mcp":
            # Call any MCP tool directly
            sys.path.insert(0, "/home/zixen15")
            import mcp_server
            tool = body.get("tool", "")
            args = body.get("args", {})
            # Whitelist of safe MCP tools (prevent arbitrary attribute access)
            safe_tools = {"query_aleph", "inject_aleph", "verify_aleph", "verify_math", "query_ollama",
                         "get_atlas_signal", "trigger_agentic_code_forge", "verify_with_lean4_mcp"}
            if not tool or tool not in safe_tools:
                self._json({"error": f"tool '{tool}' not allowed", "available": list(safe_tools)}, 403)
                return
            try:
                func = getattr(mcp_server, tool)
                result = func(**args) if args else func()
                self._json({"tool": tool, "result": result if isinstance(result, (str, int, float, list, dict)) else str(result)[:500]})
            except Exception as e:
                self._json({"error": str(e)})

        elif path == "/api/nexus/diff/scan":
            from nexus_diff_scanner import scan_commit
            repo = body.get("repo", "")
            sha = body.get("sha", "")
            if not repo:
                self._json({"error": "repo required"}, 400)
                return
            if not sha:
                from nexus_diff_scanner import get_latest_commit
                sha = get_latest_commit(repo, body.get("branch", "main"))
                if not sha:
                    self._json({"error": "Could not get latest commit"}, 404)
                    return
            result = scan_commit(repo, sha)
            self._json(result)

        elif path == "/api/nexus/ast/analyze":
            from nexus_ast import analyze_code
            code_to_analyze = body.get("code", "")
            if not code_to_analyze:
                self._json({"error": "code required"}, 400)
                return
            self._json(analyze_code(code_to_analyze, body.get("filename", "unknown")))

        elif path == "/api/nexus/scan":
            from nexus_unified import unified_scan
            repo = body.get("repo", "")
            branch = body.get("branch", "main")
            create_issues = body.get("create_issues", False)
            if not repo:
                self._json({"error": "repo required"}, 400)
                return
            result = unified_scan(repo, branch, create_issues)
            self._json(result)

        elif path == "/api/nexus/sbom/scan":
            from nexus_sbom import scan_repo
            repo = body.get("repo", "")
            branch = body.get("branch", "main")
            if not repo:
                self._json({"error": "repo required"}, 400)
                return
            result = scan_repo(repo, branch)
            self._json(result)

        elif path == "/api/nexus/supabase/sync":
            from nexus_supabase import run_sync
            result = run_sync()
            self._json(result)

        elif path == "/api/nexus/autonomos/cycle":
            from nexus_autonomos import run_cycle
            result = run_cycle()
            self._json(result)

        elif path == "/api/nexus/webhook":
            # GitHub webhook handler — triggers unified scan on push
            event = self.headers.get("X-GitHub-Event", "unknown")
            if event == "push":
                repo = body.get("repository", {}).get("full_name", "")
                # Trigger unified scan asynchronously
                try:
                    from nexus_unified import unified_scan
                    import threading
                    def run_scan():
                        try:
                            unified_scan(repo, "main", create_issues=True)
                        except Exception:
                            pass
                    threading.Thread(target=run_scan, daemon=True).start()
                except Exception:
                    pass
                self._json({
                    "status": "scan_triggered",
                    "event": "push",
                    "repo": repo,
                    "message": "NEXUS unified scan triggered (AST + Diff + SBOM)",
                })
            elif event == "pull_request":
                pr = body.get("pull_request", {})
                self._json({
                    "status": "received",
                    "event": "pull_request",
                    "action": body.get("action", ""),
                    "pr_number": pr.get("number", 0),
                    "pr_title": pr.get("title", ""),
                    "repo": body.get("repository", {}).get("full_name", ""),
                })
            else:
                self._json({"status": "received", "event": event})

        elif path == "/api/nexus/darwin/evolve":
            # Start a Darwin-Godel evolution cycle
            from nexus_darwin import run_evolution_cycle
            max_mutations = body.get("max_mutations", 3)
            
            sys.stderr.write(f"\n[NEXUS API] Darwin evolution cycle: {max_mutations} mutations\n")
            
            result = run_evolution_cycle(max_mutations=max_mutations)
            
            self._json({
                "cycle_id": result["cycle_id"],
                "baseline_score": result["baseline_score"],
                "final_score": result["final_score"],
                "total_improvement": result["total_improvement"],
                "improvements": result["improvements"],
                "regressions": result["regressions"],
                "mutations": result["mutations"],
            })

        elif path == "/api/nexus/injection/scan":
            # Prompt injection detector
            text = body.get("text", "")
            context = body.get("context", "user_input")
            
            from nexus_injection import detect_injection, is_safe, sanitize_prompt
            findings = detect_injection(text, context)
            safe = is_safe(text)
            sanitized = sanitize_prompt(text) if not safe else text
            
            self._json({
                "safe": safe,
                "findings_count": len(findings),
                "findings": findings,
                "sanitized": sanitized,
                "categories_detected": list(set(f["category"] for f in findings)),
            })

        elif path == "/api/nexus/agent/scan":
            # AI Agent Security Scanner
            code = body.get("code", "")
            filename = body.get("filename", "agent.py")
            
            from nexus_agent_scan import scan_agent_code
            findings = scan_agent_code(code, filename)
            
            self._json({
                "file": filename,
                "issues_found": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
                "findings": findings,
            })

        elif path == "/api/nexus/aibom":
            # AIBOM Generator — AI Bill of Materials
            code = body.get("code", "")
            system_name = body.get("system_name", "AI System")
            filename = body.get("filename", "agent.py")
            
            from nexus_aibom import generate_aibom
            aibom = generate_aibom(code, filename, system_name)
            
            self._json({
                "aibom": aibom,
                "risk_score": aibom.get("risk_score", 0),
                "compliance_summary": {
                    framework: {
                        "passing": sum(1 for v in checks.values() if v),
                        "total": len(checks),
                    }
                    for framework, checks in aibom.get("compliance", {}).items()
                },
            })

        elif path == "/api/nexus/autofix":
            # Auto-Fix Pipeline — find → fix → PR → verify
            repo = body.get("repo", "")
            branch = body.get("branch", "main")
            max_fixes = body.get("max_fixes", 5)
            
            if not repo:
                self._json({"error": "repo required"}, 400)
                return
            
            from nexus_autofix import auto_fix_repo
            result = auto_fix_repo(repo, branch, max_fixes)
            
            self._json(result)

        elif path == "/api/nexus/guardian/check":
            # NEXUS GUARDIAN — AI Agent Firewall
            from nexus_guardian import Guardian
            tool_name = body.get("tool_name", "")
            tool_input = body.get("tool_input", "")
            agent_reasoning = body.get("agent_reasoning", "")
            agent_code = body.get("agent_code", "")
            agent_name = body.get("agent_name", "api_agent")
            
            # Create or reuse guardian
            if not hasattr(self, '_guardian') or self._guardian.agent_name != agent_name:
                self._guardian = Guardian(agent_name=agent_name, agent_code=agent_code, aleph_logging=True)
            
            decision = self._guardian.check(tool_name, tool_input, agent_reasoning)
            self._json(decision)

        elif path == "/api/nexus/guardian/stats":
            from nexus_guardian import Guardian
            if hasattr(self, '_guardian'):
                self._json(self._guardian.get_stats())
            else:
                self._json({"error": "No guardian active. Call /api/nexus/guardian/check first."})

        elif path == "/api/nexus/guardian/audit":
            from nexus_guardian import Guardian
            if hasattr(self, '_guardian'):
                limit = int(body.get("limit", 50))
                self._json({"audit_log": self._guardian.get_audit_log(limit)})
            else:
                self._json({"audit_log": []})

        else:
            self._json({"error": "Not found", "path": path}, 404)

    def _aleph_count(self):
        try:
            with sqlite3.connect(ALEPH_DB) as conn:
                return conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        except Exception:
            return 0

# ============ START ============
if __name__ == "__main__":
    port = 8002
    server = HTTPServer(("0.0.0.0", port), NexusAPIHandler)
    print(f"NEXUS Swarm API running on port {port}")
    print(f"Endpoints:")
    print(f"  GET  /api/nexus/health")
    print(f"  POST /api/nexus/injection/scan  — Prompt Injection Detector")
    print(f"  POST /api/nexus/agent/scan     — AI Agent Security Scanner")
    print(f"  POST /api/nexus/aibom          — AIBOM Generator")
    print(f"  POST /api/nexus/autofix        — Auto-Fix Pipeline")
    print(f"  GET  /api/nexus/agents")
    print(f"  POST /api/nexus/analyze")
    print(f"  POST /api/nexus/github")
    print(f"  POST /api/nexus/github/scan")
    print(f"  GET  /api/nexus/sessions")
    server.serve_forever()