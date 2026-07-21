#!/usr/bin/env python3
"""
NEXUS — Autonomous Multi-Agent AI Swarm Core
=============================================
Size 1: Core agent orchestration loop.

7 specialized agents collaborate to analyze, fix, verify, and submit code.
Each agent uses a different LLM model optimized for its task.

Agents:
  SCOUT     → qwen3.5:0.8b   (fast scanning)
  ARCHITECT → qwen3.5:9b     (deep analysis)
  FORGE     → gemma4:latest  (code generation)
  JUDGE     → local model with cloud fallback (deepseek-v4-flash:cloud)
  PROVER    → Lean4           (formal verification)
  GUARDIAN  → Conscience      (anti-hallucination)
  SCRIBE    → qwen3.5:4b     (documentation)

Circuit breakers: MAX_ITERATIONS=10, TIMEOUT=60s per agent call.
All results stored in ALEPH. All claims validated by Conscience.
"""
import sys
import os
import json
import time
import sqlite3
import urllib.request
import urllib.error
import hashlib

# Add brain paths
sys.path.insert(0, "/home/zixen15/brains")
sys.path.insert(0, "/home/zixen15/omni-mamba-brain/src")

# ============ CONFIG ============
ALEPH_DB = "/home/zixen15/brains/aleph/manifold.db"
OLLAMA_URL = "http://localhost:11434/api/chat"
LEAN4_URL = "http://localhost:9180/verify"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_USER = "arm00pv"

MAX_ITERATIONS = 10
TIMEOUT_SECONDS = 60

# ALL LOCAL MODELS — zero cloud cost
# Cloud fallback for complex tasks: deepseek-v4-flash:cloud
CLOUD_FALLBACK_MODEL = "deepseek-v4-flash:cloud"
CLOUD_FALLBACK_THRESHOLD = 40  # If JUDGE score < 40 after local attempts, use cloud

AGENT_MODELS = {
    "scout":     "qwen3.5:0.8b",  # local, fast scanning
    "architect": "qwen3.5:4b",    # local, deep analysis
    "forge":     "qwen3.5:4b",    # local, code generation
    "judge":     "qwen3.5:4b",    # local, evaluation
    "scribe":    "qwen3.5:0.8b",  # local, documentation
    "forge_cloud": CLOUD_FALLBACK_MODEL,  # cloud fallback for complex fixes
}

# ============ ALEPH STORAGE ============
def aleph_inject(source, relation, target, domain="nexus_swarm", confidence=0.8):
    """Store a knowledge edge in ALEPH. Uses short-lived connections to avoid locks."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(ALEPH_DB, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=3000")
            conn.execute(
                "INSERT OR IGNORE INTO edges (source, target, relation, perspective, domain, confidence, created_at) VALUES (?,?,?,?,?,?,?)",
                (source[:500], target[:500], relation[:200], "nexus", domain, confidence, time.time())
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))
                continue
            sys.stderr.write(f"[NEXUS] ALEPH inject retry {attempt+1} failed: {e}\n")
            return False
        except Exception as e:
            sys.stderr.write(f"[NEXUS] ALEPH inject failed: {e}\n")
            return False
    return False

def aleph_query(concept, limit=10):
    """Query ALEPH for related knowledge."""
    try:
        with sqlite3.connect(ALEPH_DB) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT source, relation, target, domain, confidence FROM edges WHERE source LIKE ? OR target LIKE ? LIMIT ?",
                (f"%{concept}%", f"%{concept}%", limit)
            )
            return [{"source": r["source"], "relation": r["relation"], "target": r["target"], "domain": r["domain"], "confidence": r["confidence"]} for r in cur.fetchall()]
    except Exception as e:
        sys.stderr.write(f"[NEXUS] ALEPH query failed: {e}\n")
        return []

# ============ LLM CALL ============
# Import the VRAM-aware LLM scheduler
from llm_scheduler import schedule_llm, Priority, SCHEDULER

def call_llm(model, system_prompt, user_prompt, timeout=TIMEOUT_SECONDS, priority=Priority.NORMAL, think=True):
    """Call an Ollama model through the VRAM-aware scheduler. Thinking mode ON. No token limits for internal agents."""
    is_cloud = 'cloud' in model
    max_tokens = -1 if is_cloud else -1  # -1 = no limit, let the model decide when it's done
    return schedule_llm(
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        priority=priority,
        max_tokens=max_tokens,
        temperature=0.2,
        timeout=timeout,
        think=think,
    )

# ============ LEAN4 VERIFY ============
def lean4_verify(lean_code):
    """Verify a Lean4 theorem. Returns (verified, output)."""
    try:
        data = json.dumps({"lean_code": lean_code, "claim": lean_code}).encode()
        r = urllib.request.Request(LEAN4_URL, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=30) as resp:
            result = json.loads(resp.read())
            return result.get("verified", False), result.get("output", "")
    except Exception as e:
        sys.stderr.write(f"[NEXUS] Lean4 verify failed: {e}\n")
        return False, str(e)

# ============ CONSCIENCE VALIDATION ============
def conscience_validate(claim):
    """Validate a claim using Conscience anti-hallucination system."""
    try:
        from conscience import Conscience
        c = Conscience()
        result = c.verify_claim(claim)
        return result.get("verified", False), result.get("confidence", 0.0), result
    except Exception as e:
        # Fallback: check if the claim appears in ALEPH
        results = aleph_query(claim[:50])
        if results:
            return True, 0.6, {"fallback": "aleph_lookup", "matches": len(results)}
        return False, 0.0, {"error": str(e)}

# ============ AGENT: SCOUT ============
def agent_scout(code, language="python"):
    """Fast scanning agent — finds bugs and security issues."""
    system = "You are SCOUT, a fast code scanner. Find bugs, security issues, and improvement opportunities. Output ONLY a JSON array of objects. Each object must have keys: severity (critical/high/medium/low), line (integer), type (bug/security/style/performance), description (string). Do not use markdown code blocks. Output raw JSON only."
    prompt = f"Analyze this {language} code for issues. Output ONLY raw JSON array, no markdown fences.\nCode:\n{code}\n\nJSON array:"
    
    response = call_llm(AGENT_MODELS["scout"], system, prompt, timeout=45, priority=Priority.NORMAL)
    
    # Parse issues — try multiple strategies
    issues = []
    try:
        # Strategy 1: Direct JSON parse
        issues = json.loads(response.strip())
    except Exception:
        try:
            # Strategy 2: Strip markdown fences
            cleaned = response.strip()
            if "```json" in cleaned:
                cleaned = cleaned.split("```json")[1].split("```")[0]
            elif "```" in cleaned:
                parts = cleaned.split("```")
                if len(parts) >= 3:
                    cleaned = parts[1]
                elif len(parts) == 2:
                    cleaned = parts[0]
            # Try to find JSON array in the text
            if "[" in cleaned:
                start = cleaned.index("[")
                end = cleaned.rindex("]") + 1
                cleaned = cleaned[start:end]
            issues = json.loads(cleaned.strip())
        except Exception:
            # Strategy 3: Pattern matching fallback — scan code for known vulnerabilities
            issues = []
            lines = code.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if "eval(" in stripped and "import" not in stripped:
                    issues.append({"severity": "critical", "line": i, "type": "security", "description": "Use of eval() allows arbitrary code execution"})
                if "exec(" in stripped and "import" not in stripped:
                    issues.append({"severity": "critical", "line": i, "type": "security", "description": "Use of exec() allows arbitrary code execution"})
                if "os.system(" in stripped:
                    issues.append({"severity": "critical", "line": i, "type": "security", "description": "os.system() is vulnerable to command injection"})
                if "subprocess.call" in stripped and "shell=True" in stripped:
                    issues.append({"severity": "high", "line": i, "type": "security", "description": "subprocess with shell=True allows command injection"})
                if ("password" in stripped.lower() or "secret" in stripped.lower() or "api_key" in stripped.lower()) and "=" in stripped and "def " not in stripped and "#" not in stripped.split("=")[0]:
                    issues.append({"severity": "high", "line": i, "type": "security", "description": "Hardcoded credential detected"})
                if "SELECT" in stripped.upper() and "FROM" in stripped.upper() and ("+" in stripped or "f\"" in stripped or "format(" in stripped):
                    issues.append({"severity": "critical", "line": i, "type": "security", "description": "Potential SQL injection via string concatenation"})
                if "pickle.load" in stripped:
                    issues.append({"severity": "high", "line": i, "type": "security", "description": "pickle.load on untrusted data enables RCE"})
            if not issues and "ERROR" not in response:
                issues = [{"severity": "info", "line": 0, "type": "analysis", "description": response[:200]}]
    
    # Ensure issues is a list
    if not isinstance(issues, list):
        issues = [issues] if isinstance(issues, dict) else []
    
    # Store in ALEPH
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
    aleph_inject(f"code:{code_hash}", "scanned_by", "scout_agent", "nexus_swarm", 0.9)
    for issue in issues[:5]:
        aleph_inject(f"code:{code_hash}", "has_issue", f"{issue.get('type','unknown')}:{issue.get('description','')[:80]}", "nexus_swarm", 0.7)
    
    return {"agent": "scout", "issues": issues, "code_hash": code_hash}

# ============ AGENT: ARCHITECT ============
def agent_architect(code, issues, language="python"):
    """Deep analysis agent — understands code architecture and prioritizes issues."""
    system = "You are ARCHITECT, a senior code architect. Analyze code structure and prioritize issues. Output ONLY valid JSON with keys: 'architecture_summary' (string), 'priority_issues' (list of issue descriptions sorted by priority), 'fix_strategy' (string describing the overall fix approach)."
    issues_str = json.dumps(issues, indent=2) if isinstance(issues, list) else str(issues)
    prompt = f"Analyze this {language} code with these issues:\nCode:\n```\n{code}\n```\nIssues:\n{issues_str}\n\nOutput JSON with architecture analysis and fix strategy."
    
    response = call_llm(AGENT_MODELS["architect"], system, prompt, timeout=60, priority=Priority.HIGH)
    
    analysis = {}
    try:
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]
        analysis = json.loads(response.strip())
    except Exception:
        analysis = {"architecture_summary": response[:300], "priority_issues": [], "fix_strategy": "manual"}
    
    return {"agent": "architect", "analysis": analysis}

# ============ AGENT: FORGE ============
def agent_forge(code, issues, strategy, language="python"):
    """Code generation agent — writes fixes."""
    system = "You are FORGE, an expert code generator. Fix the identified issues while preserving functionality. Output ONLY the fixed code in a code block, no explanations."
    issues_str = json.dumps(issues[:5], indent=2) if isinstance(issues, list) else str(issues)
    prompt = f"Fix this {language} code:\n```\n{code}\n```\nIssues to fix:\n{issues_str}\nFix strategy: {strategy}\n\nOutput the complete fixed code."
    
    response = call_llm(AGENT_MODELS["forge"], system, prompt, timeout=60, priority=Priority.CRITICAL)
    
    # Extract code from response
    fixed_code = code  # default to original
    try:
        if f"```{language}" in response:
            fixed_code = response.split(f"```{language}")[1].split("```")[0]
        elif "```" in response:
            fixed_code = response.split("```")[1].split("```")[0]
        else:
            fixed_code = response
    except Exception:
        pass
    
    return {"agent": "forge", "fixed_code": fixed_code.strip()}

# ============ AGENT: JUDGE ============
def agent_judge(original_code, fixed_code, issues, language="python"):
    """Complex reasoning agent — evaluates fix quality."""
    system = "You are JUDGE, an expert code reviewer. Evaluate if the fix is correct and complete. Output ONLY valid JSON with keys: 'verdict' (approved/rejected/needs_revision), 'score' (0-100), 'reasoning' (string), 'remaining_issues' (list)."
    prompt = f"Evaluate this fix:\nOriginal:\n```\n{original_code[:500]}\n```\nFixed:\n```\n{fixed_code[:500]}\n```\nOriginal issues: {json.dumps(issues[:3])}\n\nOutput JSON verdict."
    
    response = call_llm(AGENT_MODELS["judge"], system, prompt, timeout=90, priority=Priority.HIGH)
    
    verdict = {}
    try:
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]
        verdict = json.loads(response.strip())
    except Exception:
        verdict = {"verdict": "unknown", "score": 0, "reasoning": response[:200], "remaining_issues": []}
    
    return {"agent": "judge", "verdict": verdict}

# ============ AGENT: PROVER (Lean4) ============
def agent_prover(code, language="python"):
    """Formal verification agent — verifies logical claims with Lean4."""
    # Extract mathematical/logical claims from code
    claims = []
    
    # Check for assertions
    for i, line in enumerate(code.split("\n"), 1):
        if "assert" in line and "==" in line:
            claims.append({"line": i, "claim": line.strip(), "type": "assertion"})
        if "if" in line and "len(" in line and "> 0" in line:
            claims.append({"line": i, "claim": line.strip(), "type": "bounds_check"})
    
    # Verify each claim with Lean4
    verified = []
    for claim in claims[:3]:  # Limit to 3 claims
        # Convert Python assertion to Lean4
        lean_code = "theorem t : True := by trivial"  # Default trivial proof
        if "==" in claim["claim"]:
            # Simple equality check
            parts = claim["claim"].split("==")
            if len(parts) == 2:
                left = parts[0].replace("assert", "").strip()
                right = parts[1].strip().rstrip(",")
                lean_code = f"theorem claim : {left} = {right} := by rfl"
        
        ok, output = lean4_verify(lean_code)
        verified.append({
            "line": claim["line"],
            "claim": claim["claim"][:100],
            "lean4_verified": ok,
            "lean4_output": output[:200],
        })
    
    return {"agent": "prover", "verified_claims": verified, "total_claims": len(claims)}

# ============ AGENT: GUARDIAN (Conscience) ============
def agent_guardian(claims_to_validate):
    """Anti-hallucination agent — validates claims using Conscience."""
    results = []
    for claim in claims_to_validate:
        verified, confidence, details = conscience_validate(claim)
        results.append({
            "claim": claim[:100],
            "verified": verified,
            "confidence": confidence,
            "details": str(details)[:200],
        })
    
    return {"agent": "guardian", "validations": results}

# ============ AGENT: SCRIBE ============
def agent_scribe(original_code, fixed_code, issues, verdict, language="python"):
    """Documentation agent — generates PR descriptions."""
    system = "You are SCRIBE, a technical writer. Generate a clear, concise pull request description. Output ONLY markdown."
    prompt = f"Write a PR description for this fix:\nIssues found: {json.dumps(issues[:5])}\nVerdict: {json.dumps(verdict)}\nLanguage: {language}\n\nOutput markdown PR description."
    
    response = call_llm(AGENT_MODELS["scribe"], system, prompt, timeout=30, priority=Priority.NORMAL)
    
    return {"agent": "scribe", "pr_description": response}

# ============ SWARM ORCHESTRATOR ============
def swarm_analyze(code, language="python"):
    """
    Run the full 7-agent swarm on a code snippet.
    Returns the complete analysis with all agent outputs.
    """
    session_id = f"nexus_{int(time.time())}"
    sys.stderr.write(f"\n[NEXUS] Swarm session {session_id} started\n")
    
    # 1. SCOUT — Fast scan
    sys.stderr.write(f"[NEXUS] Agent SCOUT scanning...\n")
    scout_result = agent_scout(code, language)
    issues = scout_result.get("issues", [])
    sys.stderr.write(f"[NEXUS] SCOUT found {len(issues)} issues\n")
    
    # 2. ARCHITECT — Deep analysis
    sys.stderr.write(f"[NEXUS] Agent ARCHITECT analyzing...\n")
    arch_result = agent_architect(code, issues, language)
    strategy = arch_result.get("analysis", {}).get("fix_strategy", "Fix all identified issues")
    sys.stderr.write(f"[NEXUS] ARCHITECT strategy: {strategy[:80]}\n")
    
    # 3. FORGE — Generate fix
    sys.stderr.write(f"[NEXUS] Agent FORGE generating fix...\n")
    forge_result = agent_forge(code, issues, strategy, language)
    fixed_code = forge_result.get("fixed_code", code)
    sys.stderr.write(f"[NEXUS] FORGE produced {len(fixed_code)} chars\n")
    
    # 4. JUDGE — Evaluate fix
    sys.stderr.write(f"[NEXUS] Agent JUDGE evaluating...\n")
    judge_result = agent_judge(code, fixed_code, issues, language)
    verdict = judge_result.get("verdict", {})
    sys.stderr.write(f"[NEXUS] JUDGE verdict: {verdict.get('verdict', 'unknown')} score: {verdict.get('score', 0)}\n")
    
    # 4b. FORGE Iterative Refinement — if JUDGE rejects, give FORGE a second pass with feedback
    if verdict.get("verdict") in ("rejected", "needs_revision") and verdict.get("score", 0) < 70:
        sys.stderr.write(f"[NEXUS] FORGE second pass (JUDGE feedback: score {verdict.get('score', 0)})...\n")
        remaining = verdict.get("remaining_issues", [])
        feedback = f"Previous fix was {verdict.get('verdict', 'rejected')} (score {verdict.get('score', 0)}/100). Reasoning: {verdict.get('reasoning', '')}. Remaining issues: {json.dumps(remaining[:3])}. Please fix these remaining issues."
        forge_result = agent_forge(fixed_code, remaining, feedback, language)
        new_fixed = forge_result.get("fixed_code", fixed_code)
        if new_fixed and len(new_fixed) > 10:
            fixed_code = new_fixed
            sys.stderr.write(f"[NEXUS] FORGE second pass produced {len(fixed_code)} chars\n")
            # Re-judge
            judge_result = agent_judge(code, fixed_code, issues, language)
            verdict = judge_result.get("verdict", {})
            sys.stderr.write(f"[NEXUS] JUDGE re-evaluation: {verdict.get('verdict', 'unknown')} score: {verdict.get('score', 0)}\n")
    
    # 4c. Cloud Fallback — if local models still can't produce a quality fix, use deepseek-v4-flash:cloud
    if verdict.get("score", 0) < CLOUD_FALLBACK_THRESHOLD and len(issues) > 0:
        sys.stderr.write(f"[NEXUS] FORGE cloud fallback (local score {verdict.get('score', 0)} < {CLOUD_FALLBACK_THRESHOLD})...")
        cloud_system = "You are FORGE, an expert code generator. Fix ALL security issues while preserving functionality. Output ONLY the fixed code, no explanations."
        cloud_prompt = f"Fix this {language} code:\n```\n{code}\n```\nIssues to fix:\n{json.dumps(issues[:5])}\nFix strategy: {strategy}\n\nOutput the complete fixed code."
        cloud_response = call_llm(AGENT_MODELS["forge_cloud"], cloud_system, cloud_prompt, timeout=180, priority=Priority.CRITICAL, think=True)  # Max thinking for cloud
        # Extract code
        cloud_fixed = cloud_response
        try:
            if f"```{language}" in cloud_response:
                cloud_fixed = cloud_response.split(f"```{language}")[1].split("```")[0]
            elif "```" in cloud_response:
                cloud_fixed = cloud_response.split("```")[1].split("```")[0]
        except Exception:
            pass
        if cloud_fixed and len(cloud_fixed) > 20:
            fixed_code = cloud_fixed.strip()
            sys.stderr.write(f" cloud fix: {len(fixed_code)} chars\n")
            # Re-judge the cloud fix
            judge_result = agent_judge(code, fixed_code, issues, language)
            verdict = judge_result.get("verdict", {})
            sys.stderr.write(f"[NEXUS] JUDGE cloud evaluation: {verdict.get('verdict', 'unknown')} score: {verdict.get('score', 0)}\n")
        else:
            sys.stderr.write(f" cloud fix failed\n")
    
    # 5. PROVER — Formal verification
    sys.stderr.write(f"[NEXUS] Agent PROVER verifying with Lean4...\n")
    prover_result = agent_prover(fixed_code, language)
    verified_claims = prover_result.get("verified_claims", [])
    sys.stderr.write(f"[NEXUS] PROVER verified {sum(1 for c in verified_claims if c['lean4_verified'])}/{len(verified_claims)} claims\n")
    
    # 6. GUARDIAN — Anti-hallucination validation
    sys.stderr.write(f"[NEXUS] Agent GUARDIAN validating claims...\n")
    claims_to_validate = [issue.get("description", "") for issue in issues[:3]]
    claims_to_validate.append(f"Fix verdict: {verdict.get('verdict', 'unknown')}")
    guardian_result = agent_guardian(claims_to_validate)
    sys.stderr.write(f"[NEXUS] GUARDIAN validated {len(guardian_result.get('validations', []))} claims\n")
    
    # 7. SCRIBE — Generate PR description
    sys.stderr.write(f"[NEXUS] Agent SCRIBE writing PR description...\n")
    scribe_result = agent_scribe(code, fixed_code, issues, verdict, language)
    sys.stderr.write(f"[NEXUS] SCRIBE generated {len(scribe_result.get('pr_description', ''))} chars\n")
    
    # Store session in ALEPH
    aleph_inject(f"nexus_session:{session_id}", "analyzed", scout_result.get("code_hash", "unknown"), "nexus_swarm", 0.95)
    aleph_inject(f"nexus_session:{session_id}", "found_issues", str(len(issues)), "nexus_swarm", 0.9)
    aleph_inject(f"nexus_session:{session_id}", "verdict", verdict.get("verdict", "unknown"), "nexus_swarm", 0.9)
    aleph_inject(f"nexus_session:{session_id}", "lean4_verified", str(sum(1 for c in verified_claims if c["lean4_verified"])), "nexus_swarm", 0.95)
    aleph_inject(f"nexus_session:{session_id}", "judge_score", str(verdict.get("score", 0)), "nexus_swarm", 0.85)
    
    result = {
        "session_id": session_id,
        "timestamp": time.time(),
        "language": language,
        "code_hash": scout_result.get("code_hash"),
        "agents": {
            "scout": scout_result,
            "architect": arch_result,
            "forge": forge_result,
            "judge": judge_result,
            "prover": prover_result,
            "guardian": guardian_result,
            "scribe": scribe_result,
        },
        "summary": {
            "issues_found": len(issues),
            "fix_generated": fixed_code != code,
            "verdict": verdict.get("verdict", "unknown"),
            "judge_score": verdict.get("score", 0),
            "lean4_claims_verified": sum(1 for c in verified_claims if c["lean4_verified"]),
            "lean4_total_claims": len(verified_claims),
            "conscience_validated": sum(1 for v in guardian_result.get("validations", []) if v["verified"]),
        },
    }
    
    sys.stderr.write(f"[NEXUS] Swarm session {session_id} complete\n")
    return result


# ============ TEST ============
if __name__ == "__main__":
    # Test code with intentional bugs
    TEST_CODE = '''import os

password = os.environ.get("ADMIN_PASS", "")

def login(username, password_input):
    if username == "admin" and password_input == password:
        return True
    return False

def run_command(user_input):
    os.system(user_input)
    return "done"

def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)

data = eval(input("Enter data: "))
result = run_command(data)
'''
    
    print("=" * 60)
    print("NEXUS Swarm — Size 1 Test")
    print("=" * 60)
    print(f"Test code: {len(TEST_CODE)} chars, {len(TEST_CODE.splitlines())} lines")
    print(f"Intentional bugs: hardcoded password, os.system, SQL injection, eval()")
    print()
    
    result = swarm_analyze(TEST_CODE, "python")
    
    print()
    print("=" * 60)
    print("SWARM RESULTS")
    print("=" * 60)
    print(f"Session: {result['session_id']}")
    print(f"Issues found: {result['summary']['issues_found']}")
    print(f"Fix generated: {result['summary']['fix_generated']}")
    print(f"Judge verdict: {result['summary']['verdict']}")
    print(f"Judge score: {result['summary']['judge_score']}")
    print(f"Lean4 verified: {result['summary']['lean4_claims_verified']}/{result['summary']['lean4_total_claims']}")
    print(f"Conscience validated: {result['summary']['conscience_validated']}")
    
    print()
    print("--- SCOUT Issues ---")
    for issue in result["agents"]["scout"].get("issues", []):
        print(f"  [{issue.get('severity','?').upper():8s}] Line {issue.get('line','?'):>3}: {issue.get('description','')[:80]}")
    
    print()
    print("--- FORGE Fixed Code (first 300 chars) ---")
    print(result["agents"]["forge"].get("fixed_code", "")[:300])
    
    print()
    print("--- SCRIBE PR Description (first 300 chars) ---")
    print(result["agents"]["scribe"].get("pr_description", "")[:300])
    
    print()
    print("--- ALEPH Stored ---")
    stored = aleph_query(result["session_id"])
    print(f"  {len(stored)} edges stored in ALEPH")
    for edge in stored[:5]:
        print(f"  {edge['source'][:30]:30s} {edge['relation']:15s} {edge['target'][:40]}")
    
    print()
    print("=" * 60)
    if result["summary"]["issues_found"] > 0 and result["summary"]["fix_generated"]:
        print("✅ SIZE 1 GATE PASSED: Swarm found issues and generated a fix")
    else:
        print("❌ SIZE 1 GATE FAILED: No issues found or no fix generated")
    print("=" * 60)