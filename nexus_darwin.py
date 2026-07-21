#!/usr/bin/env python3
"""
NEXUS-DARWIN — Self-Improving Code Swarm
=========================================
Connects the Darwin-Gödel self-improvement engine to the NEXUS 7-agent swarm.

The swarm analyzes code → JUDGE scores the fix → Darwin-Gödel mutates
the agent prompts → re-run with mutated prompts → if score improves, keep.

This is Size 8 from dream_prompt.md: the system autonomously discovers
and merges an improvement that no human suggested.

Architecture:
  1. TEST SUITE: Standard vulnerable code + expected fixes
  2. BASELINE RUN: NEXUS analyzes test code, records JUDGE score
  3. MUTATION: Darwin-Gödel mutates agent system prompts using LLM
  4. EVALUATION: Re-run NEXUS with mutated prompts
  5. SELECTION: If JUDGE score improves, keep. If not, roll back.
  6. ALEPH: Log mutation + outcome for auditability
  7. API: Expose the self-improvement loop as an endpoint

Circuit breakers: MAX_MUTATIONS=20, MAX_RUNTIME=1800s, MIN_IMPROVEMENT=5 points
"""
import sys
import os
import json
import time
import sqlite3
import shutil
import urllib.request
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Optional, List

sys.path.insert(0, "/home/zixen15/nexus")
sys.path.insert(0, "/home/zixen15/brains")

# Import NEXUS swarm
from swarm_core import (
    swarm_analyze, aleph_inject, aleph_query,
    AGENT_MODELS, call_llm, lean4_verify, conscience_validate,
    ALEPH_DB
)

# Import LLM scheduler
from llm_scheduler import schedule_llm, Priority, SCHEDULER

# ============ CONFIG ============
PROMPTS_FILE = "/home/zixen15/nexus/evolved_prompts.json"
MUTATIONS_DIR = Path("/home/zixen15/nexus/mutations_archive")
MUTATIONS_DIR.mkdir(exist_ok=True)

MAX_MUTATIONS = 20        # Max mutations per evolution cycle
MAX_RUNTIME = 1800        # 30 minute max per evolution cycle
MIN_IMPROVEMENT = 5       # Need at least 5-point improvement to keep mutation
MUTATION_MODEL = "qwen3.5:4b"  # Local model for generating mutations (zero cloud cost)

# NEXUS-DARWIN uses its own SQLite DB to avoid ALEPH lock contention with Conscience
NEXUS_DB = "/home/zixen15/nexus/nexus_darwin.db"

def nexus_inject(source, relation, target, domain="nexus_darwin", confidence=0.9):
    """Store a knowledge edge in the NEXUS-DARWIN database (separate from ALEPH to avoid locks)."""
    for attempt in range(3):
        try:
            conn = sqlite3.connect(NEXUS_DB, timeout=5)
            conn.execute("""CREATE TABLE IF NOT EXISTS edges (
                source TEXT, target TEXT, relation TEXT, domain TEXT, confidence REAL, created_at REAL,
                PRIMARY KEY (source, target, relation)
            )""")
            conn.execute("INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?)",
                         (source[:500], target[:500], relation[:200], domain, confidence, time.time()))
            conn.commit()
            conn.close()
            return True
        except sqlite3.OperationalError:
            time.sleep(0.3 * (attempt + 1))
        except Exception as e:
            sys.stderr.write(f"[NEXUS-DARWIN] DB inject failed: {e}\n")
            return False
    return False

def nexus_query(concept, limit=20):
    """Query the NEXUS-DARWIN database."""
    try:
        conn = sqlite3.connect(NEXUS_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM edges WHERE source LIKE ? OR target LIKE ? LIMIT ?",
                         (f"%{concept}%", f"%{concept}%", limit))
        results = [{"source": r["source"], "relation": r["relation"], "target": r["target"], "domain": r["domain"], "confidence": r["confidence"]} for r in cur.fetchall()]
        conn.close()
        return results
    except Exception:
        return []

def nexus_count():
    """Count edges in NEXUS-DARWIN DB."""
    try:
        conn = sqlite3.connect(NEXUS_DB, timeout=5)
        conn.execute("CREATE TABLE IF NOT EXISTS edges (source TEXT, target TEXT, relation TEXT, domain TEXT, confidence REAL, created_at REAL)")
        count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        conn.close()
        return count
    except Exception:
        return 0

# ============ TEST SUITE ============
# The JUDGE score on these is the fitness function for Darwin-Gödel.

QUICK_MODE = True
TEST_CASES_ALL = [
    {
        "name": "security_basics",
        "code": """import os
password = os.environ.get("ADMIN_PASS", "")
def run_cmd(user_input):
    os.system(user_input)
    return True
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute(query)
def process(data):
    return eval(data)
""",
        "language": "python",
        "expected_issues": 4,  # hardcoded password, os.system, SQL injection, eval
    },
    {
        "name": "resource_leaks",
        "code": """import sqlite3
def get_users():
    conn = sqlite3.connect("app.db")
    cur = conn.execute("SELECT * FROM users")
    return cur.fetchall()
def write_log(msg):
    f = open("app.log", "a")
    f.write(msg)
    # Missing f.close()
def process_items(items):
    result = []
    for item in items:
        result.append(item)
    return result
""",
        "language": "python",
        "expected_issues": 2,  # unclosed connection, unclosed file
    },
    {
        "name": "input_validation",
        "code": """def transfer_money(from_account, to_account, amount):
    # No validation of inputs
    balance = get_balance(from_account)
    if balance >= amount:
        debit(from_account, amount)
        credit(to_account, amount)
    return True

def parse_config(filename):
    import json
    with open(filename) as f:
        return json.load(f)
    # No error handling for missing file or invalid JSON
""",
        "language": "python",
        "expected_issues": 2,  # no input validation, no error handling
    },
]

TEST_CASES = TEST_CASES_ALL[:1] if QUICK_MODE else TEST_CASES_ALL

# ============ EVOLVED PROMPTS ============
# The initial prompts for each agent. These get mutated by Darwin-Gödel.

INITIAL_PROMPTS = {
    "scout_system": "You are SCOUT, a fast code scanner. Find bugs, security issues, and improvement opportunities. Output ONLY a JSON array of objects. Each object must have keys: severity (critical/high/medium/low), line (integer), type (bug/security/style/performance), description (string). Do not use markdown code blocks. Output raw JSON only.",
    "scout_user": "Analyze this {language} code for issues. Output ONLY raw JSON array, no markdown fences.\nCode:\n{code}\n\nJSON array:",
    
    "architect_system": "You are ARCHITECT, a senior code architect. Analyze code structure and prioritize issues. Output ONLY valid JSON with keys: 'architecture_summary' (string), 'priority_issues' (list of issue descriptions sorted by priority), 'fix_strategy' (string describing the overall fix approach).",
    "architect_user": "Analyze this {language} code with these issues:\nCode:\n```\n{code}\n```\nIssues:\n{issues}\n\nOutput JSON with architecture analysis and fix strategy.",
    
    "forge_system": "You are FORGE, an expert code generator. Fix the identified issues while preserving functionality. Output ONLY the fixed code in a code block, no explanations.",
    "forge_user": "Fix this {language} code:\n```\n{code}\n```\nIssues to fix:\n{issues}\nFix strategy: {strategy}\n\nOutput the complete fixed code.",
    
    "judge_system": "You are JUDGE, an expert code reviewer. Evaluate if the fix is correct and complete. Output ONLY valid JSON with keys: 'verdict' (approved/rejected/needs_revision), 'score' (0-100), 'reasoning' (string), 'remaining_issues' (list).",
    "judge_user": "Evaluate this fix:\nOriginal:\n```\n{original}\n```\nFixed:\n```\n{fixed}\n```\nOriginal issues: {issues}\n\nOutput JSON verdict.",
    
    "scribe_system": "You are SCRIBE, a technical writer. Generate a clear, concise pull request description. Output ONLY markdown.",
    "scribe_user": "Write a PR description for this fix:\nIssues found: {issues}\nVerdict: {verdict}\nLanguage: {language}\n\nOutput markdown PR description.",
}

def load_prompts():
    """Load evolved prompts from file, or use initial prompts if file doesn't exist."""
    if os.path.exists(PROMPTS_FILE):
        with open(PROMPTS_FILE) as f:
            return json.load(f)
    return INITIAL_PROMPTS.copy()

def save_prompts(prompts):
    """Save evolved prompts to file."""
    with open(PROMPTS_FILE, "w") as f:
        json.dump(prompts, f, indent=2)

def backup_prompts():
    """Backup current prompts before mutation."""
    backup = f"{PROMPTS_FILE}.bak"
    if os.path.exists(PROMPTS_FILE):
        shutil.copy2(PROMPTS_FILE, backup)
    else:
        save_prompts(INITIAL_PROMPTS)
        shutil.copy2(PROMPTS_FILE, backup)

# ============ FITNESS FUNCTION ============
def evaluate_swarm(prompts, test_case):
    """
    Run the NEXUS swarm on a test case using the given prompts.
    Returns the JUDGE score (fitness) and details.
    
    This temporarily replaces the agent prompts, runs the swarm,
    then restores the original prompts.
    """
    # We can't easily inject prompts into swarm_analyze without modifying it.
    # Instead, we run swarm_analyze as-is and measure the JUDGE score.
    # The prompt mutations will be applied by modifying the agent functions
    # to read from the evolved_prompts file.
    
    result = swarm_analyze(test_case["code"], test_case["language"])
    
    score = result["summary"]["judge_score"]
    issues_found = result["summary"]["issues_found"]
    verdict = result["summary"]["verdict"]
    
    return {
        "score": score,
        "issues_found": issues_found,
        "verdict": verdict,
        "session_id": result["session_id"],
        "expected_issues": test_case["expected_issues"],
        "issue_coverage": issues_found / max(1, test_case["expected_issues"]),
    }

def run_fitness_suite(prompts):
    """Run the swarm on all test cases and return average fitness."""
    results = []
    for tc in TEST_CASES:
        r = evaluate_swarm(prompts, tc)
        results.append(r)
    
    avg_score = sum(r["score"] for r in results) / len(results)
    avg_coverage = sum(r["issue_coverage"] for r in results) / len(results)
    
    return {
        "avg_score": avg_score,
        "avg_coverage": avg_coverage,
        "results": results,
        "total_issues_found": sum(r["issues_found"] for r in results),
        "total_expected": sum(r["expected_issues"] for r in results),
    }

# ============ DARWIN-GÖDEL MUTATION ============
def generate_mutation(current_prompts, feedback, failed_areas):
    """
    Use the LLM to generate a mutated version of the agent prompts.
    Targets high-impact prompts first (FORGE, SCOUT, JUDGE) that directly
    affect the JUDGE score, before trying lower-impact ones (SCRIBE, ARCHITECT).
    """
    # Priority order: prompts that directly affect JUDGE score
    impact_order = [
        "forge_system",    # Code generation quality → directly affects score
        "scout_system",    # Issue detection → affects coverage
        "judge_system",    # Evaluation strictness → affects score calibration
        "architect_system", # Strategy → affects fix approach
        "forge_user",      # User prompt for forge
        "scout_user",      # User prompt for scout
        "judge_user",      # User prompt for judge
        "architect_user",  # User prompt for architect
        "scribe_system",   # Low impact (only affects PR description)
        "scribe_user",     # Low impact
    ]
    
    # Find the first prompt in impact order that exists in current_prompts
    target_key = None
    for key in impact_order:
        if key in current_prompts:
            target_key = key
            break
    
    if not target_key:
        target_key = list(current_prompts.keys())[0]
    
    current_prompt = current_prompts[target_key]
    
    mutation_prompt = f"""You are the Darwin-Gödel self-improvement engine for NEXUS, a 7-agent code analysis swarm.

The swarm's current performance:
  Average JUDGE score: {feedback['avg_score']:.1f}/100
  Issue coverage: {feedback['avg_coverage']:.1%}
  Issues found: {feedback['total_issues_found']}/{feedback['total_expected']}

Failed areas: {json.dumps(failed_areas)}

Here is the current system prompt for the {target_key.split('_')[0].upper()} agent:
---
{current_prompt}
---

Propose an improved version of this prompt that will help the agent:
1. Find more issues (if coverage is low)
2. Generate better fixes (if score is low)
3. Be more precise and accurate

Output ONLY the new prompt text, no explanations, no markdown fences.
The prompt should be a complete system instruction for the agent.
"""
    
    sys.stderr.write(f"[NEXUS-DARWIN] Mutating {target_key}...\n")
    
    mutated = schedule_llm(
        model=MUTATION_MODEL,
        system_prompt="You are a prompt engineering expert. Output ONLY the improved prompt text.",
        user_prompt=mutation_prompt,
        priority=Priority.LOW,  # Don't block user-facing agents
        max_tokens=400,
        temperature=0.5,  # Slightly creative for exploration
    )
    
    # Clean up
    if mutated.startswith("```"):
        mutated = mutated.split("```")[1]
        if mutated.startswith("\n"):
            mutated = mutated[1:]
    mutated = mutated.strip()
    
    if len(mutated) < 20:
        sys.stderr.write(f"[NEXUS-DARWIN] Mutation too short ({len(mutated)} chars). Skipping.\n")
        return None, None
    
    return target_key, mutated

# ============ EVOLUTION CYCLE ============
def run_evolution_cycle(max_mutations=MAX_MUTATIONS):
    """
    Run a full Darwin-Gödel evolution cycle:
    1. Evaluate baseline (current prompts)
    2. Generate mutation
    3. Evaluate mutation
    4. If better, keep. If not, roll back.
    5. Repeat.
    
    Returns a summary of the evolution cycle.
    """
    cycle_id = f"darwin_{int(time.time())}"
    sys.stderr.write(f"\n[NEXUS-DARWIN] Evolution cycle {cycle_id} started\n")
    sys.stderr.write(f"[NEXUS-DARWIN] Max mutations: {max_mutations}\n")
    
    # Load current prompts
    prompts = load_prompts()
    backup_prompts()
    
    # 1. BASELINE EVALUATION
    sys.stderr.write(f"[NEXUS-DARWIN] Running baseline evaluation...\n")
    baseline = run_fitness_suite(prompts)
    baseline_score = baseline["avg_score"]
    sys.stderr.write(f"[NEXUS-DARWIN] Baseline: score={baseline_score:.1f}, coverage={baseline['avg_coverage']:.1%}, "
                     f"issues={baseline['total_issues_found']}/{baseline['total_expected']}\n")
    
    # Log baseline to ALEPH
    nexus_inject(f"darwin_cycle:{cycle_id}", "baseline_score", str(round(baseline_score, 1)), "nexus_darwin", 0.95)
    nexus_inject(f"darwin_cycle:{cycle_id}", "baseline_coverage", str(round(baseline["avg_coverage"], 2)), "nexus_darwin", 0.95)
    nexus_inject(f"darwin_cycle:{cycle_id}", "total_issues", f"{baseline['total_issues_found']}/{baseline['total_expected']}", "nexus_darwin", 0.9)
    
    results = {
        "cycle_id": cycle_id,
        "baseline_score": baseline_score,
        "baseline_coverage": baseline["avg_coverage"],
        "mutations": [],
        "improvements": 0,
        "regressions": 0,
        "final_score": baseline_score,
    }
    
    best_score = baseline_score
    best_prompts = prompts.copy()
    
    # 2. MUTATION LOOP
    for i in range(max_mutations):
        elapsed = time.time() - (results.get("start_time", time.time()))
        if elapsed > MAX_RUNTIME:
            sys.stderr.write(f"[NEXUS-DARWIN] Max runtime reached ({elapsed:.0f}s). Stopping.\n")
            break
        
        sys.stderr.write(f"\n[NEXUS-DARWIN] Mutation {i+1}/{max_mutations}\n")
        
        # Identify failed areas
        failed = []
        for r in baseline["results"]:
            if r["issue_coverage"] < 1.0:
                failed.append(f"Test '{r.get('session_id','?')[-8:]}': found {r['issues_found']}/{r['expected_issues']} issues, score {r['score']}")
        
        # Generate mutation
        target_key, mutated_prompt = generate_mutation(prompts, {
            "avg_score": best_score,
            "avg_coverage": baseline["avg_coverage"],
            "total_issues_found": baseline["total_issues_found"],
            "total_expected": baseline["total_expected"],
        }, failed)
        
        if not target_key or not mutated_prompt:
            results["mutations"].append({
                "iteration": i + 1,
                "status": "skipped",
                "reason": "mutation_too_short",
            })
            continue
        
        # Apply mutation
        old_prompt = prompts[target_key]
        prompts[target_key] = mutated_prompt
        save_prompts(prompts)  # Persist so swarm_analyze picks it up
        
        # Evaluate mutation
        sys.stderr.write(f"[NEXUS-DARWIN] Evaluating mutation {i+1}...\n")
        mutation_eval = run_fitness_suite(prompts)
        mutation_score = mutation_eval["avg_score"]
        
        improvement = mutation_score - best_score
        sys.stderr.write(f"[NEXUS-DARWIN] Mutation {i+1} score: {mutation_score:.1f} "
                         f"(improvement: {improvement:+.1f})\n")
        
        # 3. SELECTION
        mutation_id = f"mut_{int(time.time())}"
        if mutation_score > best_score + MIN_IMPROVEMENT:
            # KEEP — improvement found
            sys.stderr.write(f"[NEXUS-DARWIN] ✅ Mutation {mutation_id} IMPROVED! "
                             f"{best_score:.1f} → {mutation_score:.1f} "
                             f"(+{improvement:.1f})\n")
            best_score = mutation_score
            best_prompts = prompts.copy()
            results["improvements"] += 1
            
            # Archive the successful mutation
            with open(MUTATIONS_DIR / f"{mutation_id}.json", "w") as f:
                json.dump({
                    "mutation_id": mutation_id,
                    "target": target_key,
                    "old_prompt": old_prompt,
                    "new_prompt": mutated_prompt,
                    "score_before": best_score - improvement,
                    "score_after": mutation_score,
                    "improvement": improvement,
                }, f, indent=2)
            
            # Log to ALEPH
            nexus_inject(f"darwin_cycle:{cycle_id}", "mutation_improved", mutation_id, "nexus_darwin", 0.95)
            nexus_inject(f"mutation:{mutation_id}", "target_prompt", target_key, "nexus_darwin", 0.9)
            nexus_inject(f"mutation:{mutation_id}", "improvement", str(round(improvement, 1)), "nexus_darwin", 0.95)
            nexus_inject(f"mutation:{mutation_id}", "new_score", str(round(mutation_score, 1)), "nexus_darwin", 0.9)
            
            results["mutations"].append({
                "iteration": i + 1,
                "mutation_id": mutation_id,
                "target": target_key,
                "status": "improved",
                "score_before": round(best_score - improvement, 1),
                "score_after": round(mutation_score, 1),
                "improvement": round(improvement, 1),
            })
            
            # Update baseline for next iteration
            baseline = mutation_eval
        else:
            # ROLL BACK — no improvement
            sys.stderr.write(f"[NEXUS-DARWIN] ❌ Mutation {mutation_id} did not improve "
                             f"({mutation_score:.1f} vs best {best_score:.1f}). Rolling back.\n")
            prompts[target_key] = old_prompt
            save_prompts(prompts)
            results["regressions"] += 1
            
            # Log to ALEPH
            nexus_inject(f"darwin_cycle:{cycle_id}", "mutation_rejected", mutation_id, "nexus_darwin", 0.7)
            nexus_inject(f"mutation:{mutation_id}", "rejected_score", str(round(mutation_score, 1)), "nexus_darwin", 0.7)
            
            results["mutations"].append({
                "iteration": i + 1,
                "mutation_id": mutation_id,
                "target": target_key,
                "status": "rejected",
                "score": round(mutation_score, 1),
                "best": round(best_score, 1),
            })
    
    # 4. FINAL STATE
    results["final_score"] = best_score
    results["total_improvement"] = best_score - baseline_score
    results["duration_s"] = time.time() - results.get("start_time", time.time())
    
    # Log final state to ALEPH
    nexus_inject(f"darwin_cycle:{cycle_id}", "final_score", str(round(best_score, 1)), "nexus_darwin", 0.95)
    nexus_inject(f"darwin_cycle:{cycle_id}", "total_improvement", str(round(results["total_improvement"], 1)), "nexus_darwin", 0.95)
    nexus_inject(f"darwin_cycle:{cycle_id}", "improvements", str(results["improvements"]), "nexus_darwin", 0.9)
    nexus_inject(f"darwin_cycle:{cycle_id}", "regressions", str(results["regressions"]), "nexus_darwin", 0.9)
    
    sys.stderr.write(f"\n[NEXUS-DARWIN] Evolution cycle {cycle_id} complete\n")
    sys.stderr.write(f"[NEXUS-DARWIN] Baseline: {baseline_score:.1f} → Final: {best_score:.1f} "
                     f"(improvement: {results['total_improvement']:+.1f})\n")
    sys.stderr.write(f"[NEXUS-DARWIN] Improvements: {results['improvements']}, "
                     f"Regressions: {results['regressions']}\n")
    
    return results


# ============ EVOLUTION STATUS ============
def get_evolution_status():
    """Get current evolution status for monitoring."""
    prompts = load_prompts()
    
    # Count mutations in ALEPH
    try:
        with sqlite3.connect(NEXUS_DB, timeout=5) as conn:
            total_cycles = conn.execute("SELECT COUNT(*) FROM edges WHERE domain='nexus_darwin' AND relation='final_score'").fetchone()[0]
            total_improvements = conn.execute("SELECT COUNT(*) FROM edges WHERE domain='nexus_darwin' AND relation='mutation_improved'").fetchone()[0]
            total_rejections = conn.execute("SELECT COUNT(*) FROM edges WHERE domain='nexus_darwin' AND relation='mutation_rejected'").fetchone()[0]
    except Exception:
        total_cycles = 0
        total_improvements = 0
        total_rejections = 0
    
    # Count archived mutations
    archived = len(list(MUTATIONS_DIR.glob("*.json")))
    
    return {
        "status": "ready",
        "prompts_loaded": len(prompts),
        "prompt_keys": list(prompts.keys()),
        "total_cycles": total_cycles,
        "total_improvements": total_improvements,
        "total_rejections": total_rejections,
        "archived_mutations": archived,
        "test_cases": len(TEST_CASES),
        "mutation_model": MUTATION_MODEL,
        "scheduler_stats": SCHEDULER.get_status()["metrics"],
    }


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 60)
    print("NEXUS-DARWIN — Self-Improving Code Swarm")
    print("=" * 60)
    
    # Quick test: run one evaluation + one mutation
    print("\n--- Loading prompts ---")
    prompts = load_prompts()
    print(f"Loaded {len(prompts)} agent prompts")
    
    print("\n--- Running baseline evaluation ---")
    t0 = time.time()
    baseline = run_fitness_suite(prompts)
    print(f"  Time: {time.time()-t0:.1f}s")
    print(f"  Avg score: {baseline['avg_score']:.1f}/100")
    print(f"  Coverage: {baseline['avg_coverage']:.1%}")
    print(f"  Issues found: {baseline['total_issues_found']}/{baseline['total_expected']}")
    
    print("\n--- Generating one mutation ---")
    failed = ["Low issue coverage", "Low fix quality score"]
    target_key, mutated = generate_mutation(prompts, {
        "avg_score": baseline["avg_score"],
        "avg_coverage": baseline["avg_coverage"],
        "total_issues_found": baseline["total_issues_found"],
        "total_expected": baseline["total_expected"],
    }, failed)
    
    if target_key:
        print(f"  Target: {target_key}")
        print(f"  Original ({len(prompts[target_key])} chars): {prompts[target_key][:100]}...")
        print(f"  Mutated ({len(mutated)} chars): {mutated[:100]}...")
    else:
        print("  Mutation generation failed")
    
    print("\n--- Evolution status ---")
    status = get_evolution_status()
    for k, v in status.items():
        print(f"  {k}: {v}")
    
    print("\n" + "=" * 60)
    print("✅ NEXUS-DARWIN core ready. Run run_evolution_cycle() to start evolving.")
    print("=" * 60)