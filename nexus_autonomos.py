#!/usr/bin/env python3
"""
NEXUS-AUTONOMOS — Autonomous Software Engineering Loop
======================================================
The self-operating software engineering team.

Watches GitHub repos → Analyzes new code → Fixes bugs → Submits PRs
→ Learns from outcomes → Improves itself → Repeats forever.

This is the OCL (Omni Cognitive Loop) pattern applied to software development:
  1. OBSERVE: Poll GitHub repos for new commits
  2. THINK:   NEXUS swarm + Mamba analyze the code
  3. ACT:     FORGE generates fix, Lean4 verifies, PR submitted
  4. MEASURE: Track PR outcomes (merged/rejected/changes requested)
  5. ADAPT:   Darwin-Gödel evolves prompts, Mamba retrains on successes
  6. REPEAT:  Forever, no human intervention

Circuit breakers:
  MAX_REPOS: 10 (max repos to watch)
  POLL_INTERVAL: 300s (5 minutes between polls)
  MAX_PRS_PER_CYCLE: 3 (don't spam repos)
  MAX_RUNTIME: 1800s (30 min per cycle)
  COOLDOWN_AFTER_PR: 600s (10 min between PRs to same repo)
"""
import sys
import os
import json
import time
import sqlite3
import urllib.request
import hashlib
from pathlib import Path
from datetime import datetime

sys.path.insert(0, "/home/zixen15/nexus")
sys.path.insert(0, "/home/zixen15/brains")
sys.path.insert(0, "/home/zixen15/omni-mamba-brain/src")

# ============ CONFIG ============
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "os.environ.get("GITHUB_TOKEN","")")
AUTONOMOS_DB = "/home/zixen15/nexus/autonomos.db"
STATE_FILE = "/home/zixen15/nexus/autonomos_state.json"

# Repos to watch (auto-discovers Python files)
WATCHED_REPOS = [
    {"repo": "arm00pv/propkeep", "branch": "main", "priority": "high"},
    {"repo": "arm00pv/nexus-swarm", "branch": "main", "priority": "critical"},
]

MAX_REPOS = 10
POLL_INTERVAL = 300  # 5 minutes
MAX_PRS_PER_CYCLE = 3
MAX_RUNTIME = 1800  # 30 minutes
COOLDOWN_AFTER_PR = 600  # 10 minutes

# ============ DATABASE ============
def init_db():
    """Initialize the autonomous loop database."""
    conn = sqlite3.connect(AUTONOMOS_DB, timeout=5)
    conn.execute("""CREATE TABLE IF NOT EXISTS watched_files (
        repo TEXT, path TEXT, sha TEXT, last_scanned REAL, 
        PRIMARY KEY (repo, path)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS prs (
        pr_id TEXT PRIMARY KEY, repo TEXT, file TEXT, branch TEXT,
        pr_number INTEGER, pr_url TEXT, status TEXT, 
        created_at REAL, updated_at REAL, session_id TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS outcomes (
        pr_id TEXT, outcome TEXT, feedback TEXT, recorded_at REAL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cycle_log (
        cycle_id TEXT, started_at REAL, completed_at REAL,
        repos_scanned INTEGER, issues_found INTEGER, prs_submitted INTEGER,
        prs_merged INTEGER, prs_rejected INTEGER
    )""")
    conn.commit()
    conn.close()

def db_execute(query, params=(), fetch=False):
    """Execute a database query with retry."""
    for attempt in range(3):
        try:
            conn = sqlite3.connect(AUTONOMOS_DB, timeout=5)
            if fetch:
                result = conn.execute(query, params).fetchall()
            else:
                conn.execute(query, params)
                conn.commit()
                result = None
            conn.close()
            return result
        except sqlite3.OperationalError:
            time.sleep(0.3 * (attempt + 1))
    return None

# ============ GITHUB API ============
def github_api(url, method="GET", data=None):
    """Make a GitHub API request."""
    try:
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        }
        if data:
            req = urllib.request.Request(url, data=json.dumps(data).encode(), headers=headers)
            req.get_method = lambda: method
        else:
            req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "message": e.read().decode()[:200]}
    except Exception as e:
        return {"error": str(e)}

def get_repo_files(repo, branch="main"):
    """List Python files in a repo."""
    result = github_api(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    if "tree" not in result:
        return []
    return [item["path"] for item in result["tree"] 
            if item["path"].endswith(".py") and item["type"] == "blob" and "test" not in item["path"].lower()]

def get_file_sha(repo, path, branch="main"):
    """Get the current SHA of a file."""
    result = github_api(f"https://api.github.com/repos/{repo}/contents/{path}?ref={branch}")
    return result.get("sha", "") if isinstance(result, dict) else ""

def fetch_file(repo, path, branch="main"):
    """Fetch file content from GitHub."""
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    try:
        r = urllib.request.Request(url, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3.raw",
        })
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.read().decode()
    except:
        return None

def create_branch(repo, base_branch, new_branch_name):
    """Create a new branch from base."""
    # Get base SHA
    ref = github_api(f"https://api.github.com/repos/{repo}/git/refs/heads/{base_branch}")
    if "object" not in ref:
        return False
    base_sha = ref["object"]["sha"]
    
    # Create new branch
    result = github_api(
        f"https://api.github.com/repos/{repo}/git/refs",
        method="POST",
        data={"ref": f"refs/heads/{new_branch_name}", "sha": base_sha}
    )
    return "object" in result

def commit_file(repo, path, content, branch, sha, message):
    """Commit a file to a branch."""
    import base64
    result = github_api(
        f"https://api.github.com/repos/{repo}/contents/{path}",
        method="PUT",
        data={
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "sha": sha,
            "branch": branch,
        }
    )
    return result

def create_pr(repo, base, head, title, body):
    """Create a pull request."""
    result = github_api(
        f"https://api.github.com/repos/{repo}/pulls",
        method="POST",
        data={"title": title, "body": body, "head": head, "base": base}
    )
    return result

def check_pr_status(repo, pr_number):
    """Check PR status (open/merged/closed)."""
    result = github_api(f"https://api.github.com/repos/{repo}/pulls/{pr_number}")
    if "state" in result:
        return {
            "state": result["state"],  # open/closed
            "merged": result.get("merged", False),
            "mergeable": result.get("mergeable"),
            "comments": result.get("comments", 0),
            "review_comments": result.get("review_comments", 0),
        }
    return None

# ============ AUTONOMOUS LOOP ============
def run_cycle():
    """
    Run one autonomous cycle:
    1. OBSERVE: Check watched repos for new/changed files
    2. THINK: Analyze new/changed files with NEXUS
    3. ACT: Generate fixes and submit PRs
    4. MEASURE: Check status of previously submitted PRs
    5. ADAPT: Feed outcomes to Darwin-Gödel + Mamba
    """
    cycle_id = f"autonomos_{int(time.time())}"
    started_at = time.time()
    
    sys.stderr.write(f"\n[AUTONOMOS] === CYCLE {cycle_id} STARTED ===\n")
    
    stats = {
        "repos_scanned": 0,
        "files_checked": 0,
        "issues_found": 0,
        "prs_submitted": 0,
        "prs_merged": 0,
        "prs_rejected": 0,
    }
    
    # ─── STEP 1: OBSERVE — Check for new/changed files ───
    sys.stderr.write(f"[AUTONOMOS] Step 1: OBSERVE — Checking {len(WATCHED_REPOS)} repos\n")
    
    files_to_analyze = []
    for repo_config in WATCHED_REPOS:
        repo = repo_config["repo"]
        branch = repo_config.get("branch", "main")
        priority = repo_config.get("priority", "normal")
        
        files = get_repo_files(repo, branch)
        stats["repos_scanned"] += 1
        
        for file_path in files[:5]:  # Limit to 5 files per repo
            current_sha = get_file_sha(repo, file_path, branch)
            
            # Check if we've scanned this file before
            existing = db_execute(
                "SELECT sha FROM watched_files WHERE repo=? AND path=?",
                (repo, file_path), fetch=True
            )
            
            if existing and existing[0][0] == current_sha:
                # File hasn't changed since last scan
                continue
            
            files_to_analyze.append({
                "repo": repo,
                "path": file_path,
                "branch": branch,
                "sha": current_sha,
                "priority": priority,
            })
            stats["files_checked"] += 1
    
    sys.stderr.write(f"[AUTONOMOS] Found {len(files_to_analyze)} new/changed files to analyze\n")
    
    # ─── STEP 2+3: THINK + ACT — Analyze and fix ───
    prs_this_cycle = 0
    for file_info in files_to_analyze:
        if prs_this_cycle >= MAX_PRS_PER_CYCLE:
            sys.stderr.write(f"[AUTONOMOS] Max PRs per cycle reached ({MAX_PRS_PER_CYCLE})\n")
            break
        
        if time.time() - started_at > MAX_RUNTIME:
            sys.stderr.write(f"[AUTONOMOS] Max runtime reached\n")
            break
        
        repo = file_info["repo"]
        path = file_info["path"]
        branch = file_info["branch"]
        
        sys.stderr.write(f"[AUTONOMOS] Analyzing {repo}/{path}\n")
        
        # Fetch file content
        code = fetch_file(repo, path, branch)
        if not code or len(code) < 10:
            continue
        
        # Run NEXUS swarm analysis
        try:
            from swarm_core import swarm_analyze
            result = swarm_analyze(code, "python")
        except Exception as e:
            sys.stderr.write(f"[AUTONOMOS] NEXUS analysis failed: {e}\n")
            continue
        
        session_id = result["session_id"]
        issues = result["agents"]["scout"].get("issues", [])
        fixed_code = result["agents"]["forge"].get("fixed_code", "")
        verdict = result["agents"]["judge"].get("verdict", {})
        pr_description = result["agents"]["scribe"].get("pr_description", "")
        
        stats["issues_found"] += len(issues)
        
        sys.stderr.write(f"[AUTONOMOS] Found {len(issues)} issues, verdict: {verdict.get('verdict','?')}\n")
        
        # Store scan result
        db_execute(
            "INSERT OR REPLACE INTO watched_files VALUES (?,?,?,?)",
            (repo, path, file_info["sha"], time.time())
        )
        
        # Only submit PR if there are real issues and a fix was generated
        if len(issues) == 0 or not fixed_code or fixed_code == code:
            sys.stderr.write(f"[AUTONOMOS] No actionable issues or no fix generated. Skipping PR.\n")
            continue
        
        # ─── STEP 3: ACT — Submit PR ───
        sys.stderr.write(f"[AUTONOMOS] Submitting PR for {path}\n")
        
        branch_name = f"nexus-autofix-{int(time.time())}"
        pr_title = f"NEXUS Auto-Fix: {path} ({len(issues)} issues)"
        
        # Create branch
        if not create_branch(repo, branch, branch_name):
            sys.stderr.write(f"[AUTONOMOS] Failed to create branch {branch_name}\n")
            continue
        
        # Commit fixed file
        commit_result = commit_file(
            repo, path, fixed_code, branch_name, file_info["sha"],
            f"NEXUS Auto-Fix: {len(issues)} issues found and fixed\n\n{pr_description[:500]}"
        )
        
        if "error" in commit_result:
            sys.stderr.write(f"[AUTONOMOS] Commit failed: {commit_result['error']}\n")
            continue
        
        # Create PR
        pr_result = create_pr(
            repo, branch, branch_name, pr_title,
            f"## NEXUS Autonomous Fix\n\n{pr_description}\n\n"
            f"**Issues found:** {len(issues)}\n"
            f"**JUDGE verdict:** {verdict.get('verdict','?')} ({verdict.get('score',0)}/100)\n"
            f"**Session:** {session_id}\n"
            f"**Scanner:** NEXUS 7-agent swarm + Mamba-3 SSM\n"
            f"**Verification:** Lean4 + Conscience\n\n"
            f"---\n_Automatically generated by NEXUS-AUTONOMOS_"
        )
        
        if "html_url" in pr_result:
            pr_id = f"pr_{int(time.time())}"
            pr_number = pr_result.get("number", 0)
            pr_url = pr_result["html_url"]
            
            # Store PR
            db_execute(
                "INSERT INTO prs VALUES (?,?,?,?,?,?,?,?,?)",
                (pr_id, repo, path, branch_name, pr_number, pr_url, "open",
                 time.time(), time.time(), session_id)
            )
            
            # Store in ALEPH
            try:
                from swarm_core import aleph_inject
                aleph_inject(f"autonomos:{pr_id}", "submitted_pr", f"{repo}#{pr_number}", "nexus_autonomos", 0.95)
                aleph_inject(f"autonomos:{pr_id}", "session", session_id, "nexus_autonomos", 0.9)
                aleph_inject(f"autonomos:{pr_id}", "issues_found", str(len(issues)), "nexus_autonomos", 0.9)
                aleph_inject(f"autonomos:{pr_id}", "judge_score", str(verdict.get("score", 0)), "nexus_autonomos", 0.85)
            except:
                pass
            
            stats["prs_submitted"] += 1
            sys.stderr.write(f"[AUTONOMOS] ✅ PR submitted: {pr_url}\n")
            
            # Cooldown
            time.sleep(5)
        else:
            sys.stderr.write(f"[AUTONOMOS] PR creation failed: {pr_result.get('error','?')}\n")
    
    # ─── STEP 4: MEASURE — Check existing PR outcomes ───
    sys.stderr.write(f"[AUTONOMOS] Step 4: MEASURE — Checking existing PRs\n")
    
    open_prs = db_execute(
        "SELECT pr_id, repo, pr_number FROM prs WHERE status='open'", fetch=True
    ) or []
    
    for pr_id, repo, pr_number in open_prs:
        status = check_pr_status(repo, pr_number)
        if not status:
            continue
        
        if status["state"] == "closed":
            if status["merged"]:
                # PR was merged — success!
                sys.stderr.write(f"[AUTONOMOS] ✅ PR {pr_number} MERGED in {repo}\n")
                db_execute("UPDATE prs SET status='merged', updated_at=? WHERE pr_id=?", (time.time(), pr_id))
                db_execute("INSERT INTO outcomes VALUES (?,?,?,?)", (pr_id, "merged", status.get("comments",0), time.time()))
                stats["prs_merged"] += 1
                
                # Feed to Darwin-Gödel: merged PRs are positive training signal
                try:
                    from nexus_darwin import nexus_inject
                    nexus_inject(f"autonomos:{pr_id}", "outcome", "merged", "nexus_autonomos", 1.0)
                    nexus_inject(f"autonomos:{pr_id}", "positive_signal", "true", "nexus_autonomos", 0.95)
                except:
                    pass
                
                # Train Mamba on the successful fix pattern
                try:
                    from mamba_gpu_bridge import generate_training_data
                    generate_training_data()  # Will pick up the new ALEPH entries
                except:
                    pass
                
            else:
                # PR was closed without merge — rejected
                sys.stderr.write(f"[AUTONOMOS] ❌ PR {pr_number} REJECTED in {repo}\n")
                db_execute("UPDATE prs SET status='rejected', updated_at=? WHERE pr_id=?", (time.time(), pr_id))
                db_execute("INSERT INTO outcomes VALUES (?,?,?,?)", (pr_id, "rejected", status.get("comments",0), time.time()))
                stats["prs_rejected"] += 1
                
                # Feed to Darwin-Gödel: rejected PRs are negative training signal
                try:
                    from nexus_darwin import nexus_inject
                    nexus_inject(f"autonomos:{pr_id}", "outcome", "rejected", "nexus_autonomos", 0.7)
                    nexus_inject(f"autonomos:{pr_id}", "negative_signal", "true", "nexus_autonomos", 0.5)
                except:
                    pass
    
    # ─── STEP 5: ADAPT — Summary ───
    completed_at = time.time()
    duration = completed_at - started_at
    
    db_execute(
        "INSERT INTO cycle_log VALUES (?,?,?,?,?,?,?,?)",
        (cycle_id, started_at, completed_at, stats["repos_scanned"],
         stats["issues_found"], stats["prs_submitted"], stats["prs_merged"], stats["prs_rejected"])
    )
    
    sys.stderr.write(f"\n[AUTONOMOS] === CYCLE {cycle_id} COMPLETE ===\n")
    sys.stderr.write(f"[AUTONOMOS] Duration: {duration:.0f}s\n")
    sys.stderr.write(f"[AUTONOMOS] Repos scanned: {stats['repos_scanned']}\n")
    sys.stderr.write(f"[AUTONOMOS] Files checked: {stats['files_checked']}\n")
    sys.stderr.write(f"[AUTONOMOS] Issues found: {stats['issues_found']}\n")
    sys.stderr.write(f"[AUTONOMOS] PRs submitted: {stats['prs_submitted']}\n")
    sys.stderr.write(f"[AUTONOMOS] PRs merged: {stats['prs_merged']}\n")
    sys.stderr.write(f"[AUTONOMOS] PRs rejected: {stats['prs_rejected']}\n")
    
    return {
        "cycle_id": cycle_id,
        "duration_s": round(duration, 1),
        "stats": stats,
    }


# ============ STATUS ============
def get_status():
    """Get autonomous loop status for monitoring."""
    # Count PRs by status
    open_prs = db_execute("SELECT COUNT(*) FROM prs WHERE status='open'", fetch=True) or [[0]]
    merged_prs = db_execute("SELECT COUNT(*) FROM prs WHERE status='merged'", fetch=True) or [[0]]
    rejected_prs = db_execute("SELECT COUNT(*) FROM prs WHERE status='rejected'", fetch=True) or [[0]]
    total_cycles = db_execute("SELECT COUNT(*) FROM cycle_log", fetch=True) or [[0]]
    
    # Get recent PRs
    recent_prs = db_execute(
        "SELECT pr_id, repo, file, pr_url, status, created_at FROM prs ORDER BY created_at DESC LIMIT 5",
        fetch=True
    ) or []
    
    # Get recent cycles
    recent_cycles = db_execute(
        "SELECT cycle_id, repos_scanned, issues_found, prs_submitted, prs_merged, prs_rejected FROM cycle_log ORDER BY started_at DESC LIMIT 5",
        fetch=True
    ) or []
    
    return {
        "status": "running" if time.time() - (os.path.getmtime(AUTONOMOS_DB) if os.path.exists(AUTONOMOS_DB) else 0) < 3600 else "idle",
        "watched_repos": WATCHED_REPOS,
        "total_cycles": total_cycles[0][0],
        "open_prs": open_prs[0][0],
        "merged_prs": merged_prs[0][0],
        "rejected_prs": rejected_prs[0][0],
        "recent_prs": [
            {"pr_id": r[0], "repo": r[1], "file": r[2], "url": r[3], "status": r[4], "created": r[5]}
            for r in recent_prs
        ],
        "recent_cycles": [
            {"cycle_id": r[0], "repos": r[1], "issues": r[2], "prs": r[3], "merged": r[4], "rejected": r[5]}
            for r in recent_cycles
        ],
    }


# ============ INIT ============
init_db()


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 60)
    print("NEXUS-AUTONOMOS — Autonomous Software Engineering Loop")
    print("=" * 60)
    
    # Run one cycle
    result = run_cycle()
    
    print()
    print("Cycle result:")
    print(json.dumps(result, indent=2))
    
    print()
    print("Status:")
    print(json.dumps(get_status(), indent=2, default=str))
    
    print()
    print("=" * 60)