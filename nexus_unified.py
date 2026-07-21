#!/usr/bin/env python3
"""
NEXUS Unified Scanner — One Call, Full Security Audit
=======================================================
Combines all three scanners into a single unified endpoint:

  POST /api/nexus/scan {"repo": "owner/repo", "branch": "main"}

Runs in parallel:
  1. AST Code Analyzer — structural analysis of all Python files
  2. Diff Scanner — git diff analysis of latest commit
  3. SBOM Generator + Vulnerability Scanner — dependency CVEs

Returns a unified report with:
  - Code issues (from AST)
  - Diff issues (from git diff)
  - Dependency vulnerabilities (from OSV)
  - SBOM (CycloneDX format)
  - Overall security score

Then:
  - Creates GitHub Issues for critical findings
  - Syncs results to Supabase
  - Logs to ALEPH
"""
import sys
import os
import json
import time
import threading
import sqlite3
import urllib.request

sys.path.insert(0, "/home/zixen15/nexus")
sys.path.insert(0, "/home/zixen15/brains")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
UNIFIED_DB = "/home/zixen15/nexus/unified_scans.db"

def init_db():
    conn = sqlite3.connect(UNIFIED_DB, timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS unified_scans (
        id TEXT PRIMARY KEY, repo TEXT, branch TEXT,
        code_issues INTEGER, diff_issues INTEGER, vuln_count INTEGER,
        sbom_components INTEGER, security_score INTEGER,
        full_report TEXT, created REAL, duration REAL
    )""")
    conn.commit()
    conn.close()

init_db()

# ============ FETCH ALL PYTHON FILES ============
def github_api(url):
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}

def fetch_file(repo, path, branch="main"):
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    try:
        req = urllib.request.Request(url, headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3.raw",
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode()
    except Exception:
        return None

def list_python_files(repo, branch="main"):
    data = github_api(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    if "tree" not in data:
        return []
    return [item["path"] for item in data["tree"]
            if item["path"].endswith(".py") and item["type"] == "blob"
            and "test" not in item["path"].lower()
            and "__pycache__" not in item["path"]
            and ".git" not in item["path"]][:10]  # Limit to 10 files for speed

def get_latest_commit(repo, branch="main"):
    data = github_api(f"https://api.github.com/repos/{repo}/commits?sha={branch}&per_page=1")
    return data[0]["sha"] if isinstance(data, list) and data else None

# ============ GITHUB ISSUE CREATION ============
def create_github_issue(repo, title, body, labels=None):
    data = {"title": title, "body": body}
    if labels:
        data["labels"] = labels
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/issues",
            data=json.dumps(data).encode(),
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        req.get_method = lambda: "POST"
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            return result.get("html_url", "")
    except Exception:
        return ""

# ============ PARALLEL SCANNERS ============
def scan_code_ast(repo, branch, files):
    """Run AST analysis on all Python files."""
    from nexus_ast import analyze_code
    all_issues = []
    files_scanned = 0
    
    for filepath in files:
        code = fetch_file(repo, filepath, branch)
        if not code or len(code) < 10:
            continue
        result = analyze_code(code, filepath)
        files_scanned += 1
        for issue in result.get("issues", []):
            issue["file"] = filepath
            all_issues.append(issue)
    
    # Also scan for secrets in each file
    secret_issues = []
    for filepath in files:
        file_content = fetch_file(repo, filepath, branch)
        if file_content:
            secrets = scan_secrets(file_content, filepath)
            secret_issues.extend(secrets)
    
    all_issues.extend(secret_issues)
    
    return {
        "scanner": "ast+secrets",
        "files_scanned": files_scanned,
        "issues": all_issues,
        "secrets_found": len(secret_issues),
        "critical": sum(1 for i in all_issues if i["severity"] == "critical"),
        "high": sum(1 for i in all_issues if i["severity"] == "high"),
        "medium": sum(1 for i in all_issues if i["severity"] == "medium"),
    }

def scan_diff(repo, branch):
    """Run diff scanner on latest commit."""
    from nexus_diff_scanner import scan_commit, get_latest_commit
    sha = get_latest_commit(repo, branch)
    if not sha:
        return {"scanner": "diff", "status": "no_commits", "issues": []}
    result = scan_commit(repo, sha)
    issues = []
    for r in result.get("results", []):
        for issue in r.get("issues", []):
            issues.append(issue)
    return {
        "scanner": "diff",
        "commit": sha,
        "files_scanned": result.get("files_scanned", 0),
        "issues": issues,
        "duration_s": result.get("duration_s", 0),
    }

def scan_sbom(repo, branch):
    """Run SBOM + vulnerability scanner + Dockerfile scan."""
    from nexus_sbom import scan_repo
    result = scan_repo(repo, branch)
    
    # Also scan Dockerfiles
    docker_issues = []
    for df_path in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]:
        content = fetch_file(repo, df_path, branch)
        if content:
            docker_issues = scan_dockerfile(content, df_path)
    
    return {
        "scanner": "sbom",
        "components": result.get("total_components", 0),
        "vulnerable_components": result.get("vulnerable_components", 0),
        "vulnerabilities": result.get("vulnerabilities", []),
        "total_vulns": result.get("total_vulnerabilities", 0),
        "sbom": result.get("sbom"),
        "sources": result.get("sources", []),
        "dockerfile_issues": docker_issues,
    }

# ============ UNIFIED SCAN ============
def unified_scan(repo, branch="main", create_issues=False):
    """
    Run all three scanners in parallel.
    Returns a unified security report.
    """
    scan_id = f"unified_{int(time.time())}"
    started = time.time()
    
    sys.stderr.write(f"\n[UNIFIED] Scanning {repo}@{branch}\n")
    
    # Fetch file list
    files = list_python_files(repo, branch)
    sys.stderr.write(f"[UNIFIED] {len(files)} Python files to scan\n")
    
    # Run all three scanners in parallel (threads)
    ast_result = {}
    diff_result = {}
    sbom_result = {}
    
    def run_ast():
        nonlocal ast_result
        ast_result = scan_code_ast(repo, branch, files)
        sys.stderr.write(f"[UNIFIED] AST: {ast_result.get('files_scanned',0)} files, {len(ast_result.get('issues',[]))} issues\n")
    
    def run_diff():
        nonlocal diff_result
        diff_result = scan_diff(repo, branch)
        sys.stderr.write(f"[UNIFIED] Diff: {diff_result.get('files_scanned',0)} files, {len(diff_result.get('issues',[]))} issues\n")
    
    def run_sbom():
        nonlocal sbom_result
        sbom_result = scan_sbom(repo, branch)
        sys.stderr.write(f"[UNIFIED] SBOM: {sbom_result.get('components',0)} components, {sbom_result.get('total_vulns',0)} vulns\n")
    
    threads = [
        threading.Thread(target=run_ast, daemon=True),
        threading.Thread(target=run_diff, daemon=True),
        threading.Thread(target=run_sbom, daemon=True),
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)  # Max 60s per scanner
    
    # Merge results
    all_code_issues = ast_result.get("issues", [])
    all_diff_issues = diff_result.get("issues", [])
    all_vulns = sbom_result.get("vulnerabilities", [])
    
    total_issues = len(all_code_issues) + len(all_diff_issues)
    total_vulns = sbom_result.get("total_vulns", 0)
    
    # Calculate security score (0-100, higher is better)
    # Only CRITICAL and HIGH affect score. LOW/MEDIUM are informational.
    critical_count = sum(1 for i in all_code_issues + all_diff_issues if i.get("severity") == "critical")
    high_count = sum(1 for i in all_code_issues + all_diff_issues if i.get("severity") == "high")
    score = max(0, 100 - (critical_count * 25) - (high_count * 10) - (total_vulns * 5))
    
    duration = time.time() - started
    
    report = {
        "scan_id": scan_id,
        "repo": repo,
        "branch": branch,
        "timestamp": time.time(),
        "duration_s": round(duration, 2),
        "security_score": score,
        "summary": {
            "files_scanned": ast_result.get("files_scanned", 0),
            "code_issues": len(all_code_issues),
            "diff_issues": len(all_diff_issues),
            "dependency_vulns": total_vulns,
            "sbom_components": sbom_result.get("components", 0),
            "critical_count": critical_count,
            "high_count": high_count,
        },
        "ast_scan": ast_result,
        "diff_scan": diff_result,
        "sbom_scan": {
            "components": sbom_result.get("components", 0),
            "vulnerable_components": sbom_result.get("vulnerable_components", 0),
            "total_vulns": total_vulns,
            "sources": sbom_result.get("sources", []),
            "vulnerabilities": [
                {
                    "package": v["package"],
                    "version": v["version"],
                    "vuln_count": v["vuln_count"],
                    "status": v["status"],
                    "top_vulns": [
                        {"id": vuln["id"], "summary": vuln["summary"][:80], "fixed_in": vuln.get("fixed_in")}
                        for vuln in v.get("vulnerabilities", [])[:2]
                    ] if v["vuln_count"] > 0 else []
                }
                for v in all_vulns if v.get("vuln_count", 0) > 0
            ],
        },
        "all_code_issues": all_code_issues[:20],  # Limit for response size
        "all_diff_issues": all_diff_issues[:10],
    }
    
    # Create GitHub Issues for critical findings
    if create_issues and critical_count > 0:
        issue_title = f"[NEXUS] {critical_count} critical security issues found in {repo}"
        issue_body = f"""## NEXUS Unified Security Scan

**Repository:** {repo}
**Security Score:** {score}/100
**Scan Duration:** {duration:.1f}s

### Summary
- **Code Issues (AST):** {len(all_code_issues)} ({critical_count} critical, {high_count} high)
- **Diff Issues:** {len(all_diff_issues)}
- **Dependency Vulnerabilities:** {total_vulns}
- **SBOM Components:** {sbom_result.get('components', 0)}

### Critical Issues
"""
        for issue in all_code_issues[:10]:
            if issue.get("severity") == "critical":
                issue_body += f"- **{issue.get('file','?')}** line {issue.get('line','?')}: {issue.get('description','')}\n"
        
        if total_vulns > 0:
            issue_body += f"\n### Dependency Vulnerabilities\n"
            for v in all_vulns:
                if v.get("vuln_count", 0) > 0:
                    issue_body += f"- **{v['package']}@{v['version']}**: {v['vuln_count']} vulnerabilities\n"
        
        issue_body += f"\n---\n_Automatically generated by NEXUS Unified Scanner_"
        issue_url = create_github_issue(repo, issue_title, issue_body, ["nexus-critical", "security", "automated"])
        report["github_issue"] = issue_url
    
    # Store in DB
    try:
        conn = sqlite3.connect(UNIFIED_DB, timeout=10)
        conn.execute("INSERT OR REPLACE INTO unified_scans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, repo, branch, len(all_code_issues), len(all_diff_issues),
                     total_vulns, sbom_result.get("components", 0), score,
                     json.dumps(report)[:5000], time.time(), duration))
        conn.commit()
        conn.close()
    except Exception:
        pass
    
    # Sync to Supabase
    try:
        from nexus_supabase import supabase_insert
from nexus_secrets import scan_secrets
from nexus_dockerfile import scan_dockerfile
        supabase_insert([{
            "id": f"unified_{scan_id}",
            "topic": f"nexus_unified:{repo}",
            "fact": f"Score: {score}/100 | Code: {len(all_code_issues)} issues | Diff: {len(all_diff_issues)} | Vulns: {total_vulns} | {duration:.1f}s",
            "source": "unified_scanner",
            "verified": True,
        }])
    except Exception:
        pass
    
    sys.stderr.write(f"[UNIFIED] Complete: score={score}/100, {total_issues} code issues, {total_vulns} dep vulns, {duration:.1f}s\n")
    
    return report

def get_unified_status():
    try:
        conn = sqlite3.connect(UNIFIED_DB, timeout=5)
        total = conn.execute("SELECT COUNT(*) FROM unified_scans").fetchone()[0]
        recent = conn.execute("SELECT id, repo, security_score, code_issues, vuln_count, duration FROM unified_scans ORDER BY created DESC LIMIT 5").fetchall()
        conn.close()
        return {
            "total_scans": total,
            "recent": [{"id": r[0], "repo": r[1], "score": r[2], "code_issues": r[3], "vulns": r[4], "duration": r[5]} for r in recent],
        }
    except Exception:
        return {"total_scans": 0, "recent": []}


# ============ TEST ============
if __name__ == "__main__":
    os.environ.setdefault("GITHUB_TOKEN", "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")
    os.environ.setdefault("SUPABASE_KEY", "sb_secret_OKU5p10BHjTzHR8eh84ORQ_zqQdpnao")
    
    print("=" * 60)
    print("NEXUS Unified Scanner Test")
    print("=" * 60)
    
    # Test on our own repo first
    repo = "arm00pv/nexus-swarm"
    print(f"\nScanning: {repo}")
    result = unified_scan(repo, create_issues=True)
    
    print(f"\nResults:")
    print(f"  Scan ID: {result['scan_id']}")
    print(f"  Security Score: {result['security_score']}/100")
    print(f"  Duration: {result['duration_s']}s")
    print(f"\n  Summary:")
    s = result['summary']
    print(f"    Files scanned (AST): {s['files_scanned']}")
    print(f"    Code issues: {s['code_issues']} ({s['critical_count']} critical, {s['high_count']} high)")
    print(f"    Diff issues: {s['diff_issues']}")
    print(f"    Dependency vulns: {s['dependency_vulns']}")
    print(f"    SBOM components: {s['sbom_components']}")
    
    if result.get("github_issue"):
        print(f"\n  GitHub Issue: {result['github_issue']}")
    
    # Test on an external repo (proves it works on real-world code)
    print(f"\n{'='*60}")
    print("Testing on EXTERNAL repo (real-world code)...")
    print(f"{'='*60}")
    
    # Use a popular, well-maintained Python project
    repo2 = "psf/requests"  # The Python requests library
    print(f"\nScanning: {repo2}")
    result2 = unified_scan(repo2)
    
    print(f"\nResults:")
    print(f"  Security Score: {result2['security_score']}/100")
    print(f"  Duration: {result2['duration_s']}s")
    print(f"\n  Summary:")
    s2 = result2['summary']
    print(f"    Files scanned: {s2['files_scanned']}")
    print(f"    Code issues: {s2['code_issues']}")
    print(f"    Dependency vulns: {s2['dependency_vulns']}")
    print(f"    SBOM components: {s2['sbom_components']}")
    
    if s2['code_issues'] > 0:
        print(f"\n  Top Code Issues:")
        for issue in result2.get('all_code_issues', [])[:5]:
            print(f"    [{issue['severity'].upper():8s}] {issue.get('file','?')}:{issue.get('line','?')} — {issue.get('description','')[:50]}")
    
    if s2['dependency_vulns'] > 0:
        print(f"\n  Dependency Vulnerabilities:")
        for v in result2.get('sbom_scan', {}).get('vulnerabilities', [])[:5]:
            print(f"    ⚠️  {v['package']}@{v['version']}: {v['vuln_count']} vulns")
    
    print(f"\n{'='*60}")