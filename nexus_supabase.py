#!/usr/bin/env python3
"""
NEXUS Supabase Sync — Local SQLite → Supabase Redundancy
=========================================================
Mirrors all local NEXUS data to Supabase for redundancy and cross-device access.

Uses the existing `neural_memory` table with NEXUS-specific topic prefixes:
  nexus_session:*  — Analysis sessions (from ALEPH)
  nexus_darwin:*    — Darwin-Gödel mutations
  nexus_autonomos:* — AUTONOMOS PR tracking
  nexus_aleph:*     — ALEPH knowledge graph edges
  nexus_propkeep:*  — PROPKEEP queries

Strategy:
  1. Read local SQLite databases (ALEPH, NEXUS-Darwin, AUTONOMOS)
  2. Sync new/changed entries to Supabase
  3. Keep local SQLite as primary (low latency)
  4. Supabase is the redundant backup + enables cross-device sync
"""
import sys
import os
import json
import time
import sqlite3
import urllib.request

sys.path.insert(0, "/home/zixen15/nexus")
sys.path.insert(0, "/home/zixen15/brains")

# ============ SUPABASE CONFIG ============
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://lnossgbybsjjtnghoykf.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "") or "sb_secret_OKU5p10BHjTzHR8eh84ORQ_zqQdpnao"
SUPABASE_TABLE = "neural_memory"

# ============ LOCAL DB PATHS ============
ALEPH_DB = "/home/zixen15/brains/aleph/manifold.db"
NEXUS_DARWIN_DB = "/home/zixen15/nexus/nexus_darwin.db"
AUTONOMOS_DB = "/home/zixen15/nexus/autonomos.db"

# Track what we've already synced
SYNC_STATE_FILE = "/home/zixen15/nexus/supabase_sync_state.json"

# ============ SUPABASE API ============
def supabase_insert(rows):
    """Insert rows into Supabase. Returns count of successful inserts."""
    if not rows:
        return 0
    
    # Batch insert (Supabase REST API supports arrays)
    try:
        data = json.dumps(rows).encode()
        r = urllib.request.Request(
            f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}",
            data=data,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal,resolution=ignore-duplicates",
            }
        )
        r.get_method = lambda: "POST"
        with urllib.request.urlopen(r, timeout=30) as resp:
            if resp.status in (200, 201):
                return len(rows)
            return 0
    except Exception as e:
        sys.stderr.write(f"[SUPABASE] Insert failed: {e}\n")
        return 0

def supabase_query(topic_prefix, limit=100):
    """Query Supabase for rows with a topic prefix."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}?topic=like.{topic_prefix}*&limit={limit}&order=created_at.desc"
        r = urllib.request.Request(url, headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
        })
        with urllib.request.urlopen(r, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception:
        return []

def supabase_count(topic_prefix=None):
    """Count rows in Supabase."""
    try:
        url = f"{SUPABASE_URL}/rest/v1/{SUPABASE_TABLE}?select=id&limit=1"
        if topic_prefix:
            url += f"&topic=like.{topic_prefix}*"
        r = urllib.request.Request(url, headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Prefer": "count=exact",
        })
        with urllib.request.urlopen(r, timeout=10) as resp:
            count = resp.headers.get("Content-Range", "*/0").split("/")[-1]
            return int(count) if count.isdigit() else 0
    except Exception:
        return 0

# ============ SYNC STATE ============
def load_sync_state():
    """Load the last sync state."""
    try:
        with open(SYNC_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {
            "last_aleph_sync": 0,
            "last_darwin_sync": 0,
            "last_autonomos_sync": 0,
            "total_synced": 0,
        }

def save_sync_state(state):
    """Save the sync state."""
    with open(SYNC_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

# ============ SYNC FUNCTIONS ============
def sync_aleph(state):
    """Sync new ALEPH edges to Supabase."""
    last_sync = state.get("last_aleph_sync", 0)
    rows_to_sync = []
    
    try:
        conn = sqlite3.connect(ALEPH_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        # Get edges created since last sync
        cur = conn.execute(
            "SELECT source, target, relation, domain, confidence, created_at FROM edges WHERE created_at > ? ORDER BY created_at ASC LIMIT 500",
            (last_sync,)
        )
        for row in cur.fetchall():
            rows_to_sync.append({
                "id": f"aleph_{hash((row['source'], row['target'], row['relation'])) & 0xFFFFFFFF:08x}",
                "topic": f"nexus_aleph:{row['domain'] or 'unknown'}",
                "fact": f"{row['source']} | {row['relation']} | {row['target']}",
                "source": "aleph",
                "verified": True,
                "context_window_id": f"confidence={row['confidence']}",
            })
        
        # Update last sync timestamp
        if rows_to_sync:
            latest = conn.execute("SELECT MAX(created_at) FROM edges WHERE created_at > ?", (last_sync,)).fetchone()[0]
            if latest:
                state["last_aleph_sync"] = latest
        
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[SUPABASE] ALEPH sync failed: {e}\n")
    
    return rows_to_sync

def sync_darwin(state):
    """Sync Darwin-Gödel mutations to Supabase."""
    last_sync = state.get("last_darwin_sync", 0)
    rows_to_sync = []
    
    try:
        conn = sqlite3.connect(NEXUS_DARWIN_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE IF NOT EXISTS edges (source TEXT, target TEXT, relation TEXT, domain TEXT, confidence REAL, created_at REAL, PRIMARY KEY (source, target, relation))")
        cur = conn.execute(
            "SELECT source, target, relation, domain, confidence, created_at FROM edges WHERE created_at > ? LIMIT 200",
            (last_sync,)
        )
        for row in cur.fetchall():
            rows_to_sync.append({
                "id": f"darwin_{hash((row['source'], row['target'], row['relation'])) & 0xFFFFFFFF:08x}",
                "topic": f"nexus_darwin:{row['relation'] or 'unknown'}",
                "fact": f"{row['source']} | {row['relation']} | {row['target']}",
                "source": "darwin_godel",
                "verified": True,
                "context_window_id": f"confidence={row['confidence']}",
            })
        
        if rows_to_sync:
            latest = conn.execute("SELECT MAX(created_at) FROM edges WHERE created_at > ?", (last_sync,)).fetchone()[0]
            if latest:
                state["last_darwin_sync"] = latest
        
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[SUPABASE] Darwin sync failed: {e}\n")
    
    return rows_to_sync

def sync_autonomos(state):
    """Sync AUTONOMOS PR tracking to Supabase."""
    last_sync = state.get("last_autonomos_sync", 0)
    rows_to_sync = []
    
    try:
        conn = sqlite3.connect(AUTONOMOS_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        
        # Sync PRs
        cur = conn.execute(
            "SELECT pr_id, repo, file, pr_url, status, created_at FROM prs WHERE created_at > ? LIMIT 100",
            (last_sync,)
        )
        for row in cur.fetchall():
            rows_to_sync.append({
                "id": f"autonomos_pr_{row['pr_id']}",
                "topic": f"nexus_autonomos:pr_{row['status']}",
                "fact": f"{row['repo']} | {row['file']} | {row['pr_url']}",
                "source": "autonomos",
                "verified": True,
                "context_window_id": row['pr_id'],
            })
        
        # Sync cycle logs
        cur = conn.execute(
            "SELECT cycle_id, repos_scanned, issues_found, prs_submitted, prs_merged, prs_rejected, started_at FROM cycle_log WHERE started_at > ? LIMIT 50",
            (last_sync,)
        )
        for row in cur.fetchall():
            rows_to_sync.append({
                "id": f"autonomos_cycle_{row['cycle_id']}",
                "topic": "nexus_autonomos:cycle",
                "fact": f"Cycle {row['cycle_id']}: scanned={row['repos_scanned']}, issues={row['issues_found']}, prs={row['prs_submitted']}, merged={row['prs_merged']}, rejected={row['prs_rejected']}",
                "source": "autonomos",
                "verified": True,
                "context_window_id": row['cycle_id'],
            })
        
        if rows_to_sync:
            state["last_autonomos_sync"] = time.time()
        
        conn.close()
    except Exception as e:
        sys.stderr.write(f"[SUPABASE] AUTONOMOS sync failed: {e}\n")
    
    return rows_to_sync

# ============ MAIN SYNC ============
def run_sync():
    """Run a full sync cycle: local SQLite → Supabase."""
    state = load_sync_state()
    total_synced = 0
    
    sys.stderr.write(f"\n[SUPABASE] === SYNC START ===\n")
    
    # 1. Sync ALEPH
    sys.stderr.write(f"[SUPABASE] Syncing ALEPH...\n")
    aleph_rows = sync_aleph(state)
    if aleph_rows:
        count = supabase_insert(aleph_rows)
        total_synced += count
        sys.stderr.write(f"[SUPABASE] ALEPH: {count}/{len(aleph_rows)} rows synced\n")
    else:
        sys.stderr.write(f"[SUPABASE] ALEPH: no new rows\n")
    
    # 2. Sync Darwin
    sys.stderr.write(f"[SUPABASE] Syncing Darwin-Gödel...\n")
    darwin_rows = sync_darwin(state)
    if darwin_rows:
        count = supabase_insert(darwin_rows)
        total_synced += count
        sys.stderr.write(f"[SUPABASE] Darwin: {count}/{len(darwin_rows)} rows synced\n")
    else:
        sys.stderr.write(f"[SUPABASE] Darwin: no new rows\n")
    
    # 3. Sync AUTONOMOS
    sys.stderr.write(f"[SUPABASE] Syncing AUTONOMOS...\n")
    autonomos_rows = sync_autonomos(state)
    if autonomos_rows:
        count = supabase_insert(autonomos_rows)
        total_synced += count
        sys.stderr.write(f"[SUPABASE] AUTONOMOS: {count}/{len(autonomos_rows)} rows synced\n")
    else:
        sys.stderr.write(f"[SUPABASE] AUTONOMOS: no new rows\n")
    
    # Update state
    state["total_synced"] = state.get("total_synced", 0) + total_synced
    save_sync_state(state)
    
    sys.stderr.write(f"[SUPABASE] === SYNC COMPLETE: {total_synced} rows synced (total: {state['total_synced']}) ===\n")
    
    return {
        "synced": total_synced,
        "total_synced": state["total_synced"],
        "aleph": len(aleph_rows),
        "darwin": len(darwin_rows),
        "autonomos": len(autonomos_rows),
    }

def get_sync_status():
    """Get sync status for monitoring."""
    state = load_sync_state()
    sb_count = supabase_count()
    sb_nexus = supabase_count("nexus")
    
    # Count local
    local_counts = {}
    for name, db_path in [("aleph", ALEPH_DB), ("darwin", NEXUS_DARWIN_DB), ("autonomos", AUTONOMOS_DB)]:
        try:
            conn = sqlite3.connect(db_path, timeout=5)
            count = conn.execute("SELECT COUNT(*) FROM edges" if name != "autonomos" else "SELECT COUNT(*) FROM prs").fetchone()[0]
            local_counts[name] = count
            conn.close()
        except Exception:
            local_counts[name] = 0
    
    return {
        "supabase_url": SUPABASE_URL,
        "supabase_total_rows": sb_count,
        "supabase_nexus_rows": sb_nexus,
        "local_counts": local_counts,
        "sync_state": state,
    }


# ============ TEST ============
if __name__ == "__main__":
    print("=" * 60)
    print("NEXUS Supabase Sync Test")
    print("=" * 60)
    
    # Run sync
    result = run_sync()
    
    print(f"\nSync result: {json.dumps(result, indent=2)}")
    
    # Check status
    print(f"\nSync status: {json.dumps(get_sync_status(), indent=2)}")
    
    # Verify by reading from Supabase
    print("\n--- Supabase verification ---")
    nexus_rows = supabase_query("nexus", limit=5)
    for row in nexus_rows[:5]:
        print(f"  {row.get('topic','?'):30s} {row.get('fact','?')[:60]}")
    
    print(f"\nTotal NEXUS rows in Supabase: {supabase_count('nexus')}")
    print("=" * 60)