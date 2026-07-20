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

MAX_MUTATIONS = 20        #