#!/usr/bin/env python3
"""
NEXUS AIBOM Generator — AI Bill of Materials
==============================================
First open-source AIBOM (AI Bill of Materials) generator.

The NTIA (National Telecommunications and Information Administration) is 
defining the AIBOM standard NOW. Federal SBOM requirements (EO 14028) don't 
cover AI systems. This fills that gap.

An AIBOM documents:
  - AI model: name, version, provider, hash, parameters
  - Training data: sources, licenses, known biases, data sheet
  - System prompt: the instructions the AI follows (for audit)
  - Tools: what the agent can call (attack surface)
  - Guardrails: what safety measures are in place
  - Human oversight: can a human override the agent?
  - Data flows: where does data go? (privacy)
  - Known risks: hallucination patterns, failure modes
  - Compliance: EU AI Act, NIST AI RMF, ISO 42001

AIBOM JSON format (compatible with CycloneDX extension):
{
  "aibom_version": "1.0",
  "generated": "2025-01-15T12:00:00Z",
  "system": {
    "name": "...",
    "type": "agent|chatbot|pipeline|rag",
    "description": "..."
  },
  "models": [
    {
      "name": "gpt-4",
      "provider": "OpenAI",
      "version": "turbo-2024-04-09",
      "capabilities": ["text-generation", "tool-use"],
      "max_tokens": 128000,
      "safety_rating": "unknown"
    }
  ],
  "training_data": [...],
  "system_prompt": "You are a helpful...",
  "tools": [...],
  "guardrails": [...],
  "human_oversight": {...},
  "data_flows": [...],
  "known_risks": [...],
  "compliance": {...}
}
"""
import ast
import re
import json
import os
import datetime
import hashlib

# ============ AIBOM SPEC ============
AIBOM_VERSION = "1.0"

def generate_aibom(code, filename="agent.py", system_name="AI System"):
    """
    Generate an AIBOM by analyzing AI agent code.
    
    Scans code for:
      - Model usage (LLM provider, model name, version)
      - System prompts (extracted from code)
      - Tools (what the agent can call)
      - Guardrails (safety measures detected)
      - Human oversight (approval mechanisms)
      - Data flows (external API calls, file access)
      - Known risks (based on patterns found)
    """
    aibom = {
        "aibom_version": AIBOM_VERSION,
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "system": {
            "name": system_name,
            "type": _detect_system_type(code),
            "description": f"Generated from {filename}",
            "file_hash": hashlib.sha256(code.encode()).hexdigest()[:16],
        },
        "models": _extract_models(code),
        "training_data": _extract_training_data(code),
        "system_prompts": _extract_prompts(code),
        "tools": _extract_tools(code),
        "guardrails": _detect_guardrails(code),
        "human_oversight": _detect_oversight(code),
        "data_flows": _extract_data_flows(code),
        "known_risks": _assess_risks(code),
        "compliance": _check_compliance(code),
    }
    
    # Calculate risk score
    risks = aibom["known_risks"]
    aibom["risk_score"] = _calculate_risk_score(aibom)
    
    return aibom


def _detect_system_type(code):
    """Detect what type of AI system this is."""
    if "AgentExecutor" in code or "initialize_agent" in code:
        return "agent"
    if "ConversationChain" in code or "ChatModel" in code:
        return "chatbot"
    if "RetrievalQA" in code or "vectorstore" in code.lower() or "embeddings" in code.lower():
        return "rag"
    if "Pipeline" in code or "pipeline" in code.lower():
        return "pipeline"
    return "unknown"


def _extract_models(code):
    """Extract AI model usage from code."""
    models = []
    
    model_patterns = [
        (r'ChatOpenAI\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "OpenAI", "chat"),
        (r'OpenAI\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "OpenAI", "completion"),
        (r'ChatAnthropic\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "Anthropic", "chat"),
        (r'Anthropic\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "Anthropic", "chat"),
        (r'llama_cpp\s*\(\s*model_path\s*=\s*["\']([^"\']+)["\']', "llama.cpp", "local"),
        (r'Ollama\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "Ollama", "local"),
        (r'HuggingFaceHub\s*\(\s*repo_id\s*=\s*["\']([^"\']+)["\']', "HuggingFace", "completion"),
        (r'model\s*=\s*["\']([^"\']+)["\'].*(?:openai|anthropic|ollama)', "unknown", "unknown"),
        (r'deepseek', "DeepSeek", "chat"),
        (r'ollama\.chat\s*\(\s*model\s*=\s*["\']([^"\']+)["\']', "Ollama", "chat"),
    ]
    
    seen = set()
    for pattern, provider, model_type in model_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            model_name = match.group(1) if match.groups() else "unknown"
            key = (provider, model_name)
            if key not in seen:
                seen.add(key)
                models.append({
                    "name": model_name,
                    "provider": provider,
                    "type": model_type,
                    "version": "latest",
                    "capabilities": _infer_capabilities(model_name),
                    "safety_rating": "unknown",
                    "local": provider in ("Ollama", "llama.cpp", "HuggingFace"),
                })
    
    # Also detect generic LLM calls
    if not models:
        if "llm" in code.lower() or "completion" in code.lower() or "chat" in code.lower():
            models.append({
                "name": "unknown",
                "provider": "unknown",
                "type": "unknown",
                "version": "unknown",
                "capabilities": [],
                "safety_rating": "unknown",
                "local": False,
            })
    
    return models


def _infer_capabilities(model_name):
    """Infer model capabilities from model name."""
    caps = []
    name_lower = model_name.lower()
    if any(w in name_lower for w in ["gpt-4", "claude", "gemini", "llama", "deepseek", "qwen", "mistral"]):
        caps.extend(["text-generation", "tool-use"])
    if "vision" in name_lower or "image" in name_lower:
        caps.append("vision")
    if "embed" in name_lower:
        caps.append("embeddings")
    if "whisper" in name_lower or "audio" in name_lower:
        caps.append("audio")
    return caps


def _extract_training_data(code):
    """Extract training data references from code."""
    data = []
    
    patterns = [
        (r'dataset\s*=\s*["\']([^"\']+)["\']', "dataset_path"),
        (r'training_data\s*=\s*["\']([^"\']+)["\']', "training_data_path"),
        (r'load_dataset\s*\(\s*["\']([^"\']+)["\']', "huggingface_dataset"),
        (r'csv|jsonl?|parquet', "file_format"),
    ]
    
    for pattern, source_type in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            if match.groups():
                data.append({
                    "source": match.group(1)[:100],
                    "type": source_type,
                    "license": "unknown",
                    "known_biases": "not_assessed",
                })
    
    return data


def _extract_prompts(code):
    """Extract system prompts from code."""
    prompts = []
    
    # Look for prompt templates
    patterns = [
        (r'(?:system_prompt|system_message|SYSTEM_PROMPT)\s*=\s*["\']([^"\']{10,})["\']', "system_prompt"),
        (r'(?:template|prompt)\s*=\s*["\']([^"\']{20,})["\']', "prompt_template"),
        (r'(?:role|content)\s*=\s*"system".*?content\s*=\s*["\']([^"\']{10,})["\']', "chat_system"),
        (r'PromptTemplate\s*\(\s*template\s*=\s*["\']([^"\']{10,})["\']', "langchain_template"),
    ]
    
    for pattern, prompt_type in patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
            prompt_text = match.group(1)[:500]  # Truncate for safety
            prompts.append({
                "type": prompt_type,
                "preview": prompt_text[:200] + "..." if len(prompt_text) > 200 else prompt_text,
                "full_length": len(match.group(1)),
                "sanitized": True,  # We only store preview
            })
    
    return prompts


def _extract_tools(code):
    """Extract tools the agent can call."""
    tools = []
    
    # @tool decorator
    for match in re.finditer(r'@tool\s+def\s+(\w+)\s*\(([^)]*)\)', code):
        name = match.group(1)
        params = match.group(2)
        tools.append({
            "name": name,
            "parameters": params.strip(),
            "dangerous": _is_dangerous_tool(name, code),
        })
    
    # Tool() constructor
    for match in re.finditer(r'Tool\s*\(\s*name\s*=\s*["\']([^"\']+)["\'].*?func\s*=\s*(\w+)', code, re.DOTALL):
        name = match.group(1)
        func_name = match.group(2)
        tools.append({
            "name": name,
            "function": func_name,
            "dangerous": _is_dangerous_tool(func_name, code),
        })
    
    # Detect dangerous function calls within tools
    dangerous_funcs = ["os.system", "subprocess", "eval(", "exec(", "open(", "requests.post", "requests.get"]
    for func in dangerous_funcs:
        if func in code:
            # Check if it's in a tool context
            for match in re.finditer(f'(?:@tool|def tool_|Tool\\().*?{re.escape(func)}', code, re.DOTALL):
                tools.append({
                    "name": func,
                    "dangerous": True,
                    "reason": "Can execute arbitrary code or access resources",
                })
                break
    
    return tools


def _is_dangerous_tool(name, code):
    """Check if a tool function is dangerous."""
    dangerous_indicators = ["exec", "shell", "system", "subprocess", "eval", "file", "delete", "remove", "write", "network", "http"]
    return any(ind in name.lower() for ind in dangerous_indicators)


def _detect_guardrails(code):
    """Detect safety guardrails in the code."""
    guardrails = []
    
    checks = [
        (r"input_validation|validate_input|sanitize", "Input validation", "high"),
        (r"output_parser|parse_output|validate_output", "Output validation", "high"),
        (r"content_filter|safety_check|guardrail", "Content filtering", "critical"),
        (r"max_tokens\s*[=:]\s*\d+", "Token limit", "medium"),
        (r"max_iterations\s*[=:]\s*\d+", "Iteration limit", "medium"),
        (r"rate_limit|throttle", "Rate limiting", "medium"),
        (r"timeout\s*[=:]\s*\d+", "Timeout", "medium"),
        (r"try.*except.*error", "Error handling", "low"),
        (r"logging|logger|log\.", "Audit logging", "high"),
        (r"human_approval|require_approval|confirm\(", "Human approval", "critical"),
        (r"Conscience|conscience|anti_hallucination", "Anti-hallucination", "high"),
    ]
    
    for pattern, name, importance in checks:
        if re.search(pattern, code, re.IGNORECASE):
            guardrails.append({
                "name": name,
                "implemented": True,
                "importance": importance,
            })
    
    # Check for MISSING guardrails
    implemented_names = {g["name"] for g in guardrails}
    required = [
        ("Input validation", "high"),
        ("Output validation", "high"),
        ("Audit logging", "high"),
        ("Human approval", "critical"),
    ]
    for name, importance in required:
        if name not in implemented_names:
            guardrails.append({
                "name": name,
                "implemented": False,
                "importance": importance,
            })
    
    return guardrails


def _detect_oversight(code):
    """Detect human oversight mechanisms."""
    oversight = {
        "has_human_in_loop": False,
        "can_override": False,
        "can_pause": False,
        "can_stop": False,
        "approval_required_for": [],
    }
    
    if re.search(r"human_in_loop|human_input|require_approval|confirm", code, re.IGNORECASE):
        oversight["has_human_in_loop"] = True
    if re.search(r"override|abort|stop_agent|cancel", code, re.IGNORECASE):
        oversight["can_override"] = True
    if re.search(r"pause|suspend|halt", code, re.IGNORECASE):
        oversight["can_pause"] = True
    if re.search(r"stop|kill|terminate|max_iterations", code, re.IGNORECASE):
        oversight["can_stop"] = True
    
    # Check what requires approval
    if "exec" in code.lower() or "shell" in code.lower():
        oversight["approval_required_for"].append("shell_execution")
    if "delete" in code.lower() or "remove" in code.lower():
        oversight["approval_required_for"].append("file_deletion")
    if "post" in code.lower() or "send" in code.lower():
        oversight["approval_required_for"].append("external_data_transfer")
    
    return oversight


def _extract_data_flows(code):
    """Map where data flows in the system."""
    flows = []
    
    flow_patterns = [
        (r"requests\.(post|put)\s*\(\s*['\"]([^'\"]+)['\"]", "outbound_http", "external"),
        (r"requests\.(get)\s*\(\s*['\"]([^'\"]+)['\"]", "inbound_http", "external"),
        (r"open\s*\(\s*['\"]([^'\"]+)['\"]", "file_access", "local"),
        (r"subprocess|os\.system", "shell_execution", "system"),
        (r"(?:postgre|mysql|mongo|redis).*?://", "database", "database"),
        (r"api[_\-]?key|token|secret", "credential_use", "sensitive"),
        (r"upload|send_data|exfiltrate", "data_upload", "external"),
    ]
    
    for pattern, flow_type, destination in flow_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            flows.append({
                "type": flow_type,
                "destination": destination,
                "encrypted": "unknown",
            })
    
    return flows


def _assess_risks(code):
    """Assess known risks based on code patterns."""
    risks = []
    
    risk_checks = [
        (r"os\.system|subprocess.*shell\s*=\s*True|eval\(|exec\(", "Arbitrary code execution", "critical"),
        (r"open\s*\([^)]*\)\s*$", "Unrestricted file access", "high"),
        (r"requests\.(post|put).*data", "External data transmission without validation", "high"),
        (r"pickle\.load", "Unsafe deserialization", "critical"),
        (r"verify_ssl\s*=\s*False", "SSL verification disabled", "high"),
        (r"allow_dangerous_code", "Dangerous code execution flag enabled", "critical"),
        (r"\{[^}]*user_input[^}]*\}", "User input in format string — prompt injection risk", "high"),
    ]
    
    for pattern, risk, severity in risk_checks:
        if re.search(pattern, code, re.IGNORECASE):
            risks.append({
                "risk": risk,
                "severity": severity,
                "mitigation": "Add input validation, sandboxing, and human oversight",
            })
    
    return risks


def _check_compliance(code):
    """Check compliance with AI regulations."""
    return {
        "eu_ai_act": {
            "transparency": bool(re.search(r"log|trace|audit|explain", code, re.IGNORECASE)),
            "human_oversight": bool(re.search(r"human|approval|override", code, re.IGNORECASE)),
            "risk_assessment": bool(re.search(r"risk|assess|evaluate", code, re.IGNORECASE)),
            "data_governance": bool(re.search(r"data.*govern|privacy|gdpr|consent", code, re.IGNORECASE)),
            "bias_testing": bool(re.search(r"bias|fairness|discriminat", code, re.IGNORECASE)),
        },
        "nist_ai_rmf": {
            "govern": bool(re.search(r"policy|govern|framework", code, re.IGNORECASE)),
            "map": bool(re.search(r"risk|assess|map.*risk", code, re.IGNORECASE)),
            "measure": bool(re.search(r"metric|measure|evaluat|benchmark", code, re.IGNORECASE)),
            "manage": bool(re.search(r"mitigat|manage|control|monitor", code, re.IGNORECASE)),
        },
        "iso_42001": {
            "ai_management_system": False,  # Requires org-level implementation
            "risk_management": bool(re.search(r"risk|assess", code, re.IGNORECASE)),
            "impact_assessment": bool(re.search(r"impact|assess", code, re.IGNORECASE)),
        },
    }


def _calculate_risk_score(aibom):
    """Calculate overall risk score (0-100, higher = more risky)."""
    score = 0
    
    # Each risk adds to score
    for risk in aibom.get("known_risks", []):
        if risk["severity"] == "critical":
            score += 25
        elif risk["severity"] == "high":
            score += 15
        elif risk["severity"] == "medium":
            score += 5
    
    # Missing guardrails add to score
    for g in aibom.get("guardrails", []):
        if not g["implemented"]:
            if g["importance"] == "critical":
                score += 15
            elif g["importance"] == "high":
                score += 10
    
    # No human oversight adds risk
    if not aibom.get("human_oversight", {}).get("has_human_in_loop", False):
        score += 10
    
    # Dangerous tools add risk
    dangerous_tools = sum(1 for t in aibom.get("tools", []) if t.get("dangerous"))
    score += dangerous_tools * 10
    
    return min(100, score)


# ============ TEST ============
if __name__ == "__main__":
    test_agent = '''
import os
import subprocess
from langchain.tools import Tool
from langchain.agents import AgentExecutor, initialize_agent
from langchain.chat_models import ChatOpenAI
from langchain.prompts import PromptTemplate

# Model
llm = ChatOpenAI(model="gpt-4-turbo", temperature=0)

# System prompt
SYSTEM_PROMPT = "You are a helpful coding assistant. Use tools to help users."

# Tool 1: Run command (DANGEROUS)
@tool
def run_command(command: str) -> str:
    """Execute a shell command."""
    result = os.system(command)
    return str(result)

# Tool 2: Read file (DANGEROUS - path traversal)
@tool
def read_file(path: str) -> str:
    """Read a file."""
    with open(path) as f:
        return f.read()

# Tool 3: Safe tool
@tool
def calculate(expression: str) -> str:
    """Calculate a math expression."""
    try:
        return str(eval(expression))
    except Exception as e:
        return f"Error: {e}"

# Agent (no human in loop, no max iterations)
agent = initialize_agent(
    tools=[run_command, read_file, calculate],
    llm=llm,
)

# Prompt template with user input (injection surface)
prompt = PromptTemplate(
    input_variables=["user_query"],
    template="Answer: {user_query}"
)

import logging
logging.basicConfig()
'''
    
    print("=" * 70)
    print("  NEXUS AIBOM GENERATOR — FIRST OPEN-SOURCE AI BILL OF MATERIALS")
    print("=" * 70)
    
    aibom = generate_aibom(test_agent, "agent.py", "Test Agent")
    
    print(f"\n  AIBOM Version: {aibom['aibom_version']}")
    print(f"  Generated: {aibom['generated']}")
    print(f"  Risk Score: {aibom['risk_score']}/100")
    
    print(f"\n  System: {aibom['system']['name']} (type: {aibom['system']['type']})")
    
    print(f"\n  Models ({len(aibom['models'])}):")
    for m in aibom["models"]:
        print(f"    - {m['name']} ({m['provider']}, {'local' if m['local'] else 'cloud'})")
    
    print(f"\n  System Prompts ({len(aibom['system_prompts'])}):")
    for p in aibom["system_prompts"]:
        print(f"    - [{p['type']}] {p['preview'][:60]}...")
    
    print(f"\n  Tools ({len(aibom['tools'])}):")
    for t in aibom["tools"]:
        danger = "🚫 DANGEROUS" if t.get("dangerous") else "✅ Safe"
        print(f"    - {t['name']}: {danger}")
    
    print(f"\n  Guardrails ({len(aibom['guardrails'])}):")
    for g in aibom["guardrails"]:
        status = "✅" if g["implemented"] else "❌ MISSING"
        print(f"    {status} {g['name']} ({g['importance']})")
    
    print(f"\n  Human Oversight:")
    ho = aibom["human_oversight"]
    print(f"    Human in loop: {ho['has_human_in_loop']}")
    print(f"    Can override: {ho['can_override']}")
    print(f"    Approval required for: {ho['approval_required_for']}")
    
    print(f"\n  Data Flows ({len(aibom['data_flows'])}):")
    for f in aibom["data_flows"]:
        print(f"    - {f['type']} → {f['destination']}")
    
    print(f"\n  Known Risks ({len(aibom['known_risks'])}):")
    for r in aibom["known_risks"]:
        print(f"    [{r['severity'].upper():8s}] {r['risk']}")
    
    print(f"\n  Compliance:")
    for framework, checks in aibom["compliance"].items():
        passing = sum(1 for v in checks.values() if v)
        total = len(checks)
        print(f"    {framework}: {passing}/{total} checks pass")
    
    # Output JSON
    print(f"\n{'=' * 70}")
    print("  AIBOM JSON:")
    print(json.dumps(aibom, indent=2)[:2000])
    print(f"  ... ({len(json.dumps(aibom))} bytes total)")
    print(f"{'=' * 70}")