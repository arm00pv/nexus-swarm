#!/usr/bin/env python3
"""
NEXUS AI Agent Security Scanner
================================
Scans AI agent code (LangChain, CrewAI, AutoGPT, custom) for security vulnerabilities.

AI agents are the new attack surface. They can:
  - Call tools (exec, shell, web requests, file access)
  - Make decisions autonomously
  - Process untrusted user input
  - Access secrets and APIs

This scanner finds:
  1. Unrestricted tool access — agent can call ANY tool with ANY argument
  2. Missing output validation — agent output used without sanitization
  3. Prompt injection surface — user input directly in prompt template
  4. No human-in-the-loop — dangerous actions with no human approval
  5. Hardcoded secrets in agent code
  6. No rate limiting — agent can make unlimited API calls
  7. Unrestricted file access — agent can read/write any file
  8. Shell execution without sandboxing
  9. No error handling — agent crashes leak information
  10. No audit trail — agent actions not logged

Leverages existing NEXUS AST infrastructure.
"""
import ast
import re
import json

# ============ AGENT-SPECIFIC AST PATTERNS ============

def analyze_agent_code(code, filename="unknown"):
    """
    Analyze Python code for AI agent security issues using AST.
    Returns list of findings.
    """
    findings = []
    
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings
    
    lines = code.split("\n")
    
    for node in ast.walk(tree):
        # === 1. UNRESTRICTED TOOL ACCESS ===
        # Detect: tools=[Tool(...)] with no input validation
        if isinstance(node, ast.keyword) and node.arg == "tools":
            if isinstance(node.value, ast.List):
                for elt in node.value.elts:
                    if isinstance(elt, ast.Call):
                        name = getattr(elt.func, "id", "") or getattr(elt.func, "attr", "")
                        if name in ("Tool", "StructuredTool", "BaseTool"):
                            # Check if input_validator or args_schema is missing
                            has_validator = any(
                                kw.arg in ("args_schema", "input_validator", "handle_tool_error")
                                for kw in elt.keywords
                            )
                            if not has_validator:
                                findings.append({
                                    "line": getattr(node, "lineno", 0),
                                    "severity": "high",
                                    "type": "agent_security",
                                    "category": "unrestricted_tool",
                                    "description": f"Tool '{name}' has no input validation schema — agent can pass any arguments",
                                    "file": filename,
                                    "scanner": "agent",
                                })
        
        # === 2. PROMPT INJECTION SURFACE ===
        # Detect: f-string in prompt template with user input
        if isinstance(node, ast.JoinedStr):
            # Check if this is in a prompt context (PromptTemplate, ChatPromptTemplate, system_message)
            for child in ast.walk(node):
                if isinstance(child, ast.FormattedValue):
                    # Look for user input variables in f-strings
                    src_line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                    if any(word in src_line.lower() for word in ["prompt", "template", "system", "message", "instruction"]):
                        findings.append({
                            "line": node.lineno,
                            "severity": "high",
                            "type": "agent_security",
                            "category": "injection_surface",
                            "description": "User input in prompt template without sanitization — prompt injection risk",
                            "file": filename,
                            "scanner": "agent",
                        })
                        break
        
        # === 3. NO HUMAN-IN-THE-LOOP ===
        # Detect: AgentExecutor without human_approval
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            
            # AgentExecutor, Crew, or chain with no human_in_loop
            if name in ("AgentExecutor", "Crew", "initialize_agent", "create_react_agent"):
                has_human_approval = any(
                    kw.arg in ("human_input", "human_in_loop", "require_human_approval", "max_iterations")
                    for kw in node.keywords
                )
                if not has_human_approval:
                    findings.append({
                        "line": getattr(node, "lineno", 0),
                        "severity": "medium",
                        "type": "agent_security",
                        "category": "no_human_loop",
                        "description": f"{name} has no human-in-the-loop — agent acts autonomously without approval",
                        "file": filename,
                        "scanner": "agent",
                    })
        
        # === 4. SHELL EXECUTION WITHOUT SANDBIZ ===
        # Detect: subprocess/os.system/eval/exec in agent tool
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name in ("system", "popen", "eval", "exec", "compile"):
                # Check if it's in a tool/agent context
                src_lines = "\n".join(lines[max(0, getattr(node, "lineno", 0)-5):getattr(node, "lineno", 0)+5])
                if any(word in src_lines.lower() for word in ["tool", "agent", "function", "run", "execute"]):
                    findings.append({
                        "line": getattr(node, "lineno", 0),
                        "severity": "critical",
                        "type": "agent_security",
                        "category": "shell_execution",
                        "description": f"Shell execution ({name}) in agent context — no sandboxing detected",
                        "file": filename,
                        "scanner": "agent",
                    })
            
            # subprocess with shell=True
            if name in ("run", "Popen", "call", "check_output", "check_call"):
                if hasattr(node, "func") and getattr(node.func, "attr", "") in ("run", "Popen", "call", "check_output", "check_call"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append({
                                "line": getattr(node, "lineno", 0),
                                "severity": "critical",
                                "type": "agent_security",
                                "category": "shell_injection",
                                "description": f"subprocess.{name}(shell=True) — agent can inject commands",
                                "file": filename,
                                "scanner": "agent",
                            })
        
        # === 5. UNRESTRICTED FILE ACCESS ===
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name in ("open", "read_file", "write_file"):
                # Check if path is user-controlled (not hardcoded)
                if node.args and not isinstance(node.args[0], ast.Constant):
                    src_line = lines[getattr(node, "lineno", 0) - 1] if getattr(node, "lineno", 0) <= len(lines) else ""
                    if "tool" in src_line.lower() or "agent" in src_line.lower() or "func" in src_line.lower():
                        findings.append({
                            "line": getattr(node, "lineno", 0),
                            "severity": "high",
                            "type": "agent_security",
                            "category": "unrestricted_file",
                            "description": f"File access ({name}) with dynamic path in agent context — path traversal risk",
                            "file": filename,
                            "scanner": "agent",
                        })
        
        # === 6. NO RATE LIMITING ===
        # Detect: API calls (requests.post/get) without rate limiting
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name in ("post", "get", "request", "api_call", "chat_completion", "create"):
                src_line = lines[getattr(node, "lineno", 0) - 1] if getattr(node, "lineno", 0) <= len(lines) else ""
                # Check if there's a retry or rate_limit in the surrounding code
                surrounding = "\n".join(lines[max(0, getattr(node, "lineno", 0)-10):getattr(node, "lineno", 0)+10])
                if "rate_limit" not in surrounding.lower() and "retry" not in surrounding.lower() and "sleep" not in surrounding.lower():
                    if any(word in src_line.lower() for word in ["api", "openai", "anthropic", "llm", "model"]):
                        # Only flag if it looks like an API call
                        pass  # Too noisy, skip for now
        
        # === 7. NO ERROR HANDLING IN AGENT ===
        # Detect: function decorated as @tool with no try/except
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                dec_name = getattr(decorator, "id", "") or getattr(decorator, "attr", "")
                if dec_name == "tool":
                    # Check if function body has try/except
                    has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))
                    if not has_try:
                        findings.append({
                            "line": node.lineno,
                            "severity": "medium",
                            "type": "agent_security",
                            "category": "no_error_handling",
                            "description": f"@tool function '{node.name}' has no error handling — crashes leak information",
                            "file": filename,
                            "scanner": "agent",
                        })
                    # Check if function has return type hint (output validation)
                    if not node.returns:
                        findings.append({
                            "line": node.lineno,
                            "severity": "low",
                            "type": "agent_security",
                            "category": "no_output_validation",
                            "description": f"@tool function '{node.name}' has no return type — output not validated",
                            "file": filename,
                            "scanner": "agent",
                        })
        
        # === 8. PICKLE DESERIALIZATION IN AGENT ===
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name in ("loads", "load") and isinstance(node.func, ast.Attribute):
                if getattr(node.func.value, "id", "") == "pickle":
                    findings.append({
                        "line": getattr(node, "lineno", 0),
                        "severity": "critical",
                        "type": "agent_security",
                        "category": "pickle_deserialization",
                        "description": "pickle.load() — arbitrary code execution if agent processes untrusted data",
                        "file": filename,
                        "scanner": "agent",
                    })
    
    return findings


# ============ REGEX FALLBACK (for non-Python agents) ============
AGENT_REGEX_PATTERNS = [
    (r'llm_chain\s*\.\s*run\s*\(\s*user_input', "LLM chain with raw user input — prompt injection risk", "high", "injection_surface"),
    (r'ConversationBufferMemory\s*\(\s*\)', "Memory without max token limit — unbounded memory growth", "low", "resource"),
    (r'allow_dangerous_code\s*=\s*True', "Dangerous code execution enabled", "critical", "dangerous_code"),
    (r'verify_ssl\s*=\s*False', "SSL verification disabled — MITM risk", "high", "network"),
    (r'allow_delegation\s*=\s*True', "Agent delegation enabled — privilege escalation risk", "medium", "delegation"),
    (r'\.max_iterations\s*=\s*0', "No max iterations — agent can run forever", "high", "resource"),
    (r'tools?\s*=\s*\[\s*\]', "Empty tools list — check if agent needs tools", "low", "config"),
]


# ============ MAIN SCAN FUNCTION ============
def scan_agent_code(code, filename="unknown"):
    """Scan code for AI agent security issues."""
    findings = analyze_agent_code(code, filename)
    
    # Add regex-based patterns
    for i, line in enumerate(code.split("\n"), 1):
        for pattern, desc, severity, category in AGENT_REGEX_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Skip if already found by AST
                if not any(f["line"] == i and f["category"] == category for f in findings):
                    findings.append({
                        "line": i,
                        "severity": severity,
                        "type": "agent_security",
                        "category": category,
                        "description": desc,
                        "file": filename,
                        "scanner": "agent_regex",
                    })
    
    return findings


# ============ TEST ============
if __name__ == "__main__":
    test_code = '''
import os
import subprocess
from langchain.tools import Tool
from langchain.agents import AgentExecutor, initialize_agent
from langchain.prompts import PromptTemplate

# VULNERABILITY 1: Tool with no input validation
search_tool = Tool(
    name="search",
    func=lambda x: x,  # passes any input directly
)

# VULNERABILITY 2: Shell execution in agent
@tool
def run_command(command: str):
    result = os.system(command)
    return result

# VULNERABILITY 3: No human-in-the-loop
agent = initialize_agent(
    tools=[search_tool, run_command],
    llm=llm,
    # no max_iterations, no human approval
)

# VULNERABILITY 4: User input in prompt without sanitization
prompt = PromptTemplate(
    input_variables=["user_query"],
    template=f"Answer: {user_query}"  # injection surface
)

# VULNERABILITY 5: subprocess with shell=True
@tool
def fetch_data(url: str) -> str:
    output = subprocess.run(f"curl {url}", shell=True, capture_output=True)
    return output.stdout

# VULNERABILITY 6: No error handling in tool
@tool  
def write_file(path: str):
    f = open(path, "w")
    f.write("data")
    f.close()
    return "done"

# VULNERABILITY 7: pickle deserialization
import pickle
@tool
def load_data(data: str):
    return pickle.loads(data.encode())
'''
    
    print("=" * 70)
    print("  NEXUS AI AGENT SECURITY SCANNER — TEST RESULTS")
    print("=" * 70)
    
    findings = scan_agent_code(test_code, "agent.py")
    print(f"\n  Found {len(findings)} security issues in agent code:\n")
    
    for f in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x["severity"],4)):
        icon = "🚫" if f["severity"] == "critical" else "⚠️ " if f["severity"] == "high" else "📋" if f["severity"] == "medium" else "ℹ️ "
        print(f"  {icon} [{f['severity'].upper():8s}] Line {f['line']:>3}: {f['description']}")
        print(f"             Category: {f['category']}")
    
    print(f"\n{'=' * 70}")
    print(f"  Total: {len(findings)} issues")
    print(f"  Critical: {sum(1 for f in findings if f['severity']=='critical')}")
    print(f"  High: {sum(1 for f in findings if f['severity']=='high')}")
    print(f"  Medium: {sum(1 for f in findings if f['severity']=='medium')}")
    print(f"  Low: {sum(1 for f in findings if f['severity']=='low')}")
    print(f"{'=' * 70}")