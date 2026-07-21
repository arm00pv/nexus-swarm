# NEXUS Integration Packages

Plug NEXUS security into the world's most popular AI agent platforms.

## Available Integrations

### 1. Open WebUI Filter (`openwebui_nexus_filter.py`)
**Target**: [Open WebUI](https://github.com/open-webui/open-webui) (146K★)

Intercepts every chat message before the LLM. Blocks prompt injection, redacts secrets in AI output.

**Installation:**
1. Open Open WebUI → Admin Settings → Functions → New Function
2. Name it "Nexus Guardian"
3. Paste the contents of `openwebui_nexus_filter.py`
4. Enable the filter

### 2. Browser Use Guardian (`nexus_browser_guard.py`)
**Target**: [Browser Use](https://github.com/browser-use/browser-use) (106K★)

Wraps browser agents with NEXUS security. Scans page content for injection, checks every action via Guardian.

**Usage:**
```python
from nexus_browser_guard import GuardedBrowserAgent

agent = GuardedBrowserAgent(nexus_api="https://marquezhv.com")

# Scan page before agent reads it
result = agent.check_page_content(page_text, url)

# Check action before agent executes it
action = agent.check_action("click", "#submit-btn", "Submitting form")
```

### 3. Langflow Component (`nexus_langflow_component.py`)
**Target**: [Langflow](https://github.com/langflow-ai/langflow) (152K★)

Custom Langflow component. Drag "NEXUS Guardian" node into your workflow.

**Installation:**
1. `pip install langflow`
2. Copy file to `~/.langflow/custom_components/`
3. Restart Langflow
4. Find "NEXUS Guardian" in the component sidebar

### 4. MCP Guardian Tool (`nexus_mcp_guardian.py`)
**Target**: [Dify](https://github.com/langgenius/dify) (150K★), Langflow, Open WebUI, any MCP platform

Exposes 3 MCP tools: `nexus_guardian_check`, `nexus_injection_scan`, `nexus_generate_aibom`.

### 5. Crawl4AI Guard (`nexus_crawl4ai_guard.py`)
**Target**: [Crawl4AI](https://github.com/unclecode/crawl4ai) (74K★)

Crawls websites and scans content for prompt injection vectors. Feeds real-world data to the Red Team.

### 6. OpenHands Guard (`nexus_openhands_guard.py`)
**Target**: [OpenHands](https://github.com/OpenHands/openhands) (82K★)

Protects OpenHands coding agents. Scans files for injection, checks commands via Guardian, redacts secrets in PR diffs.

## API Endpoints

All integrations call the NEXUS API at `https://marquezhv.com`:

| Endpoint | Method | Description |
|---|---|---|
| `/api/nexus/injection/scan` | POST | Scan text for prompt injection |
| `/api/nexus/guardian/check` | POST | Check tool call through 11 security layers |
| `/api/nexus/sentinel/check` | POST | Guardian + behavioral biometrics |
| `/api/nexus/agent/scan` | POST | Scan AI agent code for vulnerabilities |
| `/api/nexus/aibom` | POST | Generate AI Bill of Materials |
| `/api/nexus/sentinel/dashboard` | GET | Real-time security dashboard |

## Total Addressable Market

| Platform | Stars | Integration |
|---|---|---|
| Langflow | 152K | Custom Component |
| Dify | 150K | MCP Tool |
| Open WebUI | 146K | Filter Plugin + Deployed |
| Browser Use | 106K | Python Wrapper |
| OpenHands | 82K | Python Wrapper |
| Crawl4AI | 74K | Crawl + Scan |
| **Total** | **710K+** | |
