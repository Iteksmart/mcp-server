# iTechSmart MCP Server

**Connect any AI agent to UAIO — Autonomous IT Operations + ProofLink™ Verification**

> The SaaS products that become agent-ready in 2026 win the enterprise deals.

---

## What this does

This MCP server exposes iTechSmart's UAIO platform as tools any MCP-compatible AI agent can call — Claude, ChatGPT, Copilot, Cursor, and any other agent that speaks the Model Context Protocol.

Once connected, your AI agent can:
- **Verify** ProofLink cryptographic receipts — confirm autonomous AI actions weren't tampered with
- **Query** UAIO platform status — real-time health across 131 production containers
- **Fetch** incident details — what the AI did, when, with cryptographic proof
- **List** recent autonomous remediations — full audit trail
- **Simulate** infrastructure attacks — trigger the break-it sandbox live

---

## Quick Start

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "itechsmart": {
      "command": "npx",
      "args": ["-y", "@itechsmart/mcp-server"],
      "env": {
        "ITECHSMART_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Get your API key: contact [enterprise@itechsmart.dev](mailto:enterprise@itechsmart.dev) or [itechsmart.dev/contact](https://itechsmart.dev/contact)

### Remote MCP (SSE)

```
https://mcp.itechsmart.dev/sse
```

For platforms that support remote MCP servers directly (Cursor, Continue, etc.).

---

## Tools

### `verify_prooflink_receipt`

Verify the cryptographic integrity of a ProofLink receipt.

```
Agent: "Verify ProofLink receipt a1b2c3d4e5f6a7b8"

→ Returns:
{
  "receipt_id": "a1b2c3d4e5f6a7b8",
  "verification_result": "VERIFIED ✓",
  "tamper_detected": false,
  "action": "kubectl patch memory 512Mi→1024Mi + rollout restart",
  "human_input": "ZERO",
  "sha256": "abc123...",
  "verify_url": "https://verify.itechsmart.dev/a1b2c3d4e5f6a7b8"
}
```

### `get_receipt_chain`

Fetch and verify the complete ProofLink receipt chain.

```
Agent: "Check the full UAIO audit trail for the last 20 actions"

→ Returns: complete chain with tamper detection across all receipts
```

### `query_uaio_status`

Get real-time UAIO platform health and metrics.

```
Agent: "What's the current status of the iTechSmart platform?"

→ Returns:
{
  "status": "OPERATIONAL",
  "containers": { "healthy": 131, "total": 131 },
  "prooflink": { "receipts_generated": 134, "chain_breaks": 0 },
  "compliance": { "nist_csf": "96/100", "hipaa": "100/100" }
}
```

### `get_incident_details`

Fetch full details of a specific autonomous remediation.

```
Agent: "Show me what UAIO did during incident inc-1746960000"

→ Returns: trigger, action taken, before/after state, ProofLink receipt
```

### `list_recent_incidents`

List recent autonomous IT remediations.

```
Agent: "List the last 10 things UAIO fixed automatically"

→ Returns: chronological incident list with detection/remediation times
```

### `simulate_infrastructure_attack`

Trigger the break-it sandbox — watch the UAIO loop live.

```
Agent: "Simulate a Kubernetes OOMKilled crash and show me the ProofLink receipt"

→ Returns: full 5-phase UAIO simulation with cryptographic receipt
```

---

## Example Agent Workflows

### Compliance Audit Workflow
```
"Fetch the last 50 ProofLink receipts, verify chain integrity, 
and generate a compliance report for our SOC 2 audit."

→ Agent calls get_receipt_chain(limit=50)
→ Verifies all 50 receipts
→ Reports: chain_valid, any tamper positions, NIST control coverage
```

### Incident Investigation Workflow
```
"What did the AI fix last night between 2-4AM and can you prove it?"

→ Agent calls list_recent_incidents(since="2026-05-11T02:00:00Z")
→ Agent calls get_incident_details for each incident
→ Agent calls verify_prooflink_receipt for each receipt
→ Returns: complete verified audit trail
```

### Monitoring Workflow
```
"Check if the iTechSmart platform is healthy before we run our demo."

→ Agent calls query_uaio_status()
→ Returns: operational status, container health, compliance scores
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ITECHSMART_API_KEY` | Yes | API key — contact enterprise@itechsmart.dev or itechsmart.dev/contact |
| `ITECHSMART_API_URL` | No | Custom API URL (default: https://app.itechsmart.dev/api/v1) |

---

## Development

```bash
git clone https://github.com/Iteksmart/mcp-server
cd mcp-server
npm install
npm run build
npm start
```

---

## Links

- Platform: [itechsmart.dev](https://itechsmart.dev)
- Live demo: [itechsmart.dev/break-it](https://itechsmart.dev/break-it)
- Verify receipts: [verify.itechsmart.dev](https://verify.itechsmart.dev)
- Open-source verifier: [github.com/Iteksmart/prooflink-verifier](https://github.com/Iteksmart/prooflink-verifier)
- API docs: [docs.itechsmart.dev](https://docs.itechsmart.dev)

---

## About iTechSmart

iTechSmart builds UAIO — Unified Autonomous IT Operations. The first platform that autonomously detects, remediates, and cryptographically proves every infrastructure action.

SDVOSB · CAGE: 172W2 · NVIDIA Inception · F6S #6 Global · NIST CSF 96/100

---

MIT License — iTechSmart Inc. 2026
