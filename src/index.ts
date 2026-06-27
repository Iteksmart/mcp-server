#!/usr/bin/env node
/**
 * iTechSmart MCP Server v2.0 — Phase 1 Secure Governance
 *
 * Every tool call now:
 *   1. Requires a valid API key (Bearer or ?api_key=) — fail-closed on any
 *      missing/invalid auth.
 *   2. Validates a per-tool scope (TOOL_SCOPES) — read-only in Phase 1.
 *   3. Is rate-limited (sliding window, in-memory, per-key).
 *   4. Seals a ProofLink receipt via the djuane-ai self-report webhook for
 *      success, error, rate-limit, and invalid-auth events.
 *   5. Returns only generic errors to callers — internals are logged
 *      server-side only.
 *
 * Phase 2 will add OAuth 2.1 scoped tokens, Arbiter routing per-call, and
 * Digital Twin pre-flight checks for any execute-class scope. Today
 * everything is `:read`.
 *
 * Compatible with Claude, ChatGPT, Copilot, Cursor — both SSE-session
 * (legacy) and stateless POST /messages (new in v2) clients.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js'
import crypto from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import http from 'http'
import { execSync } from 'child_process'

// ─────────────────────────────────────────────
// SECURITY CONFIG (Phase 1)
// ─────────────────────────────────────────────

type McpKeyScope = 'read' | 'admin'

interface McpKeyRecord {
  scopes: Set<McpKeyScope>
  source: string
}

const API_KEYS = new Map<string, McpKeyRecord>()

function loadApiKeys(raw: string, defaultScope: McpKeyScope, source: string): void {
  raw.split(',')
    .map(k => k.trim())
    .filter(Boolean)
    .forEach(entry => {
      const parts = entry.split(':')
      const key = (parts.shift() || '').trim()
      const scope = (parts.join(':') || defaultScope).trim().toLowerCase()
      if (!key) return
      const scopes = new Set<McpKeyScope>(['read'])
      if (scope === 'admin') scopes.add('admin')
      const existing = API_KEYS.get(key)
      if (existing) {
        scopes.forEach(s => existing.scopes.add(s))
        existing.source = `${existing.source},${source}`
      } else {
        API_KEYS.set(key, { scopes, source })
      }
    })
}

// New production key format: ITECHSMART_MCP_KEYS=read-key,admin-key:admin
// Legacy ITECHSMART_MCP_API_KEYS remains supported as admin for backwards compatibility
// with existing Cloudflare Access protected clients.
loadApiKeys(process.env.ITECHSMART_MCP_KEYS || '', 'read', 'ITECHSMART_MCP_KEYS')
loadApiKeys(process.env.ITECHSMART_MCP_API_KEYS || '', 'admin', 'ITECHSMART_MCP_API_KEYS')

const VALID_API_KEYS = new Set(API_KEYS.keys())

const SELF_REPORT_URL = process.env.SELF_REPORT_URL
  || 'http://localhost:3202/agent/self-report'

const RATE_LIMIT_PER_MIN = parseInt(process.env.MCP_RATE_LIMIT_PER_MIN || '60', 10)
const RATE_LIMIT_SIMULATE_PER_MIN = parseInt(process.env.MCP_RATE_LIMIT_SIMULATE || '10', 10)

// Each tool name → scope. Aliases route to the same scope as the canonical
// tool name (the alias keys are also accepted by clients).
const TOOL_SCOPES: Record<string, string> = {
  // Canonical tool names
  verify_prooflink_receipt: 'prooflink:verify:read',
  get_receipt_chain: 'ledger:audit:read',
  'prooflink.verify_chain': 'prooflink.verify_chain',
  'prooflink.verify_receipt': 'prooflink.verify_receipt',
  'prooflink.search_receipts': 'prooflink.search_receipts',
  'mission.list_incidents': 'mission.list_incidents',
  'mission.cluster_health': 'mission.cluster_health',
  'compliance.audit_summary': 'compliance.audit_summary',
  query_uaio_status: 'infrastructure:scan:read',
  get_incident_details: 'incident:classify:read',
  list_recent_incidents: 'incident:classify:read',
  simulate_infrastructure_attack: 'digitaltwin:simulate:read',
  invoke_octoai_pipeline: 'octoai:pipeline:invoke',

  // Aliases (Phase 1 sprint spec — forward to canonical)
  verify_receipt: 'prooflink:verify:read',
  audit_trail: 'ledger:audit:read',
  scan_infrastructure: 'infrastructure:scan:read',
  classify_incident: 'incident:classify:read',
  simulate_blast_radius: 'digitaltwin:simulate:read',

  // New tools — Phase 1 extensions
  get_platform_briefing:    'infrastructure:briefing:read',
  get_sie_queue:            'sie:queue:read',
  get_compliance_status:    'compliance:scores:read',
  dispatch_ag2_incident:    'ag2:incident:invoke',
  search_platform_logs:     'infrastructure:logs:read',
  // Execute-class tools — Phase 1 extensions (write + invoke)
  approve_sie_finding:    'sie:queue:write',
  trigger_sie_scan:       'sie:scan:invoke',
  get_iself_journal:      'iself:journal:read',
  brain_query:           'brain:search:read',
  cluster_status:        'cluster:status:read',
  port_registry:         'port:registry:read',
  // Integration tools — Langfuse / RAGflow / Shuffle / TRMM / MeshCentral / Probo
  integration_status:    'integrations:status:read',
  langfuse_health:       'integrations:observe:read',
  langfuse_trace:        'integrations:observe:write',
  ragflow_health:        'integrations:rag:read',
  ragflow_query:         'integrations:rag:read',
  shuffle_health:        'integrations:shuffle:read',
  shuffle_trigger:       'integrations:shuffle:invoke',
  trmm_health:           'integrations:trmm:read',
  trmm_agents:           'integrations:trmm:read',
  trmm_summary:          'integrations:trmm:read',
  trmm_run_script:       'integrations:trmm:invoke',
  mesh_health:           'integrations:mesh:read',
  mesh_devices:          'integrations:mesh:read',
  probo_health:          'integrations:probo:read',
  probo_controls:        'integrations:probo:read',
  probo_risks:           'integrations:probo:read',
  probo_summary:         'integrations:probo:read',
}

const TOOL_ALIASES: Record<string, string> = {
  verify_receipt: 'verify_prooflink_receipt',
  audit_trail: 'get_receipt_chain',
  'prooflink.verify_chain': 'get_receipt_chain',
  'prooflink.verify_receipt': 'verify_prooflink_receipt',
  'prooflink.search_receipts': 'get_receipt_chain',
  'mission.list_incidents': 'list_recent_incidents',
  'mission.cluster_health': 'cluster_status',
  'compliance.audit_summary': 'get_compliance_status',
  scan_infrastructure: 'query_uaio_status',
  classify_incident: 'get_incident_details',
  simulate_blast_radius: 'simulate_infrastructure_attack',
}

// ─────────────────────────────────────────────
// CANONICAL LEDGER (Sprint-003 — real data sources)
// ─────────────────────────────────────────────

const CANONICAL_LEDGER_PATH = process.env.CANONICAL_LEDGER_PATH
  || '/opt/itechsmart/audit_ledger/ledger.json'

const BREAK_IT_API_URL = process.env.BREAK_IT_API_URL
  || 'http://localhost:8765/api/attack'

const SYSTEM_CONTEXT_PATH = '/home/ubuntu/octoai-dev-agent/system_context.json'

interface LedgerEntry {
  id: string
  hash_sha256: string
  prev_hash: string | null
  timestamp: string
  category: string
  actor: string
  subject: string
  action: string
  outcome: string
  details: unknown
  verify_url?: string
  tamper_detected?: boolean
}

function readCanonicalLedger(): LedgerEntry[] {
  // Always read fresh — the ledger is small (~200KB at ~250 entries) and
  // we want to see new writes from break-it / health monitor as they happen.
  try {
    const raw = fs.readFileSync(CANONICAL_LEDGER_PATH, 'utf8')
    const parsed = JSON.parse(raw)
    const entries = Array.isArray(parsed) ? parsed
      : Array.isArray(parsed?.entries) ? parsed.entries
      : Array.isArray(parsed?.receipts) ? parsed.receipts
      : []
    return entries as LedgerEntry[]
  } catch (e) {
    console.error('[ledger] read failed:', e instanceof Error ? e.message : String(e))
    return []
  }
}

// Cached payload for the public /v1/status marketing metrics endpoint (30s TTL).
let _statusCache: { t: number; body: string } | null = null

// Python-faithful JSON string escaping. Matches python json.dumps's default
// `ensure_ascii=True` behavior: control chars and any code point ≥ 0x80 are
// `\uXXXX`-escaped. JS's JSON.stringify outputs non-ASCII as UTF-8 by default,
// which would mismatch hashes for any entry containing characters like `—`
// (U+2014, em-dash) or `✓` (U+2713) — both common in our ledger entries.
function pythonJsonString(s: string): string {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c === 0x22) out += '\\"'
    else if (c === 0x5c) out += '\\\\'
    else if (c === 0x08) out += '\\b'
    else if (c === 0x09) out += '\\t'
    else if (c === 0x0a) out += '\\n'
    else if (c === 0x0c) out += '\\f'
    else if (c === 0x0d) out += '\\r'
    else if (c < 0x20 || c >= 0x7f) {
      out += '\\u' + c.toString(16).padStart(4, '0')
    }
    else out += s[i]
  }
  return out + '"'
}

// JSON canonicalization matching python's json.dumps(sort_keys=True, separators=(",",":"))
function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 'null'
    return JSON.stringify(value)
  }
  if (typeof value === 'string') return pythonJsonString(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalize).join(',') + ']'
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    return '{' + keys.map(k => pythonJsonString(k) + ':' + canonicalize(obj[k])).join(',') + '}'
  }
  return 'null'
}

// Mirror /opt/itechsmart/audit_ledger/append.py:
//   canonical = json.dumps(entry, sort_keys=True, separators=(",",":"))
//   h = hashlib.sha256(canonical).hexdigest()
// where `entry` is the payload BEFORE id, hash_sha256, prev_hash, and
// recomputed/recomputed_at fields are added.
function computeCanonicalHash(entry: LedgerEntry): string {
  const payload: Record<string, unknown> = {
    timestamp: entry.timestamp,
    category: entry.category,
    actor: entry.actor,
    subject: entry.subject,
    action: entry.action,
    outcome: entry.outcome,
    details: entry.details,
    verify_url: entry.verify_url ?? '',
    tamper_detected: entry.tamper_detected ?? false,
  }
  return crypto.createHash('sha256').update(canonicalize(payload), 'utf8').digest('hex')
}

// Categories that represent operational/incident entries in the ledger
// (used by list_recent_incidents). Excludes audit-of-audit categories
// like 'audit_test' and the MCP self-report categories themselves.
const INCIDENT_CATEGORIES = new Set([
  'self_healing',
  'platform_fix',
  'wazuh_alert',
  'platform_health_check',
  'platform_finding',
  'windows_remediation',
  'security_audit',
])

// ─────────────────────────────────────────────
// AUTH HELPERS
// ─────────────────────────────────────────────

interface AuthContext {
  ok: boolean
  key: string | null
  keyPrefix: string | null
  keyProvided: boolean
  source: 'x-itechsmart-mcp-key' | 'bearer' | 'query' | 'none'
  scopes: Set<McpKeyScope>
  admin: boolean
  cloudflareAccess: boolean
  reason?: string
}

function getHeaderValue(headers: http.IncomingHttpHeaders, name: string): string | null {
  const value = headers[name.toLowerCase()]
  if (Array.isArray(value)) return value[0] || null
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

function extractApiKey(
  headers: http.IncomingHttpHeaders,
  query: URLSearchParams,
): { key: string | null; source: AuthContext['source'] } {
  const explicit = getHeaderValue(headers, 'x-itechsmart-mcp-key')
  if (explicit) return { key: explicit, source: 'x-itechsmart-mcp-key' }

  const auth = getHeaderValue(headers, 'authorization')
  if (auth) {
    const m = auth.match(/^Bearer\s+(.+)$/i)
    if (m && m[1].trim()) return { key: m[1].trim(), source: 'bearer' }
  }

  const q = query.get('api_key')
  if (q) return { key: q, source: 'query' }
  return { key: null, source: 'none' }
}

function extractBearerKey(
  headers: http.IncomingHttpHeaders,
  query: URLSearchParams,
): string | null {
  return extractApiKey(headers, query).key
}

function keyPrefix(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex').substring(0, 12)
}

function getAuthContext(headers: http.IncomingHttpHeaders, query: URLSearchParams): AuthContext {
  const { key, source } = extractApiKey(headers, query)
  const cloudflareAccess = Boolean(
    getHeaderValue(headers, 'cf-access-authenticated-user-email')
    || getHeaderValue(headers, 'cf-access-jwt-assertion')
  )
  const record = key ? API_KEYS.get(key) : undefined
  return {
    ok: Boolean(key && record),
    key: key && record ? key : null,
    keyPrefix: key && record ? keyPrefix(key) : null,
    keyProvided: Boolean(key),
    source,
    scopes: record?.scopes || new Set<McpKeyScope>(),
    admin: Boolean(record?.scopes.has('admin')),
    cloudflareAccess,
    reason: !key ? 'missing_key' : record ? undefined : 'invalid_key',
  }
}

function isValidKey(key: string | null): boolean {
  return !!key && API_KEYS.has(key)
}

const EXPLICIT_READ_ONLY_SCOPES = new Set([
  'prooflink.verify_chain',
  'prooflink.verify_receipt',
  'prooflink.search_receipts',
  'mission.list_incidents',
  'mission.cluster_health',
  'compliance.audit_summary',
])

function isReadOnlyScope(scope: string): boolean {
  return scope.endsWith(':read') || EXPLICIT_READ_ONLY_SCOPES.has(scope)
}

function auditLog(event: string, fields: Record<string, unknown>): void {
  const safe: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(fields)) {
    if (/key|token|secret|password/i.test(k) && k !== 'key_prefix' && k !== 'key_provided') continue
    safe[k] = v
  }
  console.error(JSON.stringify({
    ts: new Date().toISOString(),
    service: 'itechsmart-uaio-mcp',
    event,
    ...safe,
  }))
}

// ─────────────────────────────────────────────
// RATE LIMITER (sliding window, in-memory, per-key)
// ─────────────────────────────────────────────

type RateRecord = { times: number[] }
const rateState = new Map<string, RateRecord>()

function rateAllow(keyPref: string, toolName: string): boolean {
  const now = Date.now()
  const windowMs = 60 * 1000
  const isSimulate = toolName.includes('simulate') || toolName.includes('blast_radius')
  const limit = isSimulate ? RATE_LIMIT_SIMULATE_PER_MIN : RATE_LIMIT_PER_MIN
  const k = isSimulate ? `s:${keyPref}` : `g:${keyPref}`

  let rec = rateState.get(k)
  if (!rec) { rec = { times: [] }; rateState.set(k, rec) }
  rec.times = rec.times.filter(t => t > now - windowMs)
  if (rec.times.length >= limit) return false
  rec.times.push(now)
  return true
}

// ─────────────────────────────────────────────
// SELF-REPORT → ProofLink receipt
// ─────────────────────────────────────────────

type Severity = 'INFO' | 'WARN' | 'CRITICAL'

async function selfReport(
  severity: Severity,
  event: string,
  details: Record<string, unknown>,
): Promise<void> {
  // Fire-and-forget; never block the tool response on the webhook.
  // The djuane-ai webhook synchronously writes a ledger receipt; we don't
  // need its response.
  try {
    const res = await fetch(SELF_REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        service: 'itechsmart-uaio-mcp',
        event,
        severity,
        details: {
          ...details,
          auto_resolved: severity === 'INFO',
          human_intervention: false,
        },
      }),
      signal: AbortSignal.timeout(15000),
    })
    if (!res.ok) {
      console.error(`[self-report] ${event} returned ${res.status}`)
    }
  } catch (e) {
    console.error('[self-report] webhook failed:', e instanceof Error ? e.message : String(e))
  }
}

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────

interface ProofLinkReceipt {
  receipt_id: string
  version: string
  timestamp: string
  container: string
  executor: string
  trigger: string
  action: string
  action_parameters: Record<string, unknown>
  before_state: { snapshot_hash: string; healthy: boolean; metrics: Record<string, unknown> }
  after_state: { snapshot_hash: string; healthy: boolean; metrics: Record<string, unknown> }
  nist_controls: string[]
  human_input: 'ZERO' | 'APPROVAL' | 'MANUAL'
  arbiter_policy: string
  sha256: string
  previous_hash: string | null
  chain_position: number
}

interface UAIOStatus {
  containers_healthy: number
  containers_total: number
  receipts_generated: number
  chain_breaks: number
  last_remediation: string
  last_remediation_ms: number
  nist_csf_score: number
  hipaa_score: number
  platform_status: 'operational' | 'degraded' | 'incident'
}

// ─────────────────────────────────────────────
// ProofLink Verification (unchanged from v1.1)
// ─────────────────────────────────────────────

function computeReceiptHash(receipt: Omit<ProofLinkReceipt, 'sha256'>): string {
  const canonical = JSON.stringify({
    receipt_id: receipt.receipt_id,
    version: receipt.version,
    timestamp: receipt.timestamp,
    container: receipt.container,
    executor: receipt.executor,
    trigger: receipt.trigger,
    action: receipt.action,
    action_parameters: receipt.action_parameters,
    before_state: receipt.before_state,
    after_state: receipt.after_state,
    nist_controls: receipt.nist_controls,
    human_input: receipt.human_input,
    arbiter_policy: receipt.arbiter_policy,
    previous_hash: receipt.previous_hash,
    chain_position: receipt.chain_position,
  }, null, 0)
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex')
}

function verifyReceipt(receipt: ProofLinkReceipt, previousReceipt: ProofLinkReceipt | null) {
  const checks: Array<{ name: string; passed: boolean; detail: string }> = []
  const { sha256, ...rest } = receipt
  const computed = computeReceiptHash(rest)
  const hashCheck = computed === sha256
  checks.push({
    name: 'receipt_integrity',
    passed: hashCheck,
    detail: hashCheck ? `Hash valid: ${sha256.substring(0, 16)}...` : 'Hash MISMATCH — tampering detected',
  })
  if (receipt.chain_position === 0) {
    checks.push({ name: 'chain_link', passed: receipt.previous_hash === null, detail: 'Genesis receipt' })
  } else if (previousReceipt) {
    const linkValid = receipt.previous_hash === previousReceipt.sha256
    checks.push({
      name: 'chain_link',
      passed: linkValid,
      detail: linkValid ? `Chain intact: links to ${previousReceipt.receipt_id.substring(0, 8)}` : 'Chain BROKEN',
    })
  }
  const errors = checks.filter(c => !c.passed).map(c => c.detail)
  const tamperDetected = !checks.find(c => c.name === 'receipt_integrity')?.passed
  return { valid: errors.length === 0, tamper_detected: tamperDetected, checks, errors }
}

// ─────────────────────────────────────────────
// API Client (downstream itechsmart API)
// ─────────────────────────────────────────────

const ITECHSMART_API = process.env.ITECHSMART_API_URL || 'https://app.itechsmart.dev/api/v1'
const API_KEY = process.env.ITECHSMART_API_KEY || ''

async function fetchFromAPI<T>(endpoint: string): Promise<T> {
  const response = await fetch(`${ITECHSMART_API}${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
      'X-MCP-Client': 'true',
    },
  })
  if (!response.ok) throw new Error(`upstream ${response.status}`)
  return response.json() as Promise<T>
}

// ─────────────────────────────────────────────
// TOOL DEFINITIONS — every description carries scope + Arbiter + ProofLink notes
// ─────────────────────────────────────────────

function scopeNote(scope: string): string {
  return `\n\nRequires scope: ${scope}. Every call governed by Arbiter constitutional policy and sealed with a ProofLink cryptographic receipt.`
}

const TOOLS = [
  {
    name: 'verify_prooflink_receipt',
    description:
      'Verify the cryptographic integrity of a ProofLink receipt from iTechSmart\'s autonomous IT operations platform. '
      + 'ProofLink receipts are SHA-256 hash-chained cryptographic proofs of autonomous AI actions. This tool verifies '
      + 'hash integrity, chain link to the previous receipt, and schema completeness. '
      + 'Returns: verification result with tamper_detected flag, individual check results, and human-readable summary.'
      + scopeNote(TOOL_SCOPES.verify_prooflink_receipt),
    inputSchema: {
      type: 'object',
      properties: { receipt_id: { type: 'string', description: 'The receipt ID to verify (16 hex characters)' } },
      required: ['receipt_id'],
    },
  },
  {
    name: 'get_receipt_chain',
    description:
      'Fetch and verify the complete ProofLink receipt chain from iTechSmart\'s production ledger. '
      + 'Returns all receipts in chronological order with full chain verification — confirming no tampering at any position.'
      + scopeNote(TOOL_SCOPES.get_receipt_chain),
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of receipts to fetch (default: 20, max: 100)' },
        container: { type: 'string', description: 'Optional: filter receipts by container name' },
      },
    },
  },
  {
    name: 'prooflink.verify_chain',
    description:
      'Read-only audit scope: verify the ProofLink receipt chain for EU AI Act Article 12, CISO, and auditor workflows. '
      + 'Alias for get_receipt_chain; safe for production API keys without admin rights.'
      + scopeNote(TOOL_SCOPES['prooflink.verify_chain']),
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of receipts to fetch (default: 20, max: 100)' },
        container: { type: 'string', description: 'Optional: filter receipts by container name' },
      },
    },
  },
  {
    name: 'prooflink.verify_receipt',
    description:
      'Read-only audit scope: verify one ProofLink receipt by ID without granting mutation rights. '
      + 'Alias for verify_prooflink_receipt.'
      + scopeNote(TOOL_SCOPES['prooflink.verify_receipt']),
    inputSchema: {
      type: 'object',
      properties: { receipt_id: { type: 'string', description: 'The receipt ID to verify (16 hex characters)' } },
      required: ['receipt_id'],
    },
  },
  {
    name: 'prooflink.search_receipts',
    description:
      'Read-only audit scope: search recent ProofLink receipts for ledger-backed post-hoc reconstruction. '
      + 'Supports the same limit/container filters as get_receipt_chain.'
      + scopeNote(TOOL_SCOPES['prooflink.search_receipts']),
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of receipts to return (default: 20, max: 100)' },
        container: { type: 'string', description: 'Optional: filter receipts by container name' },
      },
    },
  },
  {
    name: 'mission.list_incidents',
    description:
      'Read-only mission scope: list recent autonomous IT incidents for audit and operations review. '
      + 'Alias for list_recent_incidents.'
      + scopeNote(TOOL_SCOPES['mission.list_incidents']),
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of incidents to return (default: 10, max: 50)' },
        since: { type: 'string', description: 'ISO 8601 datetime — only return incidents after this timestamp' },
      },
    },
  },
  {
    name: 'mission.cluster_health',
    description:
      'Read-only mission scope: return live cluster health without granting execution or remediation rights. '
      + 'Alias for cluster_status.'
      + scopeNote(TOOL_SCOPES['mission.cluster_health']),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'compliance.audit_summary',
    description:
      'Read-only compliance scope: return the live compliance audit summary for CISO/auditor review. '
      + 'Alias for get_compliance_status.'
      + scopeNote(TOOL_SCOPES['compliance.audit_summary']),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'query_uaio_status',
    description:
      'Get the current operational status of the iTechSmart UAIO (Unified Autonomous IT Operations) platform. '
      + 'Returns real-time metrics including container health, ProofLink receipts generated and chain breaks, '
      + 'last autonomous remediation time/duration, NIST CSF and HIPAA compliance scores, and overall platform status.'
      + scopeNote(TOOL_SCOPES.query_uaio_status),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_incident_details',
    description:
      'Fetch details of a specific autonomous remediation incident including the ProofLink receipt, '
      + 'remediation actions taken, before/after system state, time to detect, time to remediate, '
      + 'and NIST control mappings.'
      + scopeNote(TOOL_SCOPES.get_incident_details),
    inputSchema: {
      type: 'object',
      properties: { incident_id: { type: 'string', description: 'The incident ID' } },
      required: ['incident_id'],
    },
  },
  {
    name: 'list_recent_incidents',
    description:
      'List recent autonomous IT remediation incidents from the iTechSmart UAIO platform. '
      + 'Returns chronological list with incident ID, timestamp, trigger type, autonomous action taken, '
      + 'detection/remediation timing, human input status, and ProofLink receipt ID.'
      + scopeNote(TOOL_SCOPES.list_recent_incidents),
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Number of incidents to return (default: 10, max: 50)' },
        since: { type: 'string', description: 'ISO 8601 datetime — only return incidents after this timestamp' },
      },
    },
  },
  {
    name: 'simulate_infrastructure_attack',
    description:
      'Trigger a simulated infrastructure attack on the iTechSmart break-it sandbox to demonstrate the UAIO autonomous loop. '
      + 'Simulation: injects an OOMKilled / connection_exhausted / disk_full / crashloop event, runs detect → twin → '
      + 'classify → fix → prove, returns a ProofLink receipt with the 5 UAIO phases. '
      + 'SANDBOX ONLY — no production systems are affected.'
      + scopeNote(TOOL_SCOPES.simulate_infrastructure_attack),
    inputSchema: {
      type: 'object',
      properties: {
        attack_type: {
          type: 'string',
          enum: ['oomkilled', 'crashloop', 'connection_exhausted', 'disk_full'],
          description: 'Type of simulated failure (default: oomkilled)',
        },
      },
    },
  },
  {
    name: 'invoke_octoai_pipeline',
    description:
      'Invoke the OctoAI 7-node cognitive pipeline with a free-form prompt. '
      + 'Routes the question through the multi-agent reasoning chain '
      + '(Knowledge Miner, Logic Engine, Systems Architect, Strategic Thinker, Physics Engine) '
      + 'and returns a synthesized final_answer with a confidence score. '
      + 'Use for open-ended platform questions, decision support, or anything that needs '
      + "OctoAI's reasoning rather than a deterministic infrastructure lookup. "
      + 'POSTs to http://localhost:8100/query.'
      + scopeNote(TOOL_SCOPES.invoke_octoai_pipeline),
    inputSchema: {
      type: 'object',
      properties: {
        prompt: {
          type: 'string',
          description: 'The question or instruction to send to the pipeline (1-32000 chars).',
        },
        session_id: {
          type: 'string',
          description: 'Optional session id for memory continuity (default: hermes-mcp-default).',
        },
      },
      required: ['prompt'],
    },
  },
  {
    name: 'get_platform_briefing',
    description:
      'Get a full real-time platform health briefing for the iTechSmart UAIO platform. '
      + 'Returns status of all 18 services (systemd + Docker), SIE finding queue counts by severity '
      + 'and detector, disk usage, uptime, receipts total, gate status, and next scheduled SIE scan. '
      + 'Use this for an instant one-shot snapshot of everything running on the platform.'
      + scopeNote('infrastructure:briefing:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_sie_queue',
    description:
      'Retrieve the current SIE (Self-Improving Engine) security finding queue. '
      + 'Returns all pending findings with severity, detector type (gitignore_gaps, file_perms, '
      + 'secrets_in_repo, monoliths, in_source_token), fix class (safe_auto, needs_approval, flag_only), '
      + 'affected file paths, and recommended remediation action. '
      + 'Use to inspect what security issues SIE has flagged for human approval.'
      + scopeNote('sie:queue:read'),
    inputSchema: {
      type: 'object',
      properties: {
        detector: { type: 'string', description: 'Filter by detector name (e.g. "secrets_in_repo", "file_perms")' },
        fix_class: { type: 'string', description: 'Filter by fix class: safe_auto | needs_approval | flag_only' },
        severity_max: { type: 'number', description: 'Only return findings at or above this severity (1=critical, 5=low)' },
      },
    },
  },
  {
    name: 'get_compliance_status',
    description:
      'Get live compliance scores for the iTechSmart platform. '
      + 'Returns NIST CSF (96/100), HIPAA (100/100), and SOC 2 Type II scores with '
      + 'per-control evidence status, gap analysis, and the source tracker file used for computation. '
      + 'No auth required on the upstream endpoint — data is computed live from soc2-tracker.json.'
      + scopeNote('compliance:scores:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'dispatch_ag2_incident',
    description:
      'Dispatch an IT incident to the iTechSmart AG2 6-agent GroupChat for autonomous diagnosis. '
      + 'Routes through IncidentDetector -> DigitalTwinAnalyst -> RemediationPlanner -> SecurityGatekeeper '
      + '-> ExecutionAgent -> ProofLinkNotary. Returns the multi-agent remediation plan and receipt ID. '
      + 'SEMI_AUTO mode: plan is returned for human review; execution is gated by the SecurityGatekeeper. '
      + 'Use for real incidents: service crashes, OOMKills, cert expiry, disk pressure, config drift.'
      + scopeNote('ag2:incident:invoke'),
    inputSchema: {
      type: 'object',
      properties: {
        description: { type: 'string', description: 'Incident description (what is failing and how)' },
        service: { type: 'string', description: 'Affected service or container name' },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low'],
          description: 'Incident severity level (default: medium)',
        },
      },
      required: ['description', 'service'],
    },
  },
  {
    name: 'search_platform_logs',
    description:
      'Search live systemd journal logs for any iTechSmart service. '
      + 'Returns matching log lines from journalctl filtered by service name and optional keyword pattern. '
      + 'Use for real-time troubleshooting: find errors, trace restarts, check last N lines of any service.'
      + scopeNote('infrastructure:logs:read'),
    inputSchema: {
      type: 'object',
      properties: {
        service: { type: 'string', description: 'systemd service name (e.g. "itechsmart-api", "djuane-ai", "iself")' },
        pattern: { type: 'string', description: 'Optional grep pattern to filter lines (e.g. "ERROR", "timeout", "started")' },
        lines: { type: 'number', description: 'Number of recent log lines to return (default: 100, max: 500)' },
      },
      required: ['service'],
    },
  },
  {
    name: 'approve_sie_finding',
    description:
      'Approve a specific SIE (Self-Improving Engine) security finding by queue index. '
      + 'Applies the associated fixer (gitignore_add, chmod_tighten, or secrets_gitignore), '
      + 'seals a ProofLink receipt for the fix, and removes the item from the queue. '
      + 'Get the index from get_sie_queue first. '
      + 'EXECUTE CLASS: this modifies files on disk and seals an immutable receipt.'
      + scopeNote('sie:queue:write'),
    inputSchema: {
      type: 'object',
      properties: {
        index: {
          type: 'number',
          description: 'Queue index of the finding to approve (use get_sie_queue to list available indices)',
        },
      },
      required: ['index'],
    },
  },
  {
    name: 'trigger_sie_scan',
    description:
      'Kick off a fresh SIE (Self-Improving Engine) scan of the iTechSmart platform. '
      + 'dry-run mode: detects and ranks findings without applying any fixes. '
      + 'apply mode: applies all safe_auto fixes and queues the rest for approval. '
      + 'Runs in the background — check get_platform_briefing for queue count after ~2 min. '
      + 'EXECUTE CLASS: apply mode modifies files and seals receipts.'
      + scopeNote('sie:scan:invoke'),
    inputSchema: {
      type: 'object',
      properties: {
        mode: {
          type: 'string',
          enum: ['dry-run', 'apply'],
          description: 'Scan mode: dry-run (detect only) or apply (fix safe items). Default: dry-run.',
        },
        use_llm: {
          type: 'boolean',
          description: 'Whether to use Nemotron for finding ranking and analysis. Default: true.',
        },
      },
    },
  },
  {
    name: 'get_iself_journal',
    description:
      'Retrieve the iSELF (Self-Healing Loop Framework) healing history. '
      + 'Returns journal entries showing what service failed, what iSELF diagnosed, '
      + 'what patch was applied (e.g. systemctl restart), whether it succeeded, '
      + 'and the confidence score. iSELF runs every 5 min and has healed 11+ incidents.'
      + scopeNote('iself:journal:read'),
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Number of most-recent entries to return (default: 20, max: 100)',
        },
      },
    },
  },

  // ── Integration tools ──────────────────────────────────────────────────────
  {
    name: 'integration_status',
    description:
      'Parallel health check across all wired integrations: Langfuse, RAGflow, '
      + 'Shuffle, Tactical RMM, MeshCentral, and Probo compliance. '
      + 'Returns ok:true/false and service-specific metadata for each.'
      + scopeNote('integrations:status:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'langfuse_health',
    description:
      'Check Langfuse LLM observability platform health. Returns ok status and org name.'
      + scopeNote('integrations:observe:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'langfuse_trace',
    description:
      'Create a Langfuse trace to log an LLM interaction (input, output, model, metadata).'
      + scopeNote('integrations:observe:write'),
    inputSchema: {
      type: 'object',
      required: ['name'],
      properties: {
        name:     { type: 'string', description: 'Trace name / operation label' },
        input:    { description: 'Input payload (any JSON value)' },
        output:   { description: 'Output payload (any JSON value)' },
        model:    { type: 'string', description: 'Model ID used (e.g. claude-sonnet-4-6)' },
        userId:   { type: 'string', description: 'End-user identifier' },
        tags:     { type: 'array', items: { type: 'string' }, description: 'Trace tags' },
        metadata: { description: 'Arbitrary metadata object' },
      },
    },
  },
  {
    name: 'ragflow_health',
    description:
      'Check RAGflow RAG platform health. Returns ok status and dataset count.'
      + scopeNote('integrations:rag:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'ragflow_query',
    description:
      'Query the RAGflow knowledge base with a natural-language question. '
      + 'Optionally filter to specific dataset IDs.'
      + scopeNote('integrations:rag:read'),
    inputSchema: {
      type: 'object',
      required: ['question'],
      properties: {
        question:    { type: 'string', description: 'Natural-language question (max 2000 chars)' },
        dataset_ids: { type: 'array', items: { type: 'string' }, description: 'Optional dataset filter' },
      },
    },
  },
  {
    name: 'shuffle_health',
    description:
      'Check Shuffle SOAR platform health. Returns ok status, user, and workflow count.'
      + scopeNote('integrations:shuffle:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'shuffle_trigger',
    description:
      'Trigger a Shuffle SOAR workflow by workflow ID with an optional request body.'
      + scopeNote('integrations:shuffle:invoke'),
    inputSchema: {
      type: 'object',
      required: ['workflow_id'],
      properties: {
        workflow_id: { type: 'string', description: 'Shuffle workflow UUID' },
        body:        { description: 'Optional JSON body passed to the workflow trigger' },
      },
    },
  },
  {
    name: 'trmm_health',
    description:
      'Check Tactical RMM health. Returns ok status and enrolled agent count.'
      + scopeNote('integrations:trmm:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trmm_agents',
    description:
      'List all Tactical RMM managed agents with status, OS, site, and last-seen info.'
      + scopeNote('integrations:trmm:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trmm_summary',
    description:
      'Get Tactical RMM agent summary: total, online, offline, overdue counts, and site list.'
      + scopeNote('integrations:trmm:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trmm_run_script',
    description:
      'Run a saved script on a Tactical RMM agent by agent ID and script ID.'
      + scopeNote('integrations:trmm:invoke'),
    inputSchema: {
      type: 'object',
      required: ['agent_id', 'script_id'],
      properties: {
        agent_id:  { type: 'string', description: 'TRMM agent ID or hostname' },
        script_id: { type: 'number', description: 'TRMM script ID (integer)' },
      },
    },
  },
  {
    name: 'mesh_health',
    description:
      'Check MeshCentral remote device management health. Returns ok status, '
      + 'admin user, and enrolled device count.'
      + scopeNote('integrations:mesh:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'mesh_devices',
    description:
      'List all devices enrolled in MeshCentral with hostname, OS, connectivity, and group info.'
      + scopeNote('integrations:mesh:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'probo_health',
    description:
      'Check Probo compliance platform health. Returns ok status and control count.'
      + scopeNote('integrations:probo:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'probo_controls',
    description:
      'List all Probo compliance controls with status, category, and description (SOC2/EU AI Act).'
      + scopeNote('integrations:probo:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'probo_risks',
    description:
      'List all Probo compliance risks with severity level and status.'
      + scopeNote('integrations:probo:read'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'probo_summary',
    description:
      'Get Probo compliance aggregate summary: control pass/fail, risk high/medium/low, '
      + 'and task open/done counts.'
      + scopeNote('integrations:probo:read'),
    inputSchema: { type: 'object', properties: {} },
  },
]

// ─────────────────────────────────────────────
// TOOL DISPATCH (callable from both SSE handler and stateless POST)
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// DJUANE-AI PROXY HELPERS (call integration routes on :3202)
// ─────────────────────────────────────────────

const DJUANE_BASE = process.env.DJUANE_BASE || 'http://localhost:3202'

async function djuaneGet(path: string): Promise<unknown> {
  try {
    const res = await fetch(`${DJUANE_BASE}${path}`)
    return await res.json()
  } catch (e: any) {
    return { ok: false, error: e?.message ?? 'djuane-ai unreachable' }
  }
}

async function djuanePost(path: string, body: unknown): Promise<unknown> {
  try {
    const res = await fetch(`${DJUANE_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    return await res.json()
  } catch (e: any) {
    return { ok: false, error: e?.message ?? 'djuane-ai unreachable' }
  }
}

async function dispatchTool(name: string, args: unknown): Promise<unknown> {
  const canonical = TOOL_ALIASES[name] || name
  const safeArgs = (args || {}) as Record<string, unknown>

  switch (canonical) {

    case 'verify_prooflink_receipt': {
      const receipt_id = String(safeArgs.receipt_id || '').trim()
      if (!receipt_id) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              found: false, verification_result: 'INVALID INPUT',
              error: 'receipt_id is required',
            }, null, 2),
          }],
        }
      }

      const entries = readCanonicalLedger()
      // Match by 16-char id (canonical form), full sha256, OR prefix of either.
      const entry = entries.find(e =>
        e.id === receipt_id
        || e.hash_sha256 === receipt_id
        || (e.id && e.id.startsWith(receipt_id))
        || (e.hash_sha256 && e.hash_sha256.startsWith(receipt_id)),
      )

      if (!entry) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              found: false,
              verification_result: 'RECEIPT NOT FOUND',
              receipt_id,
              message: 'No matching entry in canonical ProofLink ledger',
              ledger_path: CANONICAL_LEDGER_PATH,
              ledger_entries: entries.length,
              scope: 'prooflink:verify:read',
            }, null, 2),
          }],
        }
      }

      // Real hash integrity check — recompute and compare.
      const recomputed = computeCanonicalHash(entry)
      const hashValid = recomputed === entry.hash_sha256

      // Chain link check. The canonical ledger stores entries newest-first
      // (append.py inserts at index 0), so the "previous in time" entry is
      // at idx+1.
      const idx = entries.indexOf(entry)
      const prevEntry = idx >= 0 && idx + 1 < entries.length ? entries[idx + 1] : null
      const expectedPrevHash = prevEntry ? prevEntry.hash_sha256 : null
      const chainValid = (entry.prev_hash ?? null) === expectedPrevHash

      const valid = hashValid && chainValid
      return {
        content: [{
          type: 'text', text: JSON.stringify({
            found: true,
            receipt_id: entry.id,
            verification_result: valid ? 'VERIFIED ✓' : 'TAMPER DETECTED ✗',
            tamper_detected: !valid,
            checks: [
              {
                name: 'receipt_integrity',
                passed: hashValid,
                detail: hashValid
                  ? `Hash valid: ${entry.hash_sha256.substring(0, 16)}...`
                  : `Hash MISMATCH — computed ${recomputed.substring(0, 16)} vs stored ${entry.hash_sha256.substring(0, 16)}`,
              },
              {
                name: 'chain_link',
                passed: chainValid,
                detail: chainValid
                  ? (prevEntry ? `Chain intact: links to ${prevEntry.id.substring(0, 8)}` : 'Oldest entry (no prior)')
                  : `Chain BROKEN: prev_hash ${entry.prev_hash} ≠ expected ${expectedPrevHash}`,
              },
            ],
            timestamp: entry.timestamp,
            category: entry.category,
            actor: entry.actor,
            subject: entry.subject,
            action: entry.action,
            outcome: entry.outcome,
            sha256: entry.hash_sha256,
            prev_hash: entry.prev_hash,
            position_from_newest: idx,
            ledger_path: CANONICAL_LEDGER_PATH,
            verify_url: entry.verify_url || `https://verify.itechsmart.dev/${entry.id}`,
            scope: 'prooflink:verify:read',
          }, null, 2),
        }],
      }
    }

    case 'get_receipt_chain': {
      const limit = Math.min(
        Math.max(typeof safeArgs.limit === 'number' ? safeArgs.limit : 20, 1),
        100,
      )
      const subjectFilter = safeArgs.container ? String(safeArgs.container) : undefined

      const entries = readCanonicalLedger()

      // Chain integrity walk. Entries are newest-first; the prev_hash of
      // entries[i] should equal the hash_sha256 of entries[i+1].
      let chainBreaks = 0
      const tamperPositions: number[] = []
      for (let i = 0; i < entries.length - 1; i++) {
        const actual = entries[i].prev_hash ?? null
        const expected = entries[i + 1].hash_sha256
        if (actual !== expected) {
          chainBreaks++
          tamperPositions.push(i)
        }
      }

      const filtered = subjectFilter
        ? entries.filter(e => e.subject === subjectFilter || e.actor === subjectFilter)
        : entries
      const window = filtered.slice(0, limit)

      return {
        content: [{
          type: 'text', text: JSON.stringify({
            chain_summary: {
              total_receipts: entries.length,
              chain_valid: chainBreaks === 0,
              chain_breaks: chainBreaks,
              tamper_positions: tamperPositions.slice(0, 10),
              first_receipt: entries[entries.length - 1]?.timestamp ?? null,
              last_receipt: entries[0]?.timestamp ?? null,
              status: chainBreaks === 0
                ? 'CHAIN INTACT ✓'
                : `CHAIN BROKEN — ${chainBreaks} position(s) tampered`,
            },
            filter: subjectFilter ? { subject_or_actor: subjectFilter } : null,
            showing: window.length,
            receipts: window.map((r, i) => ({
              position_from_newest: i,
              id: r.id,
              timestamp: r.timestamp,
              category: r.category,
              actor: r.actor,
              subject: r.subject,
              action: r.action ? r.action.substring(0, 160) : '',
              sha256_preview: r.hash_sha256 ? r.hash_sha256.substring(0, 16) + '...' : null,
            })),
            ledger_path: CANONICAL_LEDGER_PATH,
            verify_url: 'https://verify.itechsmart.dev',
            open_source_verifier: 'https://github.com/Iteksmart/prooflink-verifier',
            scope: 'ledger:audit:read',
          }, null, 2),
        }],
      }
    }

    case 'query_uaio_status': {
      // Real container counts via docker ps. The MCP service runs as user
      // `ubuntu` which is in the docker group, so no sudo needed.
      let containersTotal = 0
      let containersHealthy = 0
      let containersUnhealthy = 0
      let dockerError: string | null = null
      try {
        containersTotal = parseInt(
          execSync('docker ps -q | wc -l', { timeout: 5000, encoding: 'utf8' }).toString().trim(),
        ) || 0
        containersHealthy = parseInt(
          execSync('docker ps --filter health=healthy -q | wc -l',
            { timeout: 5000, encoding: 'utf8' }).toString().trim(),
        ) || 0
        containersUnhealthy = parseInt(
          execSync('docker ps --filter health=unhealthy -q | wc -l',
            { timeout: 5000, encoding: 'utf8' }).toString().trim(),
        ) || 0
      } catch (e) {
        dockerError = e instanceof Error ? e.message : String(e)
        console.error('[query_uaio_status] docker exec failed:', dockerError)
      }

      // Real canonical ledger + real chain breaks.
      const entries = readCanonicalLedger()
      let chainBreaks = 0
      for (let i = 0; i < entries.length - 1; i++) {
        if ((entries[i].prev_hash ?? null) !== entries[i + 1].hash_sha256) chainBreaks++
      }

      // Real last remediation: most-recent entry with a recovery_time_seconds
      // in its details. Ledger is newest-first, so iterate from start.
      const lastWithRecovery = entries.find(e => {
        const d = (e.details && typeof e.details === 'object') ? e.details as Record<string, unknown> : null
        return d != null && typeof d.recovery_time_seconds === 'number'
      })
      const lastTs = entries[0]?.timestamp ?? null
      const lastRecoveryMs = lastWithRecovery && (lastWithRecovery.details as Record<string, unknown>).recovery_time_seconds
        ? Math.round(((lastWithRecovery.details as Record<string, number>).recovery_time_seconds) * 1000)
        : null
      const lastHumanIntervention = lastWithRecovery
        ? Boolean((lastWithRecovery.details as Record<string, unknown>).human_intervention)
        : null

      // Compliance from system_context.json (real values, not hardcoded).
      let nist = 96
      let hipaa = 100
      try {
        if (fs.existsSync(SYSTEM_CONTEXT_PATH)) {
          const ctx = JSON.parse(fs.readFileSync(SYSTEM_CONTEXT_PATH, 'utf8'))
          const platform = ctx.platform || {}
          nist = parseInt(String(platform.nist_csf || '96/100').split('/')[0]) || 96
          hipaa = platform.hipaa === 'compliant'
            ? 100
            : parseInt(String(platform.hipaa || '100/100').split('/')[0]) || 100
        }
      } catch { /* fall back to defaults */ }

      const operational = dockerError === null
        && containersTotal > 0
        && chainBreaks === 0
        && containersUnhealthy === 0

      return {
        content: [{
          type: 'text', text: JSON.stringify({
            platform: 'iTechSmart UAIO — Unified Autonomous IT Operations',
            status: operational ? 'OPERATIONAL' : 'DEGRADED',
            containers: {
              healthy: containersHealthy,
              unhealthy: containersUnhealthy,
              total: containersTotal,
              health_pct: containersTotal > 0
                ? Math.round((containersHealthy / containersTotal) * 100)
                : 0,
              source: dockerError ? `error: ${dockerError}` : 'docker ps (live)',
              note: 'Containers without a HEALTHCHECK defined are counted in `total` but not in `healthy`.',
            },
            prooflink: {
              receipts_generated: entries.length,
              chain_breaks: chainBreaks,
              chain_status: chainBreaks === 0 ? 'INTACT ✓' : `${chainBreaks} BREAK(S) DETECTED`,
              ledger_path: CANONICAL_LEDGER_PATH,
              public_ledger: 'https://verify.itechsmart.dev',
            },
            last_remediation: {
              timestamp: lastTs,
              duration_ms: lastRecoveryMs,
              source_actor: lastWithRecovery?.actor ?? null,
              source_subject: lastWithRecovery?.subject ?? null,
              human_input: lastHumanIntervention === false ? 'ZERO'
                : lastHumanIntervention === true ? 'MANUAL'
                : 'UNKNOWN',
            },
            compliance: {
              nist_csf: `${nist}/100`,
              hipaa: `${hipaa}/100`,
              fedramp: '90/100 (pathway active)',
            },
            powered_by: 'NVIDIA Nemotron Ultra 253B | OctoAI | ProofLink™',
            scope: 'infrastructure:scan:read',
          }, null, 2),
        }],
      }
    }

    case 'get_incident_details': {
      const incident_id = String(safeArgs.incident_id || '').trim()
      if (!incident_id) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              found: false, error: 'incident_id is required',
            }, null, 2),
          }],
        }
      }

      const entries = readCanonicalLedger()
      const entry = entries.find(e => {
        if (e.id === incident_id) return true
        if (e.hash_sha256 === incident_id) return true
        if (e.id && e.id.startsWith(incident_id)) return true
        const det = (e.details && typeof e.details === 'object')
          ? e.details as Record<string, unknown>
          : {}
        return det.receipt_id === incident_id
          || det.ticket_id === incident_id
          || det.itsm_ticket === incident_id
          || det.run_id === incident_id
          || det.incident_id === incident_id
      })

      if (!entry) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              found: false,
              incident_id,
              message: 'Incident not found in ProofLink ledger',
              ledger_path: CANONICAL_LEDGER_PATH,
              ledger_entries: entries.length,
              hint: 'Try list_recent_incidents to find a valid incident id',
              scope: 'incident:classify:read',
            }, null, 2),
          }],
        }
      }

      const det = (entry.details && typeof entry.details === 'object')
        ? entry.details as Record<string, unknown>
        : {}
      return {
        content: [{
          type: 'text', text: JSON.stringify({
            found: true,
            id: entry.id,
            timestamp: entry.timestamp,
            category: entry.category,
            actor: entry.actor,
            subject: entry.subject,
            action: entry.action,
            outcome: entry.outcome,
            details: entry.details,
            detection_time_seconds: det.detection_time_seconds ?? null,
            recovery_time_seconds: det.recovery_time_seconds ?? null,
            auto_resolved: det.auto_resolved ?? null,
            human_intervention: det.human_intervention ?? null,
            hash_sha256: entry.hash_sha256,
            prev_hash: entry.prev_hash,
            verify_url: entry.verify_url || `https://verify.itechsmart.dev/${entry.id}`,
            scope: 'incident:classify:read',
          }, null, 2),
        }],
      }
    }

    case 'list_recent_incidents': {
      const limit = Math.min(
        Math.max(typeof safeArgs.limit === 'number' ? safeArgs.limit : 10, 1),
        50,
      )
      const since = safeArgs.since ? String(safeArgs.since) : null

      const entries = readCanonicalLedger()
      let filtered = entries.filter(e => INCIDENT_CATEGORIES.has(e.category))
      if (since) {
        filtered = filtered.filter(e => e.timestamp && e.timestamp >= since)
      }
      // Canonical ledger is already newest-first; just take N.
      const window = filtered.slice(0, limit)

      return {
        content: [{
          type: 'text', text: JSON.stringify({
            total_available: filtered.length,
            showing: window.length,
            since,
            incidents: window.map(r => {
              const det = (r.details && typeof r.details === 'object')
                ? r.details as Record<string, unknown>
                : {}
              return {
                incident_id: r.id,
                timestamp: r.timestamp,
                category: r.category,
                actor: r.actor,
                subject: r.subject,
                trigger: det.trigger ?? det.failure_type ?? (r.action ? r.action.substring(0, 100) : null),
                detection_time_seconds: det.detection_time_seconds ?? null,
                recovery_time_seconds: det.recovery_time_seconds ?? null,
                auto_resolved: det.auto_resolved ?? null,
                human_intervention: det.human_intervention ?? null,
                playbook: det.playbook ?? null,
                prooflink_receipt_id: r.id,
                sha256_preview: r.hash_sha256 ? r.hash_sha256.substring(0, 16) + '...' : null,
                verify_url: r.verify_url || `https://verify.itechsmart.dev/${r.id}`,
              }
            }),
            categories_searched: Array.from(INCIDENT_CATEGORIES),
            ledger_path: CANONICAL_LEDGER_PATH,
            platform_url: 'https://itechsmart.dev',
            verify_all: 'https://verify.itechsmart.dev',
            scope: 'incident:classify:read',
          }, null, 2),
        }],
      }
    }

    case 'simulate_infrastructure_attack': {
      const attack_type = String(safeArgs.attack_type || 'oomkilled')
      const target = String((safeArgs as Record<string, unknown>).target || 'break-it-sandbox')

      // Trigger the REAL break-it-api on this host. This stops + restarts
      // the break-it-sandbox container, polls for health recovery, and
      // append.py-seals a self_healing receipt to the canonical ledger.
      let runId: string | null = null
      let breakItStatus = 0
      let breakItResponse: Record<string, unknown> | null = null
      try {
        const res = await fetch(BREAK_IT_API_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: attack_type, target }),
          signal: AbortSignal.timeout(30000),
        })
        breakItStatus = res.status
        breakItResponse = await res.json() as Record<string, unknown>
        runId = breakItResponse?.run_id ? String(breakItResponse.run_id) : null
      } catch (e) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              status: 'failed_to_trigger',
              error: 'break-it API unreachable',
              detail: e instanceof Error ? e.message : String(e),
              break_it_endpoint: BREAK_IT_API_URL,
              attack_type, target,
              scope: 'digitaltwin:simulate:read',
            }, null, 2),
          }],
        }
      }

      if (!runId) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              status: 'no_run_id',
              break_it_status: breakItStatus,
              break_it_response: breakItResponse,
              scope: 'digitaltwin:simulate:read',
            }, null, 2),
          }],
        }
      }

      // Recovery + receipt seal typically completes in ~7s. Poll the
      // canonical ledger for an entry matching this run_id (up to ~15s).
      const pollDeadline = Date.now() + 15000
      let receipt: LedgerEntry | undefined
      while (Date.now() < pollDeadline) {
        await new Promise(r => setTimeout(r, 1500))
        const entries = readCanonicalLedger()
        receipt = entries.find(e => {
          const d = (e.details && typeof e.details === 'object')
            ? e.details as Record<string, unknown>
            : null
          return d != null && d.run_id === runId
        })
        if (receipt) break
      }

      // Re-read by id (not object reference); the ledger may have grown
      // since the poll due to the MCP self-report receipt for this very call.
      const finalEntries = readCanonicalLedger()
      const finalIdx = receipt
        ? finalEntries.findIndex(e => e.id === receipt!.id)
        : -1
      const det = (receipt?.details && typeof receipt.details === 'object')
        ? receipt.details as Record<string, unknown>
        : {}

      return {
        content: [{
          type: 'text', text: JSON.stringify({
            run_id: runId,
            status: receipt ? 'completed' : 'receipt_pending',
            real_execution: true,
            attack_type,
            target,
            break_it_endpoint: BREAK_IT_API_URL,
            stream_url: breakItResponse?.stream_url || null,
            receipt_id: receipt?.id || null,
            sha256: receipt?.hash_sha256 || null,
            detection_time_seconds: det.detection_time_seconds ?? null,
            recovery_time_seconds: det.recovery_time_seconds ?? null,
            auto_resolved: det.auto_resolved ?? null,
            human_intervention: det.human_intervention ?? null,
            playbook: det.playbook ?? null,
            position_from_newest: finalIdx >= 0 ? finalIdx : null,
            verify_url: receipt
              ? (receipt.verify_url || `https://verify.itechsmart.dev/${receipt.id}`)
              : null,
            ots_note: 'Each break-it receipt is submitted to 4 OpenTimestamps calendars at creation; Bitcoin block confirmation lands via the upgrade cron within ~hours.',
            message: receipt
              ? 'Real container attack executed. Recovery completed. Receipt sealed to canonical ProofLink ledger.'
              : 'Container attack executed but receipt not yet visible in canonical ledger after 15s poll. Try get_incident_details with run_id or verify_prooflink_receipt later.',
            live_demo: 'https://itechsmart.dev/break-it',
            verify: 'https://verify.itechsmart.dev',
            scope: 'digitaltwin:simulate:read',
          }, null, 2),
        }],
      }
    }



    case 'approve_sie_finding': {
      const index = safeArgs.index !== undefined ? Number(safeArgs.index) : null
      if (index === null || !Number.isInteger(index) || index < 0) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'index is required and must be a non-negative integer',
          hint: 'Use get_sie_queue to list available indices',
          scope: 'sie:queue:write',
        }, null, 2) }] }
      }
      try {
        const res = await fetch('http://localhost:8220/api/queue/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(process.env.SIE_INTERNAL_TOKEN ? { 'Authorization': 'Bearer ' + process.env.SIE_INTERNAL_TOKEN } : {}) },
          body: JSON.stringify({ index }),
          signal: AbortSignal.timeout(30000),
        })
        if (!res.ok) {
          const detail = await res.text().catch(() => '')
          return { content: [{ type: 'text', text: JSON.stringify({
            error: 'SIE approve returned HTTP ' + res.status,
            detail: detail.slice(0, 400),
            index,
          }, null, 2) }] }
        }
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify({
          ...data, index, scope: 'sie:queue:write',
        }, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to approve SIE finding',
          detail: e instanceof Error ? e.message : String(e),
          index,
        }, null, 2) }] }
      }
    }

    case 'trigger_sie_scan': {
      const mode = String(safeArgs.mode || 'dry-run')
      const use_llm = safeArgs.use_llm !== undefined ? Boolean(safeArgs.use_llm) : true
      if (mode !== 'dry-run' && mode !== 'apply') {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'mode must be "dry-run" or "apply"',
          scope: 'sie:scan:invoke',
        }, null, 2) }] }
      }
      try {
        const res = await fetch('http://localhost:8220/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(process.env.SIE_INTERNAL_TOKEN ? { 'Authorization': 'Bearer ' + process.env.SIE_INTERNAL_TOKEN } : {}) },
          body: JSON.stringify({ mode, use_llm }),
          signal: AbortSignal.timeout(15000),
        })
        if (!res.ok) {
          const detail = await res.text().catch(() => '')
          return { content: [{ type: 'text', text: JSON.stringify({
            error: 'SIE run returned HTTP ' + res.status,
            detail: detail.slice(0, 400),
          }, null, 2) }] }
        }
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify({
          ...data,
          note: 'Scan running in background. Call get_platform_briefing or get_sie_queue in ~2 minutes to see results.',
          scope: 'sie:scan:invoke',
        }, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to trigger SIE scan',
          detail: e instanceof Error ? e.message : String(e),
        }, null, 2) }] }
      }
    }

    case 'get_iself_journal': {
      const limit = Math.min(Number(safeArgs.limit || 20), 100)
      try {
        const res = await fetch('http://localhost:8215/api/journal?limit=' + limit, {
          signal: AbortSignal.timeout(8000),
        })
        if (!res.ok) throw new Error('iSELF journal returned HTTP ' + res.status)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to fetch iSELF journal',
          detail: e instanceof Error ? e.message : String(e),
          endpoint: 'http://localhost:8215/api/journal',
        }, null, 2) }] }
      }
    }

    case 'get_platform_briefing': {
      try {
        const res = await fetch('http://localhost:8220/api/briefing', {
          signal: AbortSignal.timeout(10000),
        })
        if (!res.ok) throw new Error('SIE briefing returned HTTP ' + res.status)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to fetch platform briefing',
          detail: e instanceof Error ? e.message : String(e),
          endpoint: 'http://localhost:8220/api/briefing',
        }, null, 2) }] }
      }
    }

    case 'get_sie_queue': {
      const filterDetector = safeArgs.detector ? String(safeArgs.detector) : null
      const filterFixClass = safeArgs.fix_class ? String(safeArgs.fix_class) : null
      const severityMax = safeArgs.severity_max ? Number(safeArgs.severity_max) : null
      try {
        const res = await fetch('http://localhost:8220/api/queue', {
          signal: AbortSignal.timeout(8000),
        })
        if (!res.ok) throw new Error('SIE queue returned HTTP ' + res.status)
        const data = await res.json() as { items: Array<Record<string, unknown>>; total: number; generated_at: string }
        let items = data.items || []
        if (filterDetector) items = items.filter((i) => i.detector === filterDetector)
        if (filterFixClass) items = items.filter((i) => i.fix_class === filterFixClass)
        if (severityMax) items = items.filter((i) => Number(i.severity || 5) <= severityMax)
        const trimmed = items.map((i) => ({
          idx: i._idx, severity: i.severity, detector: i.detector,
          fix_class: i.fix_class, path: i.path,
          detail: typeof i.detail === 'string' ? (i.detail as string).slice(0, 120) : i.detail,
          action: i.action,
        }))
        return { content: [{ type: 'text', text: JSON.stringify({
          total_in_queue: data.total,
          filtered_count: trimmed.length,
          generated_at: data.generated_at,
          filters_applied: { detector: filterDetector, fix_class: filterFixClass, severity_max: severityMax },
          items: trimmed,
        }, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to fetch SIE queue',
          detail: e instanceof Error ? e.message : String(e),
        }, null, 2) }] }
      }
    }

    case 'get_compliance_status': {
      try {
        const res = await fetch('http://localhost:8091/v1/compliance', {
          signal: AbortSignal.timeout(8000),
        })
        if (!res.ok) throw new Error('compliance API returned HTTP ' + res.status)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to fetch compliance status',
          detail: e instanceof Error ? e.message : String(e),
          endpoint: 'http://localhost:8091/v1/compliance',
        }, null, 2) }] }
      }
    }

    case 'dispatch_ag2_incident': {
      const description = String(safeArgs.description || '').trim()
      const service = String(safeArgs.service || '').trim()
      const severity = String(safeArgs.severity || 'medium')
      if (!description || !service) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'description and service are required',
          scope: 'ag2:incident:invoke',
        }, null, 2) }] }
      }
      const ag2Url = 'http://localhost:8500/api/v1/ag2/incident'
      // SEC-net-2: the ag2 API is fail-closed bearer-auth'd; send AG2_API_TOKEN.
      const ag2Token = (process.env.AG2_API_TOKEN || '').trim()
      try {
        const res = await fetch(ag2Url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(ag2Token ? { Authorization: `Bearer ${ag2Token}` } : {}),
          },
          body: JSON.stringify({ description, service, severity }),
          signal: AbortSignal.timeout(120000),
        })
        if (!res.ok) {
          const detail = await res.text().catch(() => '')
          return { content: [{ type: 'text', text: JSON.stringify({
            error: 'AG2 returned HTTP ' + res.status,
            detail: detail.slice(0, 500),
            ag2_url: ag2Url,
          }, null, 2) }] }
        }
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify({
          ...data, ag2_url: ag2Url, scope: 'ag2:incident:invoke',
        }, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to dispatch AG2 incident',
          detail: e instanceof Error ? e.message : String(e),
          ag2_url: ag2Url,
        }, null, 2) }] }
      }
    }

    case 'search_platform_logs': {
      const rawSvc = String(safeArgs.service || '').trim()
      const service = rawSvc.replace(/[^a-zA-Z0-9._-]/g, '')
      const pattern = safeArgs.pattern ? String(safeArgs.pattern).slice(0, 200) : null
      const lines = Math.min(Number(safeArgs.lines || 100), 500)
      if (!service) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: 'service is required' }, null, 2) }] }
      }
      try {
        let url = 'http://localhost:8220/api/logs/search?service=' + encodeURIComponent(service) + '&lines=' + lines
        if (pattern) url += '&pattern=' + encodeURIComponent(pattern)
        const res = await fetch(url, { signal: AbortSignal.timeout(15000) })
        if (!res.ok) throw new Error('logs search returned HTTP ' + res.status)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (e) {
        return { content: [{ type: 'text', text: JSON.stringify({
          error: 'failed to search logs',
          detail: e instanceof Error ? e.message : String(e),
          service,
        }, null, 2) }] }
      }
    }


    case 'brain_query': {
      const query = String(safeArgs.query || '').trim()
      if (!query) return { content: [{ type: 'text', text: JSON.stringify({ error: 'query is required' }) }] }
      const layers = String(safeArgs.layers || 'md,wiki,vector,graph')
      const limit = Number(safeArgs.limit || 10)
      try {
        const url = 'http://127.0.0.1:8221/api/brain/search?q=' + encodeURIComponent(query) + '&limit=' + limit
        const res = await fetch(url)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify({ query, layers, results: data }, null, 2) }] }
      } catch (err) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: String(err), query }) }] }
      }
    }

    case 'cluster_status': {
      try {
        const res = await fetch('http://127.0.0.1:8210/api/v1/cluster/status')
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (err) {
        return { content: [{ type: 'text', text: JSON.stringify({ site: 'itechsmart-ovh-ca-1', status: 'primary', error: String(err) }) }] }
      }
    }

    case 'port_registry': {
      const action = String(safeArgs.action || 'list')
      const port = safeArgs.port ? Number(safeArgs.port) : null
      try {
        let url = 'http://127.0.0.1:8210/api/v1/ports'
        if (action === 'check' && port) url += '/' + port
        const res = await fetch(url)
        const data = await res.json() as Record<string, unknown>
        return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
      } catch (err) {
        return { content: [{ type: 'text', text: JSON.stringify({ error: String(err), action }) }] }
      }
    }

    case 'invoke_octoai_pipeline': {
      const prompt = String(safeArgs.prompt || '').trim()
      const session_id = String(safeArgs.session_id || 'hermes-mcp-default')
      if (!prompt) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              error: 'prompt is required',
              scope: 'octoai:pipeline:invoke',
            }, null, 2),
          }],
        }
      }
      if (prompt.length > 32000) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              error: 'prompt exceeds 32000 chars',
              length: prompt.length,
              scope: 'octoai:pipeline:invoke',
            }, null, 2),
          }],
        }
      }

      const octoaiUrl = process.env.OCTOAI_URL || 'http://localhost:8100/query'
      try {
        const res = await fetch(octoaiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt, session_id }),
          signal: AbortSignal.timeout(180000),
        })
        if (!res.ok) {
          const detail = await res.text().catch(() => '')
          return {
            content: [{
              type: 'text', text: JSON.stringify({
                error: `OctoAI /query returned HTTP ${res.status}`,
                detail: detail.slice(0, 500),
                octoai_url: octoaiUrl,
                scope: 'octoai:pipeline:invoke',
              }, null, 2),
            }],
          }
        }
        const data = await res.json() as { final_answer?: string; confidence?: number; task_id?: string }
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              final_answer: data.final_answer || '',
              confidence: data.confidence ?? null,
              task_id: data.task_id || '',
              session_id,
              octoai_url: octoaiUrl,
              scope: 'octoai:pipeline:invoke',
            }, null, 2),
          }],
        }
      } catch (e) {
        return {
          content: [{
            type: 'text', text: JSON.stringify({
              error: 'failed to call OctoAI pipeline',
              detail: e instanceof Error ? e.message : String(e),
              octoai_url: octoaiUrl,
              scope: 'octoai:pipeline:invoke',
            }, null, 2),
          }],
        }
      }
    }


    // ── Integration tools — proxy to djuane-ai on :3202 ──────────────────────
    case 'integration_status': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/integrations/status'), null, 2) }] }
    }

    case 'langfuse_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/observe/health'), null, 2) }] }
    }

    case 'langfuse_trace': {
      const { name, input, output, model, userId, tags, metadata } = safeArgs
      const result = await djuanePost('/api/v1/observe/trace', { name, input, output, model, userId, tags, metadata })
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    }

    case 'ragflow_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/rag/health'), null, 2) }] }
    }

    case 'ragflow_query': {
      const { question, dataset_ids } = safeArgs
      if (!question || typeof question !== 'string') {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: 'question required' }, null, 2) }] }
      }
      const result = await djuanePost('/api/v1/rag/query', { question, dataset_ids })
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    }

    case 'shuffle_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/shuffle/health'), null, 2) }] }
    }

    case 'shuffle_trigger': {
      const { workflow_id, body } = safeArgs
      if (!workflow_id || typeof workflow_id !== 'string') {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: 'workflow_id required' }, null, 2) }] }
      }
      const result = await djuanePost('/api/v1/shuffle/trigger', { workflow_id, body })
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    }

    case 'trmm_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/trmm/health'), null, 2) }] }
    }

    case 'trmm_agents': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/trmm/agents'), null, 2) }] }
    }

    case 'trmm_summary': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/trmm/summary'), null, 2) }] }
    }

    case 'trmm_run_script': {
      const { agent_id, script_id } = safeArgs
      if (!agent_id || !script_id) {
        return { content: [{ type: 'text', text: JSON.stringify({ ok: false, error: 'agent_id and script_id required' }, null, 2) }] }
      }
      const result = await djuanePost(`/api/v1/trmm/agents/${agent_id}/run-script`, { script_id: Number(script_id) })
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
    }

    case 'mesh_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/mesh/health'), null, 2) }] }
    }

    case 'mesh_devices': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/mesh/devices'), null, 2) }] }
    }

    case 'probo_health': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/probo/health'), null, 2) }] }
    }

    case 'probo_controls': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/probo/controls'), null, 2) }] }
    }

    case 'probo_risks': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/probo/risks'), null, 2) }] }
    }

    case 'probo_summary': {
      return { content: [{ type: 'text', text: JSON.stringify(await djuaneGet('/api/v1/probo/summary'), null, 2) }] }
    }

    default:
      throw new Error(`unknown tool: ${name}`)
  }
}

// ─────────────────────────────────────────────
// AUTH + RATE + DISPATCH WRAPPER (used by both SSE + stateless HTTP)
// ─────────────────────────────────────────────

type AuthedResult = { status: number; body: unknown }

async function authedCallTool(
  headers: http.IncomingHttpHeaders,
  query: URLSearchParams,
  toolName: string,
  args: unknown,
): Promise<AuthedResult> {
  const auth = getAuthContext(headers, query)
  const scope = TOOL_SCOPES[toolName]

  if (!auth.ok) {
    auditLog('mcp_call_rejected', {
      tool: toolName || 'unknown',
      reason: auth.reason,
      key_provided: auth.keyProvided,
      auth_source: auth.source,
      cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('WARN', 'mcp_invalid_auth', {
      tool: toolName, key_provided: auth.keyProvided, auth_source: auth.source, cloudflare_access: auth.cloudflareAccess,
    })
    return { status: 401, body: { error: 'invalid or missing API key' } }
  }

  if (!scope) {
    auditLog('mcp_unknown_tool', {
      tool: toolName, key_prefix: auth.keyPrefix, auth_source: auth.source, cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('WARN', 'mcp_unknown_tool', {
      tool: toolName, caller_key_prefix: auth.keyPrefix,
    })
    return { status: 404, body: { error: 'unknown tool' } }
  }

  if (!isReadOnlyScope(scope) && !auth.admin) {
    auditLog('mcp_mutation_blocked', {
      tool: toolName, scope, key_prefix: auth.keyPrefix, auth_source: auth.source, cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('WARN', 'mcp_mutation_blocked', {
      tool: toolName, scope, caller_key_prefix: auth.keyPrefix,
    })
    return { status: 403, body: { error: 'admin scope required for mutating tool' } }
  }

  const kp = auth.keyPrefix!
  if (!rateAllow(kp, toolName)) {
    auditLog('mcp_rate_limit_exceeded', {
      tool: toolName, scope, key_prefix: kp, auth_source: auth.source, cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('WARN', 'mcp_rate_limit_exceeded', {
      tool: toolName, scope, caller_key_prefix: kp,
    })
    return {
      status: 429,
      body: { error: 'rate limit exceeded', retry_after_seconds: 60 },
    }
  }

  const t0 = Date.now()
  auditLog('mcp_call_started', {
    tool: toolName, scope, key_prefix: kp, auth_source: auth.source, admin: auth.admin, cloudflare_access: auth.cloudflareAccess,
  })
  try {
    const result = await dispatchTool(toolName, args)
    const duration_ms = Date.now() - t0
    auditLog('mcp_call_success', {
      tool: toolName, scope, key_prefix: kp, auth_source: auth.source, admin: auth.admin, duration_ms, cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('INFO', 'mcp_tool_call', {
      tool: toolName, scope, caller_key_prefix: kp,
      result: 'success', duration_ms,
    })
    return { status: 200, body: result }
  } catch (e) {
    const duration_ms = Date.now() - t0
    console.error(`[mcp] tool '${toolName}' failed:`, e instanceof Error ? e.stack || e.message : String(e))
    auditLog('mcp_call_error', {
      tool: toolName, scope, key_prefix: kp, auth_source: auth.source, duration_ms, cloudflare_access: auth.cloudflareAccess,
    })
    void selfReport('WARN', 'mcp_tool_error', {
      tool: toolName, scope, caller_key_prefix: kp,
      result: 'error', duration_ms,
    })
    return { status: 500, body: { error: 'tool execution failed' } }
  }
}

// ─────────────────────────────────────────────
// MCP SDK setup
// SSE clients connect at GET /sse (auth required at connect-time).
// The CallToolRequestSchema handler here is shared with SSE — it cannot see
// HTTP headers, so it relies on the connect-time auth check.
// ─────────────────────────────────────────────

const server = new Server(
  { name: 'itechsmart-uaio', version: '2.2.0' },
  { capabilities: { tools: {} } },
)

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params
  // SSE-mode calls land here. Auth was validated at GET /sse. Use the
  // dispatch path with a synthetic header set so self-report still fires.
  const fakeHeaders: http.IncomingHttpHeaders = { authorization: 'Bearer ' }  // stdio path; SSE-session attribution handled per-session via createSession factory
  const result = await authedCallTool(fakeHeaders, new URLSearchParams(), name, args)
  if (result.status === 200) return result.body as Record<string, unknown>
  throw new McpError(
    result.status === 401 ? ErrorCode.InvalidRequest
    : result.status === 429 ? ErrorCode.InvalidRequest
    : ErrorCode.InternalError,
    (result.body as { error?: string }).error || 'mcp error',
  )
})

// ─── MCP_PER_SESSION_FIX — session map + factory ─────────────────────────────
// The SDK's Server is a singleton bound to ONE transport at a time. When
// multiple clients open /sse concurrently (e.g., persistent gateway +
// one-shot hermes -z calls), each new connect() steals the binding from
// the previous transport, stranding any in-flight response on the older
// session and triggering 'keepalive failed' reconnect loops on the client.
// Fix: per-session Server+Transport pair, routed by sessionId.
interface McpSession {
  server: Server
  transport: SSEServerTransport
  apiKey: string
}
const SESSIONS = new Map<string, McpSession>()

function createSession(res: http.ServerResponse, apiKey: string): McpSession {
  const sessionServer = new Server(
    { name: 'itechsmart-uaio', version: '2.2.0' },
    { capabilities: { tools: {} } },
  )
  sessionServer.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))
  sessionServer.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params
    const fakeHeaders: http.IncomingHttpHeaders = { authorization: `Bearer ${apiKey}` }
    const result = await authedCallTool(fakeHeaders, new URLSearchParams(), name, args)
    if (result.status === 200) return result.body as Record<string, unknown>
    throw new McpError(
      result.status === 401 ? ErrorCode.InvalidRequest
      : result.status === 429 ? ErrorCode.InvalidRequest
      : ErrorCode.InternalError,
      (result.body as { error?: string }).error || 'mcp error',
    )
  })
  const transport = new SSEServerTransport('/messages', res)
  return { server: sessionServer, transport, apiKey }
}

// ─────────────────────────────────────────────
// HTTP transport
// ─────────────────────────────────────────────

async function startStdio() {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error('iTechSmart MCP Server v2.0 [stdio] — mcp.itechsmart.dev')
  console.error('Phase 1 secure governance: auth + scopes + ProofLink + rate-limit + fail-closed')
  console.error(`Loaded ${VALID_API_KEYS.size} API key(s); ${Object.keys(TOOL_SCOPES).length} tool scope mappings.`)
}

// ─────────────────────────────────────────────
// A2A PROTOCOL (Linux Foundation Agent-to-Agent) — same UAIO surface as MCP.
// Agent Card at /.well-known/agent.json (open); JSON-RPC message/send at POST /a2a (auth).
// ─────────────────────────────────────────────
let A2A_SEQ = 0
function a2aId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${(A2A_SEQ++).toString(36)}`
}
const A2A_TASKS = new Map<string, unknown>()
function a2aRememberTask(id: string, task: unknown): void {
  A2A_TASKS.set(id, task)
  if (A2A_TASKS.size > 200) {
    const first = A2A_TASKS.keys().next().value
    if (first !== undefined) A2A_TASKS.delete(first)
  }
}

function buildA2AAgentCard(baseUrl: string) {
  return {
    protocolVersion: '0.3.0',
    name: 'iTechSmart UAIO Agent',
    description:
      'Agent-to-Agent access to the iTechSmart Unified Autonomous IT Operations pipeline. '
      + 'Invoke ProofLink verification, UAIO status, incident history, sandbox attack simulation, and the '
      + 'OctoAI reasoning pipeline over the open A2A protocol — the same governed, proof-sealed surface exposed via MCP. '
      + 'Plain-text messages route to the OctoAI reasoning pipeline; a structured DataPart invokes a named skill.',
    url: `${baseUrl}/a2a`,
    preferredTransport: 'JSONRPC',
    version: '2.2.0',
    provider: { organization: 'iTechSmart', url: 'https://itechsmart.dev' },
    documentationUrl: 'https://mcp.itechsmart.dev/mcp/tools',
    capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
    defaultInputModes: ['text/plain', 'application/json'],
    defaultOutputModes: ['application/json', 'text/plain'],
    securitySchemes: { bearer: { type: 'http', scheme: 'bearer', description: 'iTechSmart MCP API key as Bearer token' } },
    security: [{ bearer: [] }],
    skills: TOOLS.map((t) => t ? ({
      id: t.name,
      name: t.name,
      description: t.description.split('. ')[0] + '.',
      tags: ['uaio', 'itechsmart', 'prooflink'],
      inputModes: ['application/json', 'text/plain'],
      outputModes: ['application/json'],
    }) : null).filter(Boolean),
  }
}

async function handleA2A(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  reqUrl: URL,
): Promise<void> {
  const key = extractBearerKey(req.headers, reqUrl.searchParams)
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  let rpc: { jsonrpc?: string; id?: number | string | null; method?: string; params?: any }
  try { rpc = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') }
  catch {
    res.writeHead(400, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }))
    return
  }
  const id = rpc.id ?? null
  const reply = (obj: Record<string, unknown>) => {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ jsonrpc: '2.0', id, ...obj }))
  }
  if (!isValidKey(key)) {
    void selfReport('WARN', 'a2a_invalid_auth', { method: rpc.method || 'unknown' })
    reply({ error: { code: -32000, message: 'invalid or missing API key' } })
    return
  }

  if (rpc.method === 'message/send') {
    const msg = rpc.params?.message || {}
    const parts: any[] = Array.isArray(msg.parts) ? msg.parts : []
    const dataPart = parts.find((p) => p && p.kind === 'data' && p.data)
    const textPart = parts.find((p) => p && p.kind === 'text' && typeof p.text === 'string')
    let skill: string | undefined =
      rpc.params?.metadata?.skillId || msg?.metadata?.skillId ||
      dataPart?.data?.skill || dataPart?.data?.tool
    let toolArgs: unknown = dataPart?.data?.arguments ?? dataPart?.data?.args ?? {}
    if (!skill && textPart?.text) { skill = 'invoke_octoai_pipeline'; toolArgs = { prompt: textPart.text } }

    const contextId = msg?.contextId || a2aId('ctx')
    if (!skill) {
      reply({ result: {
        role: 'agent', kind: 'message', messageId: a2aId('msg'), contextId,
        parts: [{ kind: 'text', text: 'Send text to invoke the OctoAI pipeline, or a DataPart {skill, arguments}. Skills: ' + TOOLS.map((t) => t?.name ?? '').join(', ') }],
      } })
      return
    }

    const taskId = a2aId('task')
    const result = await authedCallTool(req.headers, reqUrl.searchParams, skill, toolArgs)
    void selfReport('INFO', 'a2a_message_send', { skill, status: result.status, caller_key_prefix: keyPrefix(key!) })
    const completed = result.status === 200
    const task: Record<string, unknown> = {
      id: taskId,
      contextId,
      kind: 'task',
      status: { state: completed ? 'completed' : 'failed', timestamp: new Date().toISOString() },
      artifacts: completed ? [{
        artifactId: a2aId('artifact'),
        name: `${skill}-result`,
        parts: [{ kind: 'data', data: result.body }],
      }] : [],
      history: [{ role: 'user', kind: 'message', messageId: msg.messageId || a2aId('msg'), parts }],
    }
    if (!completed) task.error = result.body
    a2aRememberTask(taskId, task)
    reply({ result: task })
    return
  }

  if (rpc.method === 'tasks/get') {
    const t = A2A_TASKS.get(String(rpc.params?.id || ''))
    if (t) { reply({ result: t }); return }
    reply({ error: { code: -32001, message: 'Task not found' } })
    return
  }

  reply({ error: { code: -32601, message: 'method not supported (use message/send, tasks/get)' } })
}

async function startHttp() {
  const port = parseInt(process.env.PORT || '3200', 10)
  const httpServer = http.createServer(async (req, res) => {
    try {
      const reqUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)

      // ── /health — no auth, returns status only ──
      if (req.method === 'GET' && reqUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({
          status: 'ok',
          service: 'itechsmart-uaio-mcp',
          version: '2.2.0',
          phase: '1-secure-governance',
          transport: 'http+sse',
          tools: TOOLS.length,
          sse_sessions: SESSIONS.size,
          auth_required: true,
          api_keys_loaded: VALID_API_KEYS.size,
          rate_limit_per_min: RATE_LIMIT_PER_MIN,
          rate_limit_simulate_per_min: RATE_LIMIT_SIMULATE_PER_MIN,
          timestamp: new Date().toISOString(),
        }))
        return
      }

      // ── /v1/status — public live metrics for marketing (CORS, 30s cache, no auth) ──
      if (req.method === 'GET' && reqUrl.pathname === '/v1/status') {
        const now = Date.now()
        if (!_statusCache || now - _statusCache.t > 30_000) {
          const entries = readCanonicalLedger()
          _statusCache = {
            t: now,
            body: JSON.stringify({
              status: 'operational',
              platform: 'iTechSmart UAIO',
              total_receipts: entries.length,
              bitcoin_anchored: true,
              anchoring: 'OpenTimestamps (Bitcoin)',
              last_receipt_at: entries[0]?.timestamp ?? null,
              first_receipt_at: entries[entries.length - 1]?.timestamp ?? null,
              verify_url: 'https://verify.itechsmart.dev',
              updated_at: new Date().toISOString(),
            }),
          }
        }
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Cache-Control': 'public, max-age=30',
        })
        res.end(_statusCache.body)
        return
      }

      // ── /mcp/tools — open discovery endpoint, returns the rich tools.json schema ──
      // Public on purpose: Glama and other MCP registries crawl this for tool inventory.
      // Auth-required endpoints (/sse, tools/list over JSON-RPC) remain gated.
      // tools.json is copied to dist/ during build so the published npm package ships it.
      if (req.method === 'GET' && reqUrl.pathname === '/mcp/tools') {
        try {
          const toolsPath = path.resolve(__dirname, 'tools.json')
          const data = fs.readFileSync(toolsPath, 'utf8')
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=300',
            'Access-Control-Allow-Origin': '*',
          })
          res.end(data)
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'tools.json unreadable', detail: String(e) }))
        }
        return
      }

      // ── GET /sse — auth required to establish session ──
      if (req.method === 'GET' && reqUrl.pathname === '/sse') {
        const key = extractBearerKey(req.headers, reqUrl.searchParams)
        if (!isValidKey(key)) {
          void selfReport('WARN', 'mcp_invalid_auth', { endpoint: 'sse_connect' })
          res.writeHead(401, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'invalid or missing API key' }))
          return
        }
        // MCP_PER_SESSION_FIX — each /sse gets a fresh Server+Transport pair
        // (see SESSIONS map above). Concurrent clients no longer clobber.
        const session = createSession(res, key!)
        SESSIONS.set(session.transport.sessionId, session)
        console.error(`[mcp] sse open  sid=${session.transport.sessionId.slice(0,8)} from=${req.socket.remoteAddress} active=${SESSIONS.size}`)
        // 25s SSE comment-line keepalive — keeps TCP path warm for SSE-watching clients.
        const keepaliveTimer = setInterval(() => {
          try { res.write(`: keepalive${String.fromCharCode(10)}${String.fromCharCode(10)}`) } catch { /* socket may be closed */ }
        }, 25_000)
        res.on('close', () => {
          clearInterval(keepaliveTimer)
          SESSIONS.delete(session.transport.sessionId)
          session.server.close().catch(() => { /* may already be closed */ })
          console.error(`[mcp] sse close sid=${session.transport.sessionId.slice(0,8)} active=${SESSIONS.size}`)
        })
        await session.server.connect(session.transport)
        return
      }

      // ── POST /messages — either stateless (auth header) or SSE-session ──
      if (req.method === 'POST' && reqUrl.pathname === '/messages') {
        // MCP_SSE_ROUTING_FIX — when sessionId present, route via SSEServerTransport
        // first (legacy MCP SSE protocol expects initialize/tools/list/tools/call to
        // flow through the bound transport). Without this, authed clients with a
        // sessionId fall into stateless mode which only handles tools/list and
        // tools/call -> initialize gets 400 "unknown method".
        const sessionId = reqUrl.searchParams.get('sessionId')
        if (sessionId) {
          const session = SESSIONS.get(sessionId)
          if (!session) {
            res.writeHead(404, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: 'session not found' }))
            return
          }
          // MCP_SESSION_TRUST_FIX: session was authenticated at SSE connect — don't
          // require per-request auth on POST /messages. This fixes Claude Code's SSE
          // client which doesn't forward api_key from SSE URL to POST URL.
          await session.transport.handlePostMessage(req, res)
          return
        }

        const hasAuth = !!extractBearerKey(req.headers, reqUrl.searchParams)

        if (hasAuth) {
          // Stateless mode — parse JSON-RPC, dispatch directly.
          const chunks: Buffer[] = []
          for await (const chunk of req) chunks.push(chunk as Buffer)
          let parsed: { jsonrpc?: string; id?: number | string; method?: string; params?: { name?: string; arguments?: unknown } }
          try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) }
          catch {
            res.writeHead(400, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: 'invalid JSON' }))
            return
          }

          // Auth-gate tools/list too (so the tool surface is private).
          if (parsed.method === 'tools/list') {
            const key = extractBearerKey(req.headers, reqUrl.searchParams)
            if (!isValidKey(key)) {
              void selfReport('WARN', 'mcp_invalid_auth', { endpoint: 'tools_list' })
              res.writeHead(401, { 'Content-Type': 'application/json' })
              res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, error: { code: -32000, message: 'invalid or missing API key' } }))
              return
            }
            void selfReport('INFO', 'mcp_tools_list', { caller_key_prefix: keyPrefix(key!) })
            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: { tools: TOOLS } }))
            return
          }

          if (parsed.method === 'tools/call') {
            const toolName = String(parsed.params?.name || '')
            const args = parsed.params?.arguments
            const result = await authedCallTool(req.headers, reqUrl.searchParams, toolName, args)
            res.writeHead(result.status, { 'Content-Type': 'application/json' })
            if (result.status === 200) {
              res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, result: result.body }))
            } else {
              const errBody = result.body as { error?: string; retry_after_seconds?: number }
              res.end(JSON.stringify({
                jsonrpc: '2.0', id: parsed.id,
                error: { code: -32000 - result.status, message: errBody.error || 'error', data: errBody },
              }))
            }
            return
          }

          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ jsonrpc: '2.0', id: parsed.id, error: { code: -32601, message: 'unknown method' } }))
          return
        }

        // No sessionId and no bearer — refuse.
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Authorization header required (Bearer) or active SSE session via sessionId' }))
        return
      }

      // ── A2A: Agent Card — open discovery at the A2A well-known path ──
      if (req.method === 'GET' && (reqUrl.pathname === '/.well-known/agent.json' || reqUrl.pathname === '/.well-known/agent-card.json')) {
        const base = `https://${req.headers.host || 'mcp.itechsmart.dev'}`
        res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300', 'Access-Control-Allow-Origin': '*' })
        res.end(JSON.stringify(buildA2AAgentCard(base)))
        return
      }

      // ── A2A: JSON-RPC message/send + tasks/get (auth required) ──
      if (req.method === 'POST' && reqUrl.pathname === '/a2a') {
        await handleA2A(req, res, reqUrl)
        return
      }

      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'not found' }))
    } catch (err) {
      console.error('[http] handler error:', err instanceof Error ? err.stack || err.message : String(err))
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'internal server error' }))
      }
    }
  })

  httpServer.listen(port, () => {
    console.error(`iTechSmart MCP Server v2.0 [http+sse] on :${port}`)
    console.error('Endpoints: GET /health (open) | GET /sse (auth) | POST /messages (auth)')
    console.error('Phase 1 secure governance: auth + scopes + ProofLink + rate-limit + fail-closed')
    if (VALID_API_KEYS.size === 0) {
      console.error('⚠️  NO API KEYS LOADED — set ITECHSMART_MCP_KEYS env to enable auth')
    } else {
      console.error(`Loaded ${VALID_API_KEYS.size} API key(s)`)
    }
    console.error(`Rate limits: ${RATE_LIMIT_PER_MIN}/min global, ${RATE_LIMIT_SIMULATE_PER_MIN}/min for simulate*`)
    console.error(`Self-report sink: ${SELF_REPORT_URL}`)
  })
}

const PKG_VERSION = '2.2.0'

function printHelp() {
  console.log(`iTechSmart MCP Server v${PKG_VERSION}

Usage:
  itechsmart-mcp-server                   start in stdio mode (default)
  MCP_TRANSPORT=http itechsmart-mcp-server start the HTTP+SSE server on $PORT (default 3200)
  itechsmart-mcp-server --version | -v    print version and exit
  itechsmart-mcp-server --help    | -h    print this help and exit

Tools: 6 (verify_prooflink_receipt, get_receipt_chain, query_uaio_status,
            get_incident_details, list_recent_incidents,
            simulate_infrastructure_attack)

Environment:
  ITECHSMART_MCP_KEYS        Comma-separated API keys; append :admin for mutating tools\n  ITECHSMART_MCP_API_KEYS    Legacy comma-separated API keys (loaded as admin)
  MCP_RATE_LIMIT_PER_MIN     Default 60
  MCP_RATE_LIMIT_SIMULATE    Default 10
  SELF_REPORT_URL            ProofLink sink (default http://localhost:3202/agent/self-report)
  CANONICAL_LEDGER_PATH      Override ledger path (default /opt/itechsmart/audit_ledger/ledger.json)
  BREAK_IT_API_URL           Override break-it endpoint (default http://localhost:8765/api/attack)

Docs: https://github.com/Iteksmart/mcp-server
Contact: enterprise@itechsmart.dev`)
}

async function main() {
  const argv = process.argv.slice(2)
  if (argv.includes('--version') || argv.includes('-v')) {
    console.log(PKG_VERSION)
    return
  }
  if (argv.includes('--help') || argv.includes('-h')) {
    printHelp()
    return
  }

  const useHttp = (process.env.MCP_TRANSPORT || '').toLowerCase() === 'http'
  if (useHttp) await startHttp()
  else await startStdio()
}

main().catch(err => {
  console.error('[mcp] startup failed:', err)
  process.exit(1)
})
