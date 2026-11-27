/**
 * dsh-venery — 狩猎 · Host 半侧（驾驶舱 v2）
 *
 * 职责：
 *   ① 事实库：把红队信息收集过程中的「资产节点 / 关系边 / 漏洞」存成一份可重放的
 *      JSON 图谱，落盘在 $DSH_HOME/recon/engagements/<id>.json，原子写；
 *   ② 命令留痕：recon_run 在本机执行任意 shell 命令（Linux/macOS 用 bash，Windows 用 cmd/PowerShell），完整 stdout/stderr
 *      落到 $DSH_HOME/recon/commands/<eng>/<cmdId>.log，元信息进图谱；
 *   ③ 智能体工具：recon_start / recon_asset / recon_link / recon_vuln / recon_update /
 *      recon_ingest / recon_run / recon_view；
 *   ④ HTTP 桥：POST /recon/api —— 浏览器半侧（client.js 驾驶舱）读写同一份事实库；
 *      GET /recon/stream —— SSE 推送（图谱变更 / 命令 / 漏洞 / 对话 token / 思维流）；
 *   ⑤ 驾驶舱 AI：agentLoop.create 拉起的常驻智能体，页面里直接对话，它调 recon_* 写同一张图；
 *   ⑥ 配置中心：模型三档 / 测绘密钥 / 角色 / 提示词 / 记忆 / 技能 / MCP，全部落 $DSH_HOME/recon/config.json。
 *
 * 为什么走具名 HTTP 路由而不是 @Remote：本包是纯 JS bundle，profile 下解析不到
 * @deepseek-ai/dsh-tools 的生成期 schema 链；webServer 的 exact 路由是稳定且最小的接缝
 * （与 dsh-purge 的 /redteam/api 同构），同源校验后仅本页面可用。
 *
 * 平面归属：host。资产要跨会话、跨子智能体共享，且页面要能在会话之外读取，
 * 因此事实库必须是进程级单例，不能放进 preset。
 */
import { spawn } from 'node:child_process'
import { mkdir, readFile, writeFile, appendFile, readdir, rename, stat, unlink, rm, chmod } from 'node:fs/promises'
import { readFileSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { sep } from 'node:path'
import { homedir } from 'node:os'

export const name = 'dsh-venery'

/** 工具注册必需；webServer / systemPrompt 用 ctx.inject 软获取，缺了也不炸。 */
export const inject = ['tools']

/* ────────────────────────────── 域常量 ────────────────────────────── */

/** 允许的节点类型（与 client.js 配色表严格对齐）。 */
export const NODE_KINDS = [
  'root', 'domain', 'subdomain', 'ip', 'cidr', 'host', 'port', 'service',
  'url', 'endpoint', 'credential', 'account', 'employee', 'cert', 'repo', 'bucket', 'tech', 'note',
  'source', 'fingerprint', 'secret',
]

/** 允许的边类型。 */
export const EDGE_TYPES = [
  'discovered_from', 'subdomain_of', 'resolves_to', 'in_cidr', 'has_port', 'exposes',
  'http_on', 'redirects_to', 'links_to', 'uses_tech', 'leaks', 'credentialed_by',
  'exploited_by', 'extracted_from', 'related',
]

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const VULN_STATUSES = ['open', 'verified', 'false-positive', 'fixed']
const TASK_STATUSES = ['open', 'doing', 'passed', 'failed', 'blocked']

/** 密钥字段 → 注入给 shell 的环境变量（recon_run 与驾驶舱命令都能直接读到）。 */
const KEY_ENV = {
  github: ['GITHUB_TOKEN', 'GH_TOKEN'],
  fofa: ['FOFA_KEY'],
  fofaEmail: ['FOFA_EMAIL'],
  shodan: ['SHODAN_API_KEY'],
  virustotal: ['VT_API_KEY'],
  hunter: ['HUNTER_API_KEY'],
  quake: ['QUAKE_API_KEY'],
  censysId: ['CENSYS_API_ID'],
  censysSecret: ['CENSYS_API_SECRET'],
  securitytrails: ['SECURITYTRAILS_API_KEY'],
  hunterhow: ['HUNTERHOW_API_KEY'],
  daybreak: ['DAYBREAK_API_KEY'],
  gitlab: ['GITLAB_TOKEN'],
  telegram: ['TELEGRAM_BOT_TOKEN'],
}

const MODEL_TIERS = ['deep', 'fast', 'vision']
/** 角色/队员可选的模型档位：三档 + 跟随 DSH。 */
const MODEL_CHOICES = [...MODEL_TIERS, 'dsh']
/** 思考深度四档（界面上显示英文）。 */
const THINKING_LEVELS = ['off', 'low', 'medium', 'high']
const CUSTOM_MODEL_PROVIDER_PREFIX = 'venery-'
/** 自定义模型可选的 wire protocol（llm-pi-ai 支持的主要三种）。 */
const CUSTOM_MODEL_PROTOCOLS = ['openai-completions', 'openai-responses', 'anthropic-messages']

const DEFAULT_CONFIG = {
  version: 1,
  /** 三档模型：高复杂 / 普通任务 / 视觉。留空则回落到 Harness 默认模型。 */
  models: {
    deep: { provider: '', model: '', reasoning: '' },
    fast: { provider: '', model: '', reasoning: '' },
    vision: { provider: '', model: '', reasoning: '' },
    /** 控制台添加的自定义模型（OpenAI 兼容），注册到 dsh-llm-pi-ai。 */
    custom: [],
  },
  /** 测绘 / 情报平台密钥（明文保存在本机 $DSH_HOME/recon/config.json，文件权限 0600；接口只回显“是否已配置”）。 */
  keys: {
    github: '', fofa: '', fofaEmail: '', shodan: '', virustotal: '', hunter: '', quake: '',
    censysId: '', censysSecret: '', securitytrails: '', hunterhow: '', daybreak: '',
    gitlab: '', telegram: '',
  },
  /** 额外导出的环境变量：KEY=VALUE 行。 */
  env: [],
  /** 角色设定。 */
  role: {
    name: '红队指挥席',
    mission: '在授权范围内完成信息收集与攻击面测绘，把每条发现上图、每条结论给出证据。',
    rules: [
      '只打授权范围内的资产；越界一律先问。',
      '每个资产都要连边，孤立的节点视为没做完。',
      '能用一条命令回答的问题不要拆成三条；长扫描先小范围验证。',
      '任何“可疑”都必须给出可复现命令；没有证据的结论标 info。',
    ].join('\n'),
  },
  /** 附加提示词：common 注入所有 Agent，extra 只进驾驶舱总指挥。 */
  prompt: { common: '', extra: '' },
  /** 长期记忆条目。 */
  memory: [],
  /** 启用的技能名（会写进驾驶舱 AI 的系统提示）。 */
  skills: { enabled: [] },
  /** 页面里配置的 MCP 服务器。 */
  mcp: [],
  /** 编队队员角色（留空用内置队员角色；总指挥/参谋不在这里，见 core）。 */
  roles: { squad: [] },
  /** 常设席位（总指挥/参谋）配置：全局各一个，不能召唤/回收，只能在这里或控制台改。 */
  core: {},
  /** 事件触发规则（留空用内置两条：新资产派猎手、新漏洞派浏览器）。 */
  automation: null,
  /** 外观。 */
  ui: { accent: 'cyan', glow: true, grid: true, scanlines: true },
  /** 对话。 */
  chat: { tier: 'deep', history: 200 },
  /** 全员会议：多久没新信息算停滞、同一项目开会冷却、最多自动开几轮。 */
  meeting: { stallMinutes: 20, gapMinutes: 20, maxRounds: 3 },
  /** 看板：达到上限后的合并方式；AI 语义合并模型档位固定无思考。 */
  board: { limit: 100, mergeCount: 50, mergeMode: 'deterministic', mergeModel: 'fast' },
  /** 轨迹面板最高显示条数（控制台可配置 500/1000/2000/自定义）。 */
  trace: { limit: 500 },
  /** 离职交接：成员被释放前是否先产出交接（发现/经验/坑/技巧），写进看板。 */
  handover: { enabled: true, timeoutMs: 90000, keepSkill: false },
}

/* ────────────────────────────── 小工具 ────────────────────────────── */

const nowIso = () => new Date().toISOString()

/** 统一把 ISO 字符串 / 数字 / Date 转成 epoch 毫秒；无效值返回 0。 */
function toEpoch(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : 0
  const text = asText(value)
  if (text === '') return 0
  const parsed = Date.parse(text)
  return Number.isFinite(parsed) ? parsed : 0
}

/** 规范化节点类型：自定义类型也允许；空值回退 guessKind。 */
function normalizeKind(value) {
  const raw = asText(value).trim().toLowerCase().replace(/[^\p{L}\p{N}_-]/gu, '').slice(0, 28)
  return raw
}

/** 兼容旧版把记忆写成字符串的格式；统一转成 { title, content }。 */
function memoryEntryOf(item) {
  if (typeof item === 'string') return { title: '记忆', content: item, category: 'other', importance: 'high' }
  if (item !== null && typeof item === 'object') {
    return {
      ...item,
      title: asText(item.title, '记忆'),
      content: asText(item.content),
      category: asText(item.category, 'other'),
      importance: asText(item.importance, 'high'),
    }
  }
  return { title: '记忆', content: '', category: 'other', importance: 'high' }
}

function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

function asText(value, fallback = '') {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : fallback
}

/** 通用提示词：所有 Agent 的提示词都以「common + 换行 + 自身提示词」拼接。 */
function commonPromptOf(config) {
  const prompt = config !== null && typeof config === 'object' ? config.prompt : undefined
  return asText(prompt && prompt.common)
}

const BOARD_WRITING_RULES = [
  '## 看板写入规则（所有 agent 必须遵守）',
  '- 写 agent 看板必须分两层：`summary` 是**概括索引**，`text` 是**完整正文**。',
  '- `summary`：必须是语义提炼，写清对象/位置/结论/下一步；禁止直接复制正文、截断正文或只写空泛的“有发现”。',
  '- `text`：写完整证据、命令 commandId、判断、影响、限制和下一步；禁止用概括冒充正文。',
  '- 所有 agent 发看板必须同时提供 `summary` 和 `text`。用户看板条目只有正文，不需要 summary。',
  '- 读取看板时默认只拿到概括；需要正文必须用 `recon_board action=view id=...` 按 id 查看。',
  '- 截图只写 `shots` 路径，不在 summary/text 内嵌图片。',
].join('\n')

function withCommonPrompt(config, own) {
  const common = commonPromptOf(config)
  const text = String(own === undefined || own === null ? '' : own)
  const commonText = common === '' ? '' : safePromptText(common)
  /* 通用提示词和看板写入规则都注入所有 agent；双花括号必须消毒。 */
  return [commonText, BOARD_WRITING_RULES, text].filter((part) => part !== '').join('\n')
}

/** MCP 配置数组：保留对象结构，只丢掉空项与没名字的项。 */
function asMcpList(value) {
  if (!Array.isArray(value)) return []
  return value
    .filter((row) => row !== null && typeof row === 'object' && asText(row.name) !== '')
    .map((row) => ({ ...row }))
}

function asList(value) {
  if (Array.isArray(value)) return value.map((v) => String(v)).filter((v) => v !== '')
  if (typeof value === 'string' && value.trim() !== '') {
    return value.split(/[,\s]+/).map((v) => v.trim()).filter((v) => v !== '')
  }
  return []
}

function lower(value) {
  return String(value === undefined || value === null ? '' : value).toLowerCase()
}

/** 一次 JSON 读写的原子替换：先写临时文件再 rename，避免半截文件。 */
async function writeJsonAtomic(path, value, mode) {
  const tmp = `${path}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}.tmp`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', ...(Number.isFinite(mode) ? { mode } : {}) })
  await rename(tmp, path)
  if (Number.isFinite(mode) && process.platform !== 'win32') {
    try { await chmod(path, mode) } catch { /* 权限设置失败不阻断写入 */ }
  }
}

async function writeJsonLines(path, value) {
  const tmp = `${path}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}.tmp`
  await writeFile(tmp, `${value.map((row) => JSON.stringify(row)).join('\n')}\n`, 'utf8')
  await rename(tmp, path)
}

async function ensureDir(path) {
  await mkdir(path, { recursive: true })
  return path
}

/* ───────────────────────── 跨平台执行：shell / Python / 杀进程树 ───────────────────────── */

const IS_WIN = process.platform === 'win32'

/** 执行 shell 的候选：Windows 走 cmd.exe（或 DSH_RECON_SHELL 指定的 PowerShell/Git Bash），POSIX 走 bash/sh。 */
function shellCandidates() {
  const override = asText(process.env.DSH_RECON_SHELL)
  if (override !== '') {
    const overrideArgs = asText(process.env.DSH_RECON_SHELL_ARGS)
    const args = overrideArgs !== '' ? overrideArgs.split(/\s+/).filter((x) => x !== '') : ['-lc']
    return [{ file: override, args }]
  }
  if (IS_WIN) {
    const comspec = asText(process.env.ComSpec) || 'cmd.exe'
    return [
      { file: comspec, args: ['/d', '/s', '/c'] },
      { file: 'cmd.exe', args: ['/d', '/s', '/c'] },
      /* 没有 cmd 时退回 PowerShell；DSH_RECON_SHELL 可指定 Git Bash 等 */
      { file: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command'] },
      { file: 'pwsh.exe', args: ['-NoProfile', '-NonInteractive', '-Command'] },
    ]
  }
  const shellPath = ['/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh'].find((p) => existsSync(p))
  return shellPath !== undefined
    ? [{ file: shellPath, args: ['-lc'] }, { file: 'bash', args: ['-lc'] }]
    : [{ file: 'bash', args: ['-lc'] }, { file: 'sh', args: ['-lc'] }]
}

/** Python 解释器候选：Windows 常见 python / py / python3，POSIX 反过来；可用 DSH_RECON_PYTHON 指定。 */
function pythonCandidates() {
  const override = asText(process.env.DSH_RECON_PYTHON)
  if (override !== '') return [override]
  return IS_WIN ? ['python', 'py', 'python3'] : ['python3', 'python']
}

/** 结束整棵进程树：POSIX 杀进程组，Windows 用 taskkill /T /F（负数 pid 在 Windows 无效）。 */
function killProcessTree(child, signal = 'SIGKILL') {
  if (child === undefined || child === null) return
  if (IS_WIN) {
    try {
      spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
      return
    } catch { /* 落到 child.kill */ }
  } else {
    try { process.kill(-child.pid, signal); return } catch { /* 没有进程组 */ }
  }
  try { child.kill(signal) } catch { /* 已退出 */ }
}

/** 给模型看的本机环境说明（提示词里用，避免在 Windows 上仍自称 Kali）。 */
function hostEnvNote() {
  return IS_WIN
    ? '你运行在 Windows 主机上（shell 是 cmd.exe；如已装 Git Bash / PowerShell 也可用 DSH_RECON_SHELL 指定）。'
    : (process.platform === 'darwin'
      ? '你运行在一台 macOS 主机上：有 shell 能力；用 `which` / `--help` 确认工具是否存在，缺工具可用 brew/pip 安装。'
      : '你运行在一台 Linux 主机上：有任意 shell 能力，系统里装的命令与工具都可以直接用（nmap / nuclei / ffuf / sqlmap / subfinder / httpx / whatweb / gobuster / dirsearch / feroxbuster / masscan / netexec / impacket / curl / python3 / jq …）。')
}

/** 驾驶舱（总指挥）会话 id 登记表：执行层据此拦住「指挥席自己跑扫描」。 */
const COMMANDER_SESSIONS = new Set()

/**
 * 浏览器活动看板：记录「哪个 agent 正在用浏览器、最新画面、最后活动时间」。
 * 只做内存态 + 文件兜底（截图落盘路径由 Browser 组件返回），供图谱左侧浮窗渲染。
 */
class Browsers {
  constructor(store, trace, hub) {
    this.store = store
    this.trace = trace
    this.hub = hub
    /** key: engagementId -> Map(sessionKey -> entry) */
    this.byEngagement = new Map()
    this.restored = new Set()
  }

  sessionKey(exec, caller) {
    const info = sessionInfoOf(exec) || {}
    if (typeof info.id === 'string' && info.id !== '') return info.id
    return `actor:${caller.kind}:${caller.name}`
  }

  bucket(engagementId) {
    if (!this.byEngagement.has(engagementId)) this.byEngagement.set(engagementId, new Map())
    return this.byEngagement.get(engagementId)
  }

  begin(engagementId, sessionKey, info) {
    const bucket = this.bucket(engagementId)
    const prev = bucket.get(sessionKey) || {}
    const entry = {
      key: sessionKey,
      actor: info.actor || { role: 'lead', name: '指挥席' },
      action: info.action || 'goto',
      url: asText(info.url) !== '' ? asText(info.url) : asText(prev.url),
      shot: prev.shot || null,
      title: prev.title || '',
      status: 'running',
      startedAt: nowMs(),
      ts: nowMs(),
      error: '',
    }
    bucket.set(sessionKey, entry)
    void this.persist(engagementId)
    this.broadcast(engagementId, entry)
    return entry
  }

  end(engagementId, sessionKey, outcome) {
    const bucket = this.bucket(engagementId)
    const prev = bucket.get(sessionKey)
    if (prev === undefined) return null
    const ok = outcome !== null && typeof outcome === 'object' && outcome.ok === true
    const entry = {
      ...prev,
      status: ok ? 'idle' : 'error',
      shot: (outcome && outcome.shot) || prev.shot || null,
      url: (outcome && outcome.url) || prev.url || '',
      title: (outcome && outcome.title) || prev.title || '',
      error: ok ? '' : asText(outcome && outcome.error) || '浏览器动作失败',
      ts: nowMs(),
      lastAt: nowMs(),
    }
    bucket.set(sessionKey, entry)
    void this.persist(engagementId)
    this.broadcast(engagementId, entry)
    return entry
  }

  clear(engagementId) {
    this.byEngagement.set(engagementId, new Map())
    void this.persist(engagementId)
    this.broadcast(engagementId, null)
  }

  /** 结束某个会话的全部浏览器状态（队员被回收时调用） */
  drop(engagementId, sessionKey) {
    const bucket = this.bucket(engagementId)
    bucket.delete(sessionKey)
    void this.persist(engagementId)
    this.broadcast(engagementId, null)
  }

  broadcast(engagementId, entry) {
    try {
      this.hubBroadcast({ type: 'browser', engagementId, entry })
    } catch { /* 广播失败不影响主流程 */ }
  }

  hubBroadcast(payload) {
    if (this.hub !== null && this.hub !== undefined && typeof this.hub.broadcast === 'function') this.hub.broadcast(payload)
  }

  async fileOf(engagementId) {
    return join(this.store.root, 'browsers', `${engagementId}.json`)
  }

  async persist(engagementId) {
    try {
      const bucket = this.byEngagement.get(engagementId)
      const rows = bucket === undefined ? [] : Array.from(bucket.values())
      await mkdir(join(this.store.root, 'browsers'), { recursive: true })
      await writeJsonAtomic(await this.fileOf(engagementId), rows)
    } catch { /* 落盘失败不影响显示 */ }
  }

  async restore(engagementId) {
    if (this.restored.has(engagementId)) return
    this.restored.add(engagementId)
    try {
      const raw = JSON.parse(await readFile(await this.fileOf(engagementId), 'utf8'))
      if (!Array.isArray(raw)) return
      const bucket = this.bucket(engagementId)
      for (const entry of raw) {
        if (entry === null || typeof entry !== 'object' || typeof entry.key !== 'string') continue
        if (bucket.has(entry.key)) continue
        bucket.set(entry.key, { ...entry, status: entry.status === 'running' ? 'idle' : entry.status })
      }
    } catch { /* 没有历史画面 */ }
  }

  /** 列活跃画面：running 的永远在前，其余保留最近 90 秒有画面的 */
  list(engagementId) {
    const bucket = this.byEngagement.get(engagementId)
    if (bucket === undefined) return []
    const now = nowMs()
    const rows = []
    for (const entry of bucket.values()) {
      const fresh = entry.status === 'running' || now - Number(entry.lastAt || entry.ts || 0) < 90000
      if (!fresh) continue
      if (entry.shot === null && entry.status !== 'running') continue
      rows.push({
        key: entry.key,
        name: entry.actor && entry.actor.name ? entry.actor.name : '指挥席',
        role: entry.actor && entry.actor.role ? entry.actor.role : 'lead',
        action: entry.action,
        url: entry.url || '',
        title: entry.title || '',
        shot: entry.shot || null,
        status: entry.status,
        error: entry.error || '',
        ageMs: now - Number(entry.ts || now),
      })
    }
    const rank = (row) => (row.status === 'running' ? 0 : row.status === 'error' ? 2 : 1)
    rows.sort((a, b) => rank(a) - rank(b) || Number(a.ageMs) - Number(b.ageMs))
    return rows
  }
}


/** 轨迹署名：从 exec 的 session 信息里推断是谁在动手（成员 / 指挥席 / bash）。 */
function actorOf(exec) {
  try {
    const info = sessionInfoOf(exec) || {}
    const meta = info.meta !== null && typeof info.meta === 'object' ? info.meta : {}
    if (asText(meta.origin) === 'subagent') {
      return { role: asText(meta.role, 'member'), name: asText(meta.name, '队员') }
    }
    return { role: 'lead', name: '指挥席' }
  } catch {
    return { role: 'lead', name: '指挥席' }
  }
}

/** 从 ContentBlock[] 里取出纯文本（tools/result 观察用）。 */
function contentText(blocks) {
  if (!Array.isArray(blocks)) return ''
  const out = []
  for (const block of blocks) {
    if (block !== null && typeof block === 'object' && typeof block.text === 'string') out.push(block.text)
  }
  return out.join('\n')
}

function textBlocks(text) {
  return [{ type: 'text', text: String(text) }]
}

/** 统一的工具返回：字符串化的 JSON（schema 声明为 string，渲染为文本块）。 */
function json(value) {
  return JSON.stringify(value, null, 2)
}

function toolFailure(error) {
  const message = error && error.message ? error.message : String(error)
  const kind = /缺少|非法|invalid|required|不存在|未知|not found/i.test(message) ? 'bad_input' : 'failed'
  return json({
    ok: false,
    error: message,
    error_kind: kind,
    hint: kind === 'bad_input'
      ? '参数或标识有问题：先用 recon_view 看实际 id / 取值，再修正重试。'
      : '执行失败，错误原文见 error；不要静默跳过。',
  })
}

/* ────────────────────────────── 事实库 ────────────────────────────── */

class ReconStore {
  constructor(root, onSave) {
    this.onSave = typeof onSave === 'function' ? onSave : null
    this.root = root
    this.engDir = join(root, 'engagements')
    this.cmdDir = join(root, 'commands')
    this.workDir = join(root, 'work')
    this.cache = new Map()
    this.locks = new Map()
    this.state = { active: null }
    this.ready = null
  }

  async init() {
    await ensureDir(this.engDir)
    await ensureDir(this.cmdDir)
    await ensureDir(this.workDir)
    try {
      const raw = JSON.parse(await readFile(join(this.root, 'state.json'), 'utf8'))
      if (raw && typeof raw.active === 'string') this.state.active = raw.active
    } catch { /* 首次运行没有 state.json 是正常的 */ }
    const files = (await readdir(this.engDir)).filter((f) => f.endsWith('.json'))
    if (this.state.active === null) {
      const names = files.map((f) => f.slice(0, -5))
      this.state.active = names.length === 1 ? names[0] : null
    }
    return this
  }

  async saveState() {
    await writeJsonAtomic(join(this.root, 'state.json'), { active: this.state.active, updatedAt: nowIso() })
  }

  fileOf(id) {
    return join(this.engDir, `${id.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`)
  }

  /** 串行化同一靶标的读改写：并发工具调用不会互相覆盖。 */
  withLock(id, operation) {
    const previous = this.locks.get(id) || Promise.resolve()
    const next = previous.then(operation, operation)
    const tail = next.then(() => undefined, () => undefined)
    this.locks.set(id, tail)
    /* 锁链结束后清掉表项，避免已删除靶标长期占用内存。 */
    void tail.finally(() => { if (this.locks.get(id) === tail) this.locks.delete(id) })
    return next
  }

  async load(id) {
    const cached = this.cache.get(id)
    if (cached !== undefined) return cached
    try {
      const raw = JSON.parse(await readFile(this.fileOf(id), 'utf8'))
      const eng = normalizeEngagement(raw)
      this.cache.set(id, eng)
      return eng
    } catch {
      return undefined
    }
  }

  async save(eng) {
    eng.version = (eng.version || 0) + 1
    eng.updatedAt = nowIso()
    /* 先成功落盘再替换缓存，避免磁盘失败后内存出现“假成功”状态。 */
    await writeJsonAtomic(this.fileOf(eng.id), eng)
    this.cache.set(eng.id, eng)
    try { this.onSave?.(eng) } catch { /* 广播失败不影响落盘 */ }
    return eng
  }

  async list() {
    const files = (await readdir(this.engDir)).filter((f) => f.endsWith('.json'))
    const rows = []
    for (const file of files) {
      const id = file.slice(0, -5)
      const eng = await this.load(id)
      if (eng === undefined) continue
      rows.push({
        id: eng.id,
        name: eng.name,
        scope: eng.scope,
        createdAt: eng.createdAt,
        updatedAt: eng.updatedAt,
        stats: statsOf(eng),
      })
    }
    rows.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))
    return rows
  }

  /** 按名称复用已有靶标，否则新建（名称大小写不敏感）。 */
  async openOrCreate(rawName, scope) {
    /* 名称查重与创建必须串行，否则并发 recon_start 会创建两个同名靶标。 */
    return this.withLock('__openOrCreate__', async () => {
      const nameText = asText(rawName, '默认靶标')
      const existing = await this.list()
      const hit = existing.find((row) => lower(row.name) === lower(nameText))
      if (hit !== undefined) {
        const eng = await this.load(hit.id)
        if (eng !== undefined) {
          const merged = asList(scope)
          let changed = false
          if (merged.length > 0) {
            const set = new Set([...(eng.scope || []), ...merged])
            const nextScope = Array.from(set)
            const oldScope = eng.scope || []
            if (nextScope.length !== oldScope.length || nextScope.some((value, index) => value !== oldScope[index])) {
              eng.scope = nextScope
              changed = true
            }
          }
          this.state.active = eng.id
          await this.saveState()
          return { engagement: changed ? await this.save(eng) : eng, created: false }
        }
      }
      const id = `eng_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`
      const eng = normalizeEngagement({
        id,
        name: nameText,
        scope: asList(scope),
        createdAt: nowIso(),
        updatedAt: nowIso(),
        version: 0,
        seq: 0,
        nodes: [],
        edges: [],
        vulns: [],
        commands: [],
      })
      await ensureDir(join(this.workDir, id))
      this.state.active = id
      await this.save(eng)
      await this.saveState()
      return { engagement: eng, created: true }
    })
  }

  async mutate(id, operation) {
    return this.withLock(id, async () => {
      const eng = await this.load(id)
      if (eng === undefined) throw new Error(`靶标不存在：${id}`)
      /* 操作可能在中途抛错（例如 parent 不存在）。draft 是缓存里的活对象，
         必须在失败时恢复，否则失败调用会污染后续保存。 */
      const backup = cloneJson(eng)
      const before = {
        nodes: new Set(eng.nodes.map((row) => row.id)),
        edges: new Set(eng.edges.map((row) => row.id)),
        vulns: new Set(eng.vulns.map((row) => row.id)),
        commands: new Set(eng.commands.map((row) => row.id)),
      }
      let result
      try {
        result = await operation(eng)
      } catch (error) {
        this.cache.set(id, backup)
        throw error
      }
      const delta = {
        newNodes: eng.nodes.filter((row) => !before.nodes.has(row.id)),
        newEdges: eng.edges.filter((row) => !before.edges.has(row.id)),
        newVulns: eng.vulns.filter((row) => !before.vulns.has(row.id)),
        newCommands: eng.commands.filter((row) => !before.commands.has(row.id)),
      }
      try {
        await this.save(eng)
      } catch (error) {
        this.cache.set(id, backup)
        throw error
      }
      if (this.onDelta !== undefined && this.onDelta !== null) {
        try { this.onDelta(eng, delta) } catch { /* 观察者不外溢 */ }
      }
      if (this.state.active === null) {
        this.state.active = eng.id
        await this.saveState()
      }
      return result
    })
  }

  /** 删除一个靶标：清缓存 + 删文件 + 删该靶标全部派生数据 + 修正 active 指针。 */
  async remove(id) {
    const key = asText(id)
    return this.withLock(key, async () => {
      this.cache.delete(key)
      try { await unlink(this.fileOf(key)) } catch { /* 文件不在就算已删 */ }
      /* 命令日志 / 看板 / 任务与作战目标 / 轨迹 / 浏览器画面 / 对话 / 工作目录 / 上传 */
      const targets = [
        join(this.cmdDir, key),
        join(this.root, 'board', `${key}.json`),
        join(this.root, 'tasks', `${key}.json`),
        join(this.root, 'tasks', `${key}.mission.json`),
        join(this.root, 'trace', `${key}.jsonl`),
        join(this.root, 'browser', key),
        join(this.root, 'browsers', `${key}.json`),
        join(this.root, 'brief', `${key}.json`),
        join(this.root, 'meeting', `${key}.json`),
        /* 与 Runner.fileOf 用同一套 id 清洗规则，避免非常规 id 删不到断点 */
        join(this.root, 'checkpoints', `${String(key).replace(/[^a-zA-Z0-9_-]/g, '_')}.json`),
        join(this.root, 'work', key),
        join(this.root, 'uploads', key),
      ]
      for (const target of targets) {
        try { await rm(target, { recursive: true, force: true }) } catch { /* 尽力删 */ }
      }
      try {
        const chatDir = join(this.root, 'chat')
        for (const file of await readdir(chatDir)) {
          /* 驾驶舱对话是 <id>.json，队员对话是 <id>-aN.json，两者一起删 */
          if (file !== `${key}.json` && !file.startsWith(`${key}-`)) continue
          try { await rm(join(chatDir, file), { force: true }) } catch { /* 尽力删 */ }
        }
      } catch { /* 没有 chat 目录 */ }
      if (this.state.active === key) {
        const rest = await this.list()
        this.state.active = rest.length > 0 ? rest[0].id : null
        await this.saveState()
      }
      return true
    })
  }

  /** 清空全部项目（配置与密钥保留） */
  async removeAll() {
    const rows = await this.list()
    let removed = 0
    for (const row of rows) {
      try {
        await this.remove(row.id)
        removed += 1
      } catch { /* 单条失败继续 */ }
    }
    this.state.active = null
    await this.saveState()
    return { removed, total: rows.length }
  }

  async setActive(id) {
    const eng = await this.load(id)
    if (eng === undefined) throw new Error(`靶标不存在：${id}`)
    this.state.active = id
    await this.saveState()
    return eng
  }

  async activeEngagement() {
    if (this.state.active !== null) {
      const eng = await this.load(this.state.active)
      if (eng !== undefined) return eng
    }
    const list = await this.list()
    if (list.length === 0) return undefined
    this.state.active = list[0].id
    await this.saveState()
    return this.load(list[0].id)
  }
}

function normalizeEngagement(raw) {
  const eng = raw && typeof raw === 'object' ? raw : {}
  eng.id = asText(eng.id, `eng_${Date.now().toString(36)}`)
  eng.name = asText(eng.name, '默认靶标')
  eng.scope = asList(eng.scope)
  eng.createdAt = asText(eng.createdAt, nowIso())
  eng.updatedAt = asText(eng.updatedAt, nowIso())
  eng.version = Number.isFinite(eng.version) ? eng.version : 0
  eng.seq = Number.isFinite(eng.seq) ? eng.seq : 0
  eng.nodes = Array.isArray(eng.nodes) ? eng.nodes : []
  eng.edges = Array.isArray(eng.edges) ? eng.edges : []
  eng.vulns = Array.isArray(eng.vulns) ? eng.vulns : []
  eng.commands = Array.isArray(eng.commands) ? eng.commands : []
  /* seq 兜底：老文件里可能没有 seq，用现有最大编号补齐。 */
  if (eng.seq === 0) {
    const ids = [...eng.nodes, ...eng.edges, ...eng.vulns, ...eng.commands].map((row) => String(row.id || ''))
    for (const id of ids) {
      const num = Number(id.replace(/^[a-z]+/, ''))
      if (Number.isFinite(num) && num > eng.seq) eng.seq = num
    }
  }
  return eng
}

function statsOf(eng) {
  const activeNodes = (eng.nodes || []).filter((node) => node.archived !== true)
  const activeIds = new Set(activeNodes.map((node) => node.id))
  const activeEdges = (eng.edges || []).filter((edge) => activeIds.has(edge.from) && activeIds.has(edge.to))
  const activeVulns = (eng.vulns || []).filter((vuln) => activeIds.has(vuln.nodeId))
  const bySeverity = {}
  for (const sev of SEVERITIES) bySeverity[sev] = 0
  for (const vuln of activeVulns) {
    const sev = SEVERITIES.includes(vuln.severity) ? vuln.severity : 'info'
    bySeverity[sev] += 1
  }
  return {
    nodes: activeNodes.length,
    edges: activeEdges.length,
    vulns: activeVulns.length,
    openVulns: activeVulns.filter((v) => v.status !== 'false-positive' && v.status !== 'fixed').length,
    commands: (eng.commands || []).length,
    bySeverity,
  }
}

function nextId(eng, prefix) {
  eng.seq += 1
  return `${prefix}${eng.seq}`
}

/* ────────────────────────── 图谱写入原语 ────────────────────────── */

function nodeView(node, eng) {
  const degree = eng.edges.filter((e) => e.from === node.id || e.to === node.id).length
  const vulns = eng.vulns.filter((v) => v.nodeId === node.id).length
  return { ...node, degree, vulnCount: vulns }
}

/** 按 id / value / label 解析节点，返回 undefined 表示找不到。 */
function findNode(eng, ref) {
  const wanted = asText(ref)
  if (wanted === '') return undefined
  const byId = eng.nodes.find((n) => n.id === wanted)
  if (byId !== undefined) return byId
  const byValue = eng.nodes.find((n) => lower(n.value) === lower(wanted))
  if (byValue !== undefined) return byValue
  if (wanted.length >= 3) {
    const partial = eng.nodes.filter((n) => lower(n.value).includes(lower(wanted)) || lower(n.label).includes(lower(wanted)))
    if (partial.length === 1) return partial[0]
  }
  return undefined
}

function candidateHint(eng, ref) {
  const wanted = lower(ref)
  const near = eng.nodes
    .filter((n) => wanted !== '' && (lower(n.value).includes(wanted) || lower(n.label).includes(wanted)))
    .slice(0, 8)
    .map((n) => `${n.id} ${n.kind}:${n.value}`)
  return near.length > 0 ? near : eng.nodes.slice(-8).map((n) => `${n.id} ${n.kind}:${n.value}`)
}

function upsertNode(eng, input) {
  const value = asText(input.value || input.node || input.label)
  if (value === '') throw new Error('缺少资产标识：value 不能为空（域名 / IP / URL / 端口 / 账号等）')
  const rawKind = normalizeKind(input.kind)
  const kind = rawKind !== '' ? rawKind : (NODE_KINDS.includes(input.kind) ? input.kind : 'note')
  const existing = eng.nodes.find((n) => lower(n.value) === lower(value))
    || eng.nodes.find((n) => lower(n.label) === lower(value) && n.kind === kind)
  const patch = {
    kind,
    value,
    /* 合并更新时没有显式 label 必须保留原 label，不能被 value 覆盖。 */
    label: asText(input.label) || (existing !== undefined ? asText(existing.label, value) : value),
    ip: asText(input.ip) || undefined,
    port: input.port === undefined || input.port === null || input.port === '' ? undefined : String(input.port),
    proto: asText(input.proto) || undefined,
    tech: asList(input.tech),
    status: asText(input.status) || undefined,
    tags: asList(input.tags),
    note: asText(input.note) || undefined,
    commandId: asText(input.commandId) || undefined,
    updatedAt: nowIso(),
  }
  if (existing !== undefined) {
    for (const [key, val] of Object.entries(patch)) {
      if (val === undefined) continue
      if (key === 'tech' || key === 'tags') {
        const set = new Set([...(existing[key] || []), ...val])
        existing[key] = Array.from(set)
        continue
      }
      if (key === 'kind' && existing.kind !== kind && existing.kind !== 'note') continue
      existing[key] = val
    }
    return { node: existing, created: false }
  }
  const node = {
    id: nextId(eng, 'n'),
    x: null,
    y: null,
    discoveredBy: asText(input.discoveredBy, 'agent'),
    createdAt: nowIso(),
    ...patch,
  }
  eng.nodes.push(node)
  return { node, created: true }
}

function ensureEdge(eng, from, to, type, extra = {}) {
  const edgeType = EDGE_TYPES.includes(type) ? type : 'related'
  const existing = eng.edges.find((e) => e.from === from && e.to === to && e.type === edgeType)
  if (existing !== undefined) {
    if (asText(extra.note)) existing.note = asText(extra.note)
    if (asText(extra.commandId)) existing.commandId = asText(extra.commandId)
    return { edge: existing, created: false }
  }
  const edge = {
    id: nextId(eng, 'e'),
    from,
    to,
    type: edgeType,
    label: asText(extra.label) || undefined,
    note: asText(extra.note) || undefined,
    commandId: asText(extra.commandId) || undefined,
    createdAt: nowIso(),
  }
  eng.edges.push(edge)
  return { edge, created: true }
}

function addVuln(eng, input) {
  const title = asText(input.title)
  if (title === '') throw new Error('缺少漏洞标题：title 不能为空')
  const anchor = findNode(eng, input.node || input.nodeId || input.asset)
  if (anchor === undefined) {
    throw new Error(`找不到关联节点：${asText(input.node, '(未提供)')}。候选：${candidateHint(eng, input.node).join(' ; ')}`)
  }
  const severity = SEVERITIES.includes(lower(input.severity)) ? lower(input.severity) : 'info'
  const existing = eng.vulns.find((v) => v.nodeId === anchor.id && lower(v.title) === lower(title)
    && lower(v.endpoint) === lower(asText(input.endpoint)))
  if (existing !== undefined) {
    /* 只在本次显式提供等级时更新，避免补证据时把 high 降成默认 info。 */
    if (SEVERITIES.includes(lower(input.severity))) existing.severity = severity
    if (asText(input.param)) existing.param = asText(input.param)
    if (asText(input.payload)) existing.payload = asText(input.payload)
    if (asText(input.description)) existing.description = asText(input.description)
    if (asText(input.cvss)) existing.cvss = asText(input.cvss)
    if (asText(input.cve)) existing.cve = asText(input.cve)
    if (asText(input.commandId)) existing.commandId = asText(input.commandId)
    if (asText(input.type)) existing.type = asText(input.type)
    if (VULN_STATUSES.includes(lower(input.status))) existing.status = lower(input.status)
    existing.updatedAt = nowIso()
    return { vuln: existing, created: false }
  }
  const vuln = {
    id: nextId(eng, 'v'),
    nodeId: anchor.id,
    title,
    severity,
    type: asText(input.type) || undefined,
    endpoint: asText(input.endpoint) || undefined,
    param: asText(input.param) || undefined,
    payload: asText(input.payload) || undefined,
    cvss: asText(input.cvss) || undefined,
    cve: asText(input.cve) || undefined,
    description: asText(input.description) || undefined,
    status: VULN_STATUSES.includes(lower(input.status)) ? lower(input.status) : 'open',
    commandId: asText(input.commandId) || undefined,
    createdAt: nowIso(),
  }
  eng.vulns.push(vuln)
  return { vuln, created: true }
}

/** 图谱的紧凑文本视图：给模型看的，不是给页面看的。 */
function graphSummary(eng, options = {}) {
  const limit = Number.isFinite(Number(options.limit))
    ? Math.max(1, Math.min(2000, Math.floor(Number(options.limit))))
    : 400
  const activeNodes = (eng.nodes || []).filter((node) => node.archived !== true)
  const activeIds = new Set(activeNodes.map((node) => node.id))
  const nodes = activeNodes.slice(0, limit).map((n) => {
    const bits = [n.id, n.kind, n.value]
    if (n.ip) bits.push(`ip=${n.ip}`)
    if (n.port) bits.push(`port=${n.port}`)
    if (n.tech && n.tech.length > 0) bits.push(`tech=${n.tech.join('/')}`)
    const vulns = (eng.vulns || []).filter((v) => v.nodeId === n.id)
    if (vulns.length > 0) bits.push(`vulns=${vulns.map((v) => `${v.severity}:${v.title}`).join('|')}`)
    return bits.join('  ')
  })
  const edges = (eng.edges || []).filter((e) => activeIds.has(e.from) && activeIds.has(e.to)).slice(0, limit).map((e) => `${e.from} -[${e.type}]-> ${e.to}`)
  const vulns = (eng.vulns || []).filter((v) => activeIds.has(v.nodeId)).slice(0, limit).map((v) => {
    const node = activeNodes.find((n) => n.id === v.nodeId)
    return `${v.id}  ${v.severity}  ${node ? node.value : v.nodeId}  ${v.title}  status=${v.status}`
  })
  const commands = eng.commands.slice(-Math.min(limit, 60)).map(
    (c) => `${c.id}  exit=${c.exitCode === null ? 'running' : c.exitCode}  ${String(c.command).slice(0, 160)}`,
  )
  return {
    engagement: { id: eng.id, name: eng.name, scope: eng.scope, updatedAt: eng.updatedAt },
    stats: statsOf(eng),
    nodes,
    edges,
    vulns,
    recentCommands: commands,
    ...(activeNodes.length > limit ? { note: `节点多于 ${limit}，仅列出前 ${limit} 个；完整数据在页面上。` } : {}),
    ...(eng.nodes.length > activeNodes.length ? { archived: eng.nodes.length - activeNodes.length } : {}),
  }
}

/* ────────────────────────── 命令执行与留痕 ────────────────────────── */

const OUTPUT_CAP = 8 * 1024 * 1024

function runShell(command, options) {
  const { cwd, timeoutMs, signal } = options
  return new Promise((resolvePromise) => {
    const startedAt = Date.now()
    let out = ''
    let err = ''
    let outBytes = 0
    let errBytes = 0
    let truncated = false
    let timedOut = false
    let settled = false
    let child
    let attempt = 0
    const candidates = shellCandidates()
    const launch = () => {
      const spec = candidates[attempt]
      /* cmd.exe 默认按系统代码页输出，中文会乱码；先切 UTF-8 再跑用户的命令 */
      const body = IS_WIN && /(^|[\\/])cmd(\.exe)?$/i.test(spec.file)
        ? `chcp 65001>nul & ${command}`
        : command
      let localChild
      let superseded = false
      try {
        localChild = spawn(spec.file, [...spec.args, body], {
          cwd,
          env: options.env || process.env,
          /* Windows 上 detached 会另开控制台，进程组语义也不存在；杀树统一走 killProcessTree */
          detached: !IS_WIN,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      } catch (error) {
        if (attempt + 1 < candidates.length) {
          superseded = true
          attempt += 1
          launch()
          return
        }
        resolvePromise({
          exitCode: null, signal: null, stdout: '', stderr: String(error && error.message ? error.message : error),
          durationMs: 0, timedOut: false, truncated: false, outBytes: 0, errBytes: 0, spawnError: true,
        })
        return
      }
      child = localChild
      localChild.stdout.on('data', (chunk) => collect(chunk, 'out'))
      localChild.stderr.on('data', (chunk) => collect(chunk, 'err'))
      localChild.on('error', (error) => {
        /* 本机没有这个 shell（典型：Windows 上写死了 /bin/bash）→ 换下一个候选 */
        if (error && error.code === 'ENOENT' && attempt + 1 < candidates.length) {
          superseded = true
          attempt += 1
          launch()
          return
        }
        err += `\n[spawn error] ${error && error.message ? error.message : error}`
        finish(null, null)
      })
      localChild.on('close', (code, sig) => {
        /* 已被后续候选取代的旧子进程，它的 close 不能结束整个 Promise。 */
        if (superseded) return
        finish(code, sig)
      })
    }
    const collect = (chunk, streamName) => {
      const text = chunk.toString('utf8')
      if (streamName === 'out') {
        outBytes += chunk.length
        if (out.length + text.length <= OUTPUT_CAP) out += text
        else truncated = true
      } else {
        errBytes += chunk.length
        if (err.length + text.length <= OUTPUT_CAP) err += text
        else truncated = true
      }
    }
    const stopChild = (reason) => {
      if (reason === 'timeout') timedOut = true
      killProcessTree(child)
    }
    const timer = setTimeout(() => stopChild('timeout'), timeoutMs)
    const onAbort = () => stopChild('abort')
    const finish = (code, sig) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (signal !== undefined && signal !== null) signal.removeEventListener('abort', onAbort)
      resolvePromise({
        exitCode: code, signal: sig, stdout: out, stderr: err,
        durationMs: Date.now() - startedAt, timedOut, truncated,
        outBytes, errBytes,
        aborted: signal !== undefined && signal !== null && signal.aborted,
      })
    }
    launch()
    if (signal !== undefined && signal !== null) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }
  })
}

/** 直接执行一个可执行文件并收集输出（不经过 shell，避免指纹把命令注进 shell）。 */
function runCapture(file, args, timeoutMs = 20000) {
  return new Promise((resolvePromise) => {
    let child
    try {
      child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, detached: !IS_WIN })
    } catch (error) {
      resolvePromise({ stdout: '', stderr: '', error: error && error.message ? error.message : String(error) })
      return
    }
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolvePromise(value)
    }
    const timer = setTimeout(() => {
      killProcessTree(child)
      finish({ stdout, stderr, error: `执行超时（${timeoutMs}ms）` })
    }, timeoutMs)
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8')
      if (stdout.length > 2 * 1024 * 1024) stdout = stdout.slice(-2 * 1024 * 1024)
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8')
      if (stderr.length > 2 * 1024 * 1024) stderr = stderr.slice(-2 * 1024 * 1024)
    })
    child.on('error', (error) => {
      finish({ stdout, stderr, error: error && error.code === 'ENOENT' ? `未找到 ${file}` : (error && error.message ? error.message : String(error)) })
    })
    child.on('close', (code) => finish({ exitCode: code, stdout, stderr }))
  })
}

/** Exploit-DB 本地库检索（searchsploit --json）。 */
async function searchExploitDb(fingerprint, limit) {
  const file = asText(process.env.SEARCHSPLOIT) || 'searchsploit'
  const outcome = await runCapture(file, ['--json', fingerprint], 25000)
  if (outcome.error !== undefined) return { source: 'exploitdb', candidates: [], error: `${file}: ${outcome.error}` }
  try {
    const parsed = JSON.parse(asText(outcome.stdout) === '' ? '{}' : outcome.stdout.trim())
    const rows = [
      ...(Array.isArray(parsed.RESULTS_EXPLOIT) ? parsed.RESULTS_EXPLOIT : []),
      ...(Array.isArray(parsed.RESULTS_SHELLCODE) ? parsed.RESULTS_SHELLCODE : []),
    ]
    const candidates = rows.slice(0, limit).map((row) => {
      const id = asText(row['EDB-ID'] !== undefined ? row['EDB-ID'] : row.EDBID)
      return {
        source: 'exploitdb',
        id,
        title: shortText(asText(row.Title), 200),
        date: asText(row.Date),
        type: asText(row.Type),
        platform: asText(row.Platform),
        path: asText(row.Path),
        url: id !== '' ? `https://www.exploit-db.com/exploits/${encodeURIComponent(id)}` : '',
      }
    })
    return { source: 'exploitdb', candidates, error: '' }
  } catch {
    return { source: 'exploitdb', candidates: [], error: `searchsploit 输出无法解析：${shortText(asText(outcome.stderr) || asText(outcome.stdout), 200)}` }
  }
}

/** NVD（CVE）公开库检索；只按关键字查历史漏洞，不碰目标。 */
async function searchNvd(fingerprint, limit) {
  if (typeof fetch !== 'function') return { source: 'nvd', candidates: [], error: '当前 Node 没有 fetch' }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 20000)
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(fingerprint)}&resultsPerPage=${limit}`
    const response = await fetch(url, { signal: controller.signal, headers: { 'user-agent': 'dsh-venery/0.50.6' } })
    if (!response.ok) return { source: 'nvd', candidates: [], error: `NVD HTTP ${response.status}` }
    const data = await response.json()
    const rows = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : []
    const candidates = rows.slice(0, limit).map((item) => {
      const cve = item && item.cve ? item.cve : {}
      const metrics = cve.metrics || {}
      const metric = (Array.isArray(metrics.cvssMetricV31) && metrics.cvssMetricV31[0])
        || (Array.isArray(metrics.cvssMetricV30) && metrics.cvssMetricV30[0])
        || (Array.isArray(metrics.cvssMetricV2) && metrics.cvssMetricV2[0])
        || null
      const severity = metric && metric.cvssData && asText(metric.cvssData.baseSeverity)
        ? asText(metric.cvssData.baseSeverity)
        : (metric && asText(metric.baseSeverity) !== '' ? asText(metric.baseSeverity) : '')
      const description = (Array.isArray(cve.descriptions) ? cve.descriptions : [])
        .find((row) => row && row.lang === 'en')
      return {
        source: 'nvd',
        id: asText(cve.id),
        title: shortText(asText(description && description.value), 240),
        published: asText(cve.published),
        severity,
        url: asText(cve.id) !== '' ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(asText(cve.id))}` : '',
      }
    })
    return { source: 'nvd', candidates, error: '' }
  } catch (error) {
    const reason = error && error.name === 'AbortError' ? '超时' : (error && error.message ? error.message : String(error))
    return { source: 'nvd', candidates: [], error: `NVD 查询失败：${reason}` }
  } finally {
    clearTimeout(timer)
  }
}

function headTail(text, budget) {
  const text2 = String(text || '')
  if (text2.length <= budget) return { body: text2, clipped: false }
  const head = Math.floor(budget * 0.35)
  const tail = budget - head
  return {
    body: `${text2.slice(0, head)}\n\n… [中间省略 ${text2.length - budget} 字符，完整输出见 outputPath / 页面命令日志] …\n\n${text2.slice(-tail)}`,
    clipped: true,
  }
}

/* ────────────────────────── 会话绑定 ────────────────────────── */

function sessionInfoOf(exec) {
  const agent = exec && exec.agent
  const session = agent && agent.session
  const header = session && session.header
  return {
    id: header && typeof header.id === 'string' ? header.id : undefined,
    parent: header && typeof header.parentSession === 'string' ? header.parentSession : undefined,
    cwd: header && typeof header.cwd === 'string' ? header.cwd : undefined,
  }
}

function bindingKeys(exec) {
  const info = sessionInfoOf(exec)
  return [info.id, info.parent].filter((v) => typeof v === 'string' && v !== '')
}


/* ────────────────────────── 配置中心 ────────────────────────── */

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value))
}

/** 深合并：对象逐键覆盖，数组整体替换（mcp / memory / env 都是整体语义）。 */
function mergeDeep(base, patch) {
  if (Array.isArray(patch)) return cloneJson(patch)
  if (patch === null || typeof patch !== 'object') return patch
  const out = Array.isArray(base) ? [] : { ...(base && typeof base === 'object' ? base : {}) }
  for (const [key, value] of Object.entries(patch)) {
    out[key] = key in out ? mergeDeep(out[key], value) : cloneJson(value)
  }
  return out
}

class ConfigStore {
  constructor(root) {
    this.root = root
    this.file = join(root, 'config.json')
    this.value = cloneJson(DEFAULT_CONFIG)
    this.listeners = new Set()
    this.ready = null
    this.writeQueue = Promise.resolve()
  }

  async init() {
    await ensureDir(this.root)
    try {
      const raw = JSON.parse(await readFile(this.file, 'utf8'))
      this.value = mergeDeep(cloneJson(DEFAULT_CONFIG), raw && typeof raw === 'object' ? raw : {})
    } catch { /* 首次运行没有配置文件 */ }
    return this
  }

  get() {
    return this.value
  }

  onChange(listener) {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async patch(patch) {
    const run = this.writeQueue.then(async () => {
      this.value = mergeDeep(this.value, patch && typeof patch === 'object' ? patch : {})
      await this.persist()
      for (const listener of Array.from(this.listeners)) {
        try { listener(this.value) } catch { /* 观察者异常不外溢 */ }
      }
      return this.value
    })
    this.writeQueue = run.then(() => undefined, () => undefined)
    return run
  }

  /** 只写盘不触发观察者（用于初始迁移）。 */
  async persist() {
    await writeJsonAtomic(this.file, this.value, 0o600)
  }

  /** 密钥环境：把配置里的 key 映射成命令可直接读取的环境变量。 */
  keyEnv() {
    const env = {}
    const keys = this.value.keys || {}
    for (const [field, names] of Object.entries(KEY_ENV)) {
      const value = asText(keys[field])
      if (value === '') continue
      for (const name of names) env[name] = value
    }
    for (const line of Array.isArray(this.value.env) ? this.value.env : []) {
      const text = asText(line)
      const at = text.indexOf('=')
      if (at <= 0) continue
      env[text.slice(0, at).trim()] = text.slice(at + 1)
    }
    return env
  }

  /** 页面可见的密钥视图：只给"配没配"，不给值。 */
  keyPresence() {
    const out = {}
    for (const [field, value] of Object.entries(this.value.keys || {})) out[field] = asText(value) !== ''
    return out
  }

  redacted(options = {}) {
    const copy = cloneJson(this.value)
    for (const field of Object.keys(copy.keys || {})) {
      if (asText(copy.keys[field]) !== '') copy.keys[field] = '••••••••'
    }
    if (options.redactEnv === true) {
      copy.env = (Array.isArray(copy.env) ? copy.env : []).map((line) => {
        const text = String(line)
        const at = text.indexOf('=')
        return at > 0 ? `${text.slice(0, at)}=••••••••` : '••••••••'
      })
      copy.mcp = (Array.isArray(copy.mcp) ? copy.mcp : []).map((row) => {
        if (row === null || typeof row !== 'object') return row
        const next = { ...row }
        if (next.env !== null && typeof next.env === 'object' && !Array.isArray(next.env)) {
          next.env = Object.fromEntries(Object.keys(next.env).map((key) => [key, '••••••••']))
        }
        if (next.headers !== null && typeof next.headers === 'object' && !Array.isArray(next.headers)) {
          next.headers = Object.fromEntries(Object.keys(next.headers).map((key) => [key, '••••••••']))
        }
        return next
      })
    }
    return copy
  }
}

/* ────────────────────────── 事件中心（SSE） ────────────────────────── */

/** 自定义模型的稳定 id / provider 路由 / 凭据引用。 */
function customModelId() {
  return `cm_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
}
function customModelProviderOf(id) {
  return `${CUSTOM_MODEL_PROVIDER_PREFIX}${String(id).replace(/[^a-zA-Z0-9_-]/g, '_')}`
}
function customModelKeyRefOf(id) {
  return `VENERY_MODEL_${String(id).replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`
}

/**
 * 自定义模型 = 控制台里填 Base URL / API Key / 模型名 / 思考深度，
 * 落到 DSH 的 llm-pi-ai provider 配置（OpenAI 兼容协议），
 * API Key 只进 credentials 服务，不写进 venery 的 config.json。
 */
class CustomModelRegistry {
  constructor(ctx, configStore) {
    this.ctx = ctx
    this.configStore = configStore
  }

  current() {
    const models = this.configStore.get().models
    return models !== null && typeof models === 'object' && Array.isArray(models.custom) ? models.custom : []
  }

  async hasKey(ref) {
    if (asText(ref) === '') return false
    const credentials = this.ctx.get('credentials')
    if (credentials === undefined || credentials === null || typeof credentials.describe !== 'function') return false
    try {
      const info = await credentials.describe(ref)
      return info !== undefined && info !== null && info.configured === true
    } catch {
      return false
    }
  }

  async list(rows = this.current()) {
    const out = []
    for (const row of rows) {
      if (row === null || typeof row !== 'object') continue
      out.push({ ...row, hasKey: await this.hasKey(row.keyRef) })
    }
    return out
  }

  /** 校验并规范化 UI 提交的自定义模型；apiKey 只用于写 credentials，不会返回。 */
  async prepare(incoming) {
    const rows = Array.isArray(incoming) ? incoming : []
    const existing = new Map(this.current().map((row) => [asText(row.id), row]))
    const next = []
    const keyUpdates = []
    const seenNames = new Set()
    for (const raw of rows) {
      if (raw === null || typeof raw !== 'object') continue
      const givenId = asText(raw.id).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 48)
      const prev = existing.get(givenId)
      const id = givenId !== '' ? givenId : customModelId()
      const name = asText(raw.name, prev !== undefined ? asText(prev.name) : '')
      const baseUrl = asText(raw.baseUrl, prev !== undefined ? asText(prev.baseUrl) : '')
      const modelId = asText(raw.model, prev !== undefined ? asText(prev.model) : '')
      if (name === '') throw new Error('自定义模型缺少名称')
      if (seenNames.has(name.toLowerCase())) throw new Error(`模型名称重复：「${name}」；档位下拉按名称选择，名称必须唯一`)
      seenNames.add(name.toLowerCase())
      if (modelId === '') throw new Error(`自定义模型「${name}」缺少模型名称（API model id）`)
      if (!/^https?:\/\//i.test(baseUrl)) throw new Error(`自定义模型「${name}」的 Base URL 必须以 http:// 或 https:// 开头`)
      const reasoning = THINKING_LEVELS.includes(asText(raw.reasoning))
        ? asText(raw.reasoning)
        : (prev !== undefined && THINKING_LEVELS.includes(asText(prev.reasoning)) ? asText(prev.reasoning) : 'medium')
      const protocol = CUSTOM_MODEL_PROTOCOLS.includes(asText(raw.protocol))
        ? asText(raw.protocol)
        : (prev !== undefined && CUSTOM_MODEL_PROTOCOLS.includes(asText(prev.protocol)) ? asText(prev.protocol) : 'openai-completions')
      const provider = prev !== undefined && asText(prev.provider) !== '' ? asText(prev.provider) : customModelProviderOf(id)
      const keyRef = prev !== undefined && asText(prev.keyRef) !== '' ? asText(prev.keyRef) : customModelKeyRefOf(id)
      const apiKey = typeof raw.apiKey === 'string' ? raw.apiKey.trim() : ''
      if (apiKey !== '') keyUpdates.push({ ref: keyRef, key: apiKey })
      if (apiKey === '' && !(await this.hasKey(keyRef))) {
        throw new Error(`自定义模型「${name}」缺少 API Key；编辑已有模型时留空表示沿用已保存的 Key`)
      }
      next.push({
        id,
        name,
        provider,
        keyRef,
        baseUrl,
        model: modelId,
        reasoning,
        protocol,
        createdAt: prev !== undefined && asText(prev.createdAt) !== '' ? asText(prev.createdAt) : nowIso(),
      })
    }
    const nextIds = new Set(next.map((row) => row.id))
    const removed = this.current().filter((row) => !nextIds.has(asText(row.id)))
    return { next, keyUpdates, removed }
  }

  /** 同步到 DSH：credentials 存 key，llm-pi-ai 的 providers 注册路由。 */
  async apply(next, removed = [], keyUpdates = []) {
    if (next.length === 0 && removed.length === 0) return
    const settings = this.ctx.get('settings')
    const credentials = this.ctx.get('credentials')
    if (settings === undefined || settings === null) throw new Error('settings 服务不可用：无法注册自定义模型')
    if (keyUpdates.length > 0 || next.length > 0) {
      if (credentials === undefined || credentials === null || typeof credentials.set !== 'function') {
        throw new Error('credentials 服务不可用：无法保存自定义模型 API Key')
      }
    }
    for (const item of keyUpdates) await credentials.set(item.ref, item.key)
    if (next.length > 0) {
      const providers = {}
      for (const row of next) {
        providers[row.provider] = {
          displayName: row.name,
          api: asText(row.protocol, 'openai-completions'),
          baseURL: row.baseUrl,
          apiKeyEnv: row.keyRef,
          models: [{
            id: row.model,
            name: row.name,
            reasoningEfforts: { off: null, low: 'low', medium: 'medium', high: 'high' },
          }],
        }
      }
      await settings.update('llm-pi-ai', { providers })
    }
    if (removed.length > 0) {
      const ops = removed
        .filter((row) => asText(row.provider) !== '')
        .map((row) => ({ op: 'unset', path: ['providers', asText(row.provider)] }))
      if (ops.length > 0) {
        try { await settings.mutate('llm-pi-ai', ops) } catch { /* 路由可能已经被移除 */ }
      }
      if (credentials !== undefined && credentials !== null && typeof credentials.unset === 'function') {
        for (const row of removed) {
          try { await credentials.unset(asText(row.keyRef)) } catch { /* 忽略 */ }
        }
      }
    }
    const llm = this.ctx.get('llm')
    if (next.length > 0) {
      if (llm === undefined || llm === null || typeof llm.listProviders !== 'function') {
        throw new Error('llm 服务不可用：无法确认自定义模型路由')
      }
      const missing = new Set(next.map((row) => row.provider))
      const deadline = Date.now() + 8000
      while (missing.size > 0 && Date.now() < deadline) {
        const ids = new Set((await llm.listProviders()).map((row) => row.id))
        for (const provider of Array.from(missing)) if (ids.has(provider)) missing.delete(provider)
        if (missing.size > 0) await new Promise((resolve) => setTimeout(resolve, 150))
      }
      if (missing.size > 0) throw new Error(`自定义模型路由未注册成功：${Array.from(missing).join(', ')}`)
    }
  }

  /** 插件启动时把已有自定义模型重新挂到 llm-pi-ai；路由已在则跳过，避免每次重载都写配置。 */
  async syncCurrent() {
    const current = this.current()
    if (current.length === 0) return
    const llm = this.ctx.get('llm')
    if (llm !== undefined && llm !== null && typeof llm.listProviders === 'function') {
      try {
        const ids = new Set((await llm.listProviders()).map((row) => row.id))
        if (current.every((row) => ids.has(asText(row.provider)))) return
      } catch { /* 查不到就继续重新挂 */ }
    }
    await this.apply(current, [], [])
  }
}

class EventHub {
  constructor() {
    this.clients = new Set()
    this.seq = 0
  }

  add(res) {
    const client = { res, alive: true }
    this.clients.add(client)
    const ping = setInterval(() => {
      try { res.write(': ping\n\n') } catch { this.drop(client) }
    }, 15000)
    client.ping = ping
    res.on('close', () => this.drop(client))
    return client
  }

  drop(client) {
    if (!this.clients.has(client)) return
    this.clients.delete(client)
    clearInterval(client.ping)
    try { client.res.end() } catch { /* 已断开 */ }
  }

  broadcast(payload) {
    this.seq += 1
    const frame = `data: ${JSON.stringify({ ...payload, seq: this.seq, t: Date.now() })}\n\n`
    for (const client of Array.from(this.clients)) {
      try {
        client.res.write(frame)
      } catch {
        this.drop(client)
      }
    }
  }

  closeAll() {
    for (const client of Array.from(this.clients)) this.drop(client)
  }
}
/* ────────────────────────── 工具集 ────────────────────────── */

function registerTools(ctx, store, cfg, bindings, configStore, trace, resolveActor, browsersRef, meetingRef, squadRef) {
  const who = (exec) => (typeof resolveActor === 'function' ? resolveActor(exec) : actorOf(exec))
  const browsers = browsersRef
  const squad = squadRef
  const register = (definition) => ctx.tools.register(definition)

  const resolveEngagement = async (exec, explicit) => {
    if (asText(explicit) !== '') {
      const listed = await store.list()
      const hit = listed.find((row) => row.id === explicit) || listed.find((row) => lower(row.name) === lower(explicit))
      if (hit === undefined) throw new Error(`靶标不存在：${explicit}。现有：${listed.map((r) => `${r.id}(${r.name})`).join(', ') || '无'}`)
      return store.load(hit.id)
    }
    for (const key of bindingKeys(exec)) {
      const bound = bindings.get(key)
      if (bound !== undefined) {
        const eng = await store.load(bound)
        if (eng !== undefined) return eng
      }
    }
    const active = await store.activeEngagement()
    if (active !== undefined) {
      for (const key of bindingKeys(exec)) bindings.set(key, active.id)
      return active
    }
    throw new Error('还没有任何靶标：先调用 recon_start 建立起始资产。')
  }

  register({
    name: 'recon_start',
    description:
      '【信息收集第一步】建立/打开一次红队演练靶标，并落下用户指定的起始资产作为图谱根节点；'
      + '本会话（含其子智能体）随后自动绑定该靶标。同一名称重复调用会复用已有图谱，不会丢数据。'
      + '所有节点、关系、漏洞都会实时出现在 Harness 的「狩猎」页面里。',
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', description: '靶标名称（单位 / 项目 / 演练批次），用于复用图谱' },
        scope: { type: 'array', items: { type: 'string' }, description: '授权范围：CIDR / 域名列表' },
        root: { type: 'string', description: '用户指定的起始资产：域名 / CIDR / URL，例如 TARGET_HOST、TARGET_CIDR、TARGET_URL' },
        rootKind: { type: 'string', description: '起始资产类型（可用内置名，也可自定新类型，如 k8s/queue/sbom/osint-profile）' },
        note: { type: 'string', description: '起始资产的备注 / 授权说明' },
      },
      required: ['name'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const nameText = asText(args.name)
        if (nameText === '') throw new Error('缺少参数 name')
        const opened = await store.openOrCreate(nameText, args.scope)
        const eng = opened.engagement
        void squadRef?.ensureCore?.(eng.id).catch(() => {})
        for (const key of bindingKeys(exec)) bindings.set(key, eng.id)
        let rootNode
        if (asText(args.root) !== '') {
          const wantedKind = normalizeKind(args.rootKind)
          const inferred = wantedKind !== '' ? wantedKind : guessKind(args.root)
          rootNode = await store.mutate(eng.id, (draft) => {
            const { node, created } = upsertNode(draft, {
              value: args.root,
              kind: inferred,
              label: args.root,
              note: args.note,
              discoveredBy: 'user',
            })
            /* 起始资产永远带 seed 标记：页面上单独描边，一眼看出用户从哪儿开始 */
            node.seed = true
            return { node, created }
          })
        }
        const fresh = await store.load(eng.id)
        return json({
          ok: true,
          created: opened.created,
          engagement: { id: fresh.id, name: fresh.name, scope: fresh.scope },
          rootNode: rootNode ? rootNode.node.id : null,
          stats: statsOf(fresh),
          next: '先让参谋把整体方案写进看板 kind=hypothesis，再登记 mission 并拆任务给专人；成员完成后必须由 QA 核查证据并 accept/reject，最后你才能 mission close 宣布结束。',
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_asset',
    description:
      '登记一个资产节点（域名/子域/IP/端口/服务/URL/接口/凭证/账号/证书/仓库/技术栈…）。'
      + '同一标识重复登记会合并属性而不是产生重复节点。可用 parent + edge 一次把「从哪发现的」关系连上。',
    parameters: {
      type: 'object',
      properties: {
        value: { type: 'string', description: '资产标识：域名、IP、URL、端口、账号等' },
        kind: { type: 'string', description: '节点类型：内置 domain/subdomain/ip/port/service/url/endpoint/tech/source/fingerprint/secret/credential/account/employee/cert/repo/bucket/cidr/host/root/note，也可自定任意新类型（api、db、queue、k8s、container、sbom、osint-profile、leak、file、cookie、session、token、dns-record、whois、social-account…），新类型会自动出现在图例与筛选里' },
        label: { type: 'string', description: '显示名（默认同 value）' },
        ip: { type: 'string', description: '解析到的 IP' },
        port: { type: ['string', 'number'], description: '端口' },
        proto: { type: 'string', description: '协议：http/https/tcp/udp/ssh/rdp…' },
        tech: { type: 'array', items: { type: 'string' }, description: '指纹 / 技术栈标签' },
        status: { type: 'string', description: '状态：alive/dead/interesting/owned…' },
        tags: { type: 'array', items: { type: 'string' }, description: '自定义标签' },
        note: { type: 'string', description: '备注 / 证据摘要' },
        parent: { type: 'string', description: '父节点 id 或 value（可选）' },
        edge: { type: 'string', enum: EDGE_TYPES, description: '父节点到本节点的关系类型，默认 discovered_from' },
        commandId: { type: 'string', description: '产出该资产的命令 id（recon_run 返回）' },
        engagement: { type: 'string', description: '靶标 id 或名称（默认当前绑定）' },
      },
      required: ['value'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const result = await store.mutate(eng.id, (draft) => {
          const parent = asText(args.parent) !== '' ? findNode(draft, args.parent) : undefined
          if (asText(args.parent) !== '' && parent === undefined) {
            throw new Error(`父节点不存在：${args.parent}。候选：${candidateHint(draft, args.parent).join(' ; ')}`)
          }
          const { node, created } = upsertNode(draft, { ...args, kind: args.kind || guessKind(args.value) })
          let edge = null
          if (parent !== undefined) {
            edge = ensureEdge(draft, parent.id, node.id, asText(args.edge, 'discovered_from'), { commandId: args.commandId }).edge
          }
          return { node, created, edge }
        })
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: who(exec),
          title: `${result.created ? '图谱 +1 资产' : '图谱 ~ 资产'} ${result.node.kind}:${shortText(result.node.value, 80)}`,
          detail: asText(args.note) || asText(args.purpose) || '',
          refs: { nodeIds: [result.node.id], commandId: asText(args.commandId), taskId: asText(args.taskId) },
          meta: { op: result.created ? 'node.add' : 'node.update' },
        })
        return json({
          ok: true,
          id: result.node.id,
          node: { id: result.node.id, kind: result.node.kind, value: result.node.value },
          created: result.created,
          edge: result.edge ? `${result.edge.from} -[${result.edge.type}]-> ${result.edge.to}` : null,
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_link',
    description: '在两个已有节点之间连一条关系边（子域、解析、端口、跳转、同源、凭证、利用链…）。',
    parameters: {
      type: 'object',
      properties: {
        from: { type: 'string', description: '起点节点 id 或 value' },
        to: { type: 'string', description: '终点节点 id 或 value' },
        type: { type: 'string', enum: EDGE_TYPES, description: '关系类型，默认 related' },
        label: { type: 'string', description: '边上的短标签' },
        note: { type: 'string', description: '证据 / 说明' },
        commandId: { type: 'string', description: '产出该关系的命令 id' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      required: ['from', 'to'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const result = await store.mutate(eng.id, (draft) => {
          const from = findNode(draft, args.from)
          if (from === undefined) throw new Error(`起点节点不存在：${args.from}。候选：${candidateHint(draft, args.from).join(' ; ')}`)
          const to = findNode(draft, args.to)
          if (to === undefined) throw new Error(`终点节点不存在：${args.to}。候选：${candidateHint(draft, args.to).join(' ; ')}`)
          return ensureEdge(draft, from.id, to.id, args.type, args)
        })
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: who(exec),
          title: `${result.created ? '图谱 +1 关系' : '图谱 ~ 关系'} ${result.edge.from} -[${result.edge.type}]-> ${result.edge.to}`,
          detail: asText(args.note) || '',
          refs: { commandId: asText(args.commandId) },
          meta: { op: result.created ? 'edge.add' : 'edge.update' },
        })
        return json({
          ok: true,
          edge: result.edge.id,
          created: result.created,
          text: `${result.edge.from} -[${result.edge.type}]-> ${result.edge.to}`,
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_vuln',
    description:
      '登记一个探测出的漏洞/风险项：挂到某个资产节点上，带等级、类型、位置、证据与命令 id。'
      + '同资产同标题同位置会合并更新，不会重复堆积。漏洞会出现在页面的「漏洞」列表与图上。',
    parameters: {
      type: 'object',
      properties: {
        node: { type: 'string', description: '关联资产节点 id 或 value' },
        title: { type: 'string', description: '漏洞标题，例如「Nginx 目录穿越 CVE-2021-23017」' },
        severity: { type: 'string', enum: SEVERITIES, description: 'critical/high/medium/low/info' },
        type: { type: 'string', description: '类型：sqli/xss/ssrf/rce/unauth/weak-password/info-leak…' },
        endpoint: { type: 'string', description: 'URL / 接口 / 主机:端口' },
        param: { type: 'string', description: '参数名' },
        payload: { type: 'string', description: '验证用 payload' },
        cvss: { type: 'string', description: 'CVSS 分数' },
        cve: { type: 'string', description: 'CVE / CNVD 编号' },
        description: { type: 'string', description: '描述与利用条件' },
        status: { type: 'string', enum: VULN_STATUSES, description: '默认 open' },
        commandId: { type: 'string', description: '验证该漏洞的命令 id' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      required: ['node', 'title'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const result = await store.mutate(eng.id, (draft) => addVuln(draft, args))
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: who(exec),
          title: `${result.created ? '图谱 +1 漏洞' : '图谱 ~ 漏洞'} [${result.vuln.severity}] ${shortText(result.vuln.title, 100)}`,
          detail: [asText(args.endpoint), asText(args.description)].filter((x) => x !== '').join('\n'),
          refs: { vulnIds: [result.vuln.id], nodeIds: [result.vuln.nodeId], commandId: asText(args.commandId) },
          meta: { op: result.created ? 'vuln.add' : 'vuln.update', input: [asText(args.endpoint), asText(args.payload)].filter((x) => x !== '').join(' · ') },
        })
        return json({
          ok: true,
          id: result.vuln.id,
          created: result.created,
          vuln: {
            id: result.vuln.id, nodeId: result.vuln.nodeId, title: result.vuln.title,
            severity: result.vuln.severity, status: result.vuln.status,
          },
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_update',
    description: '更新已有漏洞的状态/等级/描述（验证通过、误报、已修复），或给资产节点补备注/状态/标签。',
    parameters: {
      type: 'object',
      properties: {
        vuln: { type: 'string', description: '漏洞 id（形如 v12），或「节点 value + 标题关键字」' },
        node: { type: 'string', description: '要更新的资产节点 id 或 value' },
        status: { type: 'string', enum: VULN_STATUSES, description: '漏洞新状态（open/verified/false-positive/fixed）' },
        nodeStatus: { type: 'string', description: '资产节点新状态，例如 alive/dead/interesting/owned' },
        severity: { type: 'string', enum: SEVERITIES, description: '漏洞新等级' },
        note: { type: 'string', description: '资产节点备注' },
        clearNote: { type: 'boolean', description: '清空资产节点备注' },
        tags: { type: 'array', items: { type: 'string' }, description: '追加到资产节点的标签' },
        description: { type: 'string', description: '漏洞补充描述' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const result = await store.mutate(eng.id, (draft) => {
          const touched = { vuln: null, node: null }
          if (asText(args.vuln) !== '') {
            const wanted = asText(args.vuln)
            const vuln = draft.vulns.find((v) => v.id === wanted)
              || draft.vulns.find((v) => lower(v.title).includes(lower(wanted)))
            if (vuln === undefined) {
              throw new Error(`漏洞不存在：${wanted}。现有：${draft.vulns.slice(-10).map((v) => `${v.id}(${v.title})`).join(', ') || '无'}`)
            }
            if (VULN_STATUSES.includes(lower(args.status))) vuln.status = lower(args.status)
            if (SEVERITIES.includes(lower(args.severity))) vuln.severity = lower(args.severity)
            if (asText(args.description)) vuln.description = asText(args.description)
            vuln.updatedAt = nowIso()
            touched.vuln = vuln
          }
          if (asText(args.node) !== '') {
            const node = findNode(draft, args.node)
            if (node === undefined) throw new Error(`节点不存在：${args.node}。候选：${candidateHint(draft, args.node).join(' ; ')}`)
            if (args.clearNote === true) delete node.note
            else if (asText(args.note)) node.note = asText(args.note)
            if (asText(args.nodeStatus)) node.status = asText(args.nodeStatus)
            else if (asText(args.status) && !VULN_STATUSES.includes(lower(args.status))) node.status = asText(args.status)
            if (Array.isArray(args.tags)) {
              node.tags = Array.from(new Set([...(Array.isArray(node.tags) ? node.tags : []), ...asList(args.tags)]))
            }
            node.updatedAt = nowIso()
            touched.node = node
          }
          if (touched.vuln === null && touched.node === null) throw new Error('没有可更新的对象：至少给 vuln 或 node')
          return touched
        })
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: who(exec),
          title: result.vuln ? `漏洞更新 ${result.vuln.id}｜${shortText(result.vuln.title, 80)}` : `资产更新 ${result.node.id}｜${shortText(result.node.value, 80)}`,
          detail: asText(args.description) || asText(args.note) || '',
          refs: {
            vulnIds: result.vuln ? [result.vuln.id] : [],
            nodeIds: result.node ? [result.node.id] : [],
          },
          meta: { status: args.status || '', severity: args.severity || '', nodeStatus: args.nodeStatus || '' },
        })
        return json({
          ok: true,
          vuln: result.vuln ? { id: result.vuln.id, status: result.vuln.status, severity: result.vuln.severity } : null,
          node: result.node ? { id: result.node.id, value: result.node.value, status: result.node.status || null } : null,
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_ingest',
    description:
      '批量灌入一次扫描的成果（nmap/nuclei/subfinder/httpx 跑完后用它一次性写入）：'
      + 'nodes + edges + vulns 三个数组，减少来回调用。',
    parameters: {
      type: 'object',
      properties: {
        nodes: {
          type: 'array',
          description: '资产数组，元素同 recon_asset 参数（value 必填；可用 parent 指向上文节点 value）',
          items: { type: 'object' },
        },
        edges: {
          type: 'array',
          description: '关系数组，元素：{ from, to, type, label?, note? }',
          items: { type: 'object' },
        },
        vulns: {
          type: 'array',
          description: '漏洞数组，元素同 recon_vuln 参数（node + title 必填）',
          items: { type: 'object' },
        },
        commandId: { type: 'string', description: '产出这批数据的命令 id' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const result = await store.mutate(eng.id, (draft) => {
          const report = { nodes: { created: 0, merged: 0, failed: [] }, edges: { created: 0, merged: 0, failed: [] }, vulns: { created: 0, merged: 0, failed: [] } }
          for (const row of Array.isArray(args.nodes) ? args.nodes : []) {
            try {
              const { node, created } = upsertNode(draft, { commandId: args.commandId, ...row, kind: row.kind || guessKind(row.value) })
              if (created) report.nodes.created += 1
              else report.nodes.merged += 1
              if (asText(row.parent) !== '') {
                const parent = findNode(draft, row.parent)
                if (parent !== undefined) ensureEdge(draft, parent.id, node.id, asText(row.edge, 'discovered_from'), { commandId: args.commandId })
                else report.nodes.failed.push(`${row.value}: 父节点不存在 ${row.parent}`)
              }
            } catch (error) {
              report.nodes.failed.push(`${row && row.value}: ${error.message}`)
            }
          }
          for (const row of Array.isArray(args.edges) ? args.edges : []) {
            try {
              const from = findNode(draft, row.from)
              const to = findNode(draft, row.to)
              if (from === undefined || to === undefined) throw new Error(`端点不存在（${row.from} → ${row.to}）`)
              const { created } = ensureEdge(draft, from.id, to.id, row.type, { commandId: args.commandId, ...row })
              if (created) report.edges.created += 1
              else report.edges.merged += 1
            } catch (error) {
              report.edges.failed.push(`${row && row.from}->${row && row.to}: ${error.message}`)
            }
          }
          for (const row of Array.isArray(args.vulns) ? args.vulns : []) {
            try {
              const { created } = addVuln(draft, { commandId: args.commandId, ...row })
              if (created) report.vulns.created += 1
              else report.vulns.merged += 1
            } catch (error) {
              report.vulns.failed.push(`${row && row.title}: ${error.message}`)
            }
          }
          return report
        })
        const fresh = await store.load(eng.id)
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: who(exec),
          title: `批量入图：+${result.nodes.created} 资产 / +${result.edges.created} 关系 / +${result.vulns.created} 漏洞`,
          detail: asText(args.note) || '',
          refs: { commandId: asText(args.commandId) },
          meta: { report: result },
        })
        return json({ ok: true, report: result, stats: statsOf(fresh) })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_run',
    description:
      '在本机执行一条 shell 命令（Linux/macOS 走 bash，Windows 走 cmd.exe，可用 DSH_RECON_SHELL 指定其它 shell），'
      + '完整 stdout+stderr 落盘留痕，元信息写进图谱的命令日志；页面上可直接看每条命令的原始输出。'
      + '命令会挂到指定节点（可选），形成「哪条命令发现了什么」的证据链。长扫描请适当调大 timeoutMs。',
    parameters: {
      type: 'object',
      properties: {
        command: { type: 'string', description: '要执行的命令（Linux 走 bash -lc，Windows 走 cmd /d /s /c；可用管道/重定向）' },
        purpose: { type: 'string', description: '这条命令要回答什么问题（写清意图，方便复盘）' },
        node: { type: 'string', description: '把本次执行挂到该资产节点（id 或 value，可选）' },
        timeoutMs: { type: 'number', description: '超时毫秒，默认 300000（5 分钟）' },
        cwd: { type: 'string', description: '工作目录，默认靶标 work 目录' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      required: ['command'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const command = asText(args.command)
        if (command === '') throw new Error('缺少参数 command')
        /* 执行层铁律：驾驶舱（总指挥）不许自己跑扫描/爆破/验证类命令，必须派给专业 agent */
        {
          const info = sessionInfoOf(exec) || {}
          const isCommanderSession = typeof info.id === 'string' && COMMANDER_SESSIONS.has(info.id)
          const blocked = /(^|[\s;|&(])(nmap|masscan|rustscan|naabu|nuclei|ffuf|feroxbuster|gobuster|dirb|dirsearch|sqlmap|nikto|wpscan|hydra|medusa|john|hashcat|responder|netexec|crackmapexec|subfinder|amass|assetfinder|httpx|httprobe|katana|gau|waybackurls)\b/.exec(command)
          if (isCommanderSession && blocked !== null) {
            return json({
              ok: false,
              error: `指挥席不许自己跑「${blocked[2]}」：这是执行类命令，必须派给专业 agent`,
              how_to_delegate: {
                tool: 'recon_squad',
                action: 'spawn',
                example: {
                  action: 'spawn',
                  role: 'scout',
                  name: '端口测绘手',
                  skills: ['nmap-quick'],
                  prompt: '只做端口与服务识别，产出必须带 commandId；不做漏洞验证。',
                  task: `执行并分析：${shortText(command, 160)}；结果用 recon_ingest 上图，再一句话汇报。`,
                },
              },
              note: '只有「读已有产物」的核对类命令（cat/ls/head/tail/grep/wc/jq/awk/sed）才允许你自己跑。',
            })
          }
        }
        const eng = await resolveEngagement(exec, args.engagement)
        const info = sessionInfoOf(exec)
        const workRoot = await ensureDir(join(store.workDir, eng.id))
        /* 队员有自己的工位：默认落在工位里，别写回共享目录 */
        let fallbackCwd = workRoot
        try {
          const actor = info && typeof info.id === 'string' ? squad.memberBySessionId(info.id) : undefined
          if (actor !== undefined && asText(actor.station) !== '') {
            fallbackCwd = await ensureDir(actor.station)
          }
        } catch { /* 取不到就用共享目录 */ }
        const cwd = asText(args.cwd) ? resolve(asText(args.cwd)) : fallbackCwd
        const timeoutMs = Number.isFinite(args.timeoutMs) && args.timeoutMs > 0
          ? Math.min(args.timeoutMs, 6 * 60 * 60 * 1000)
          : cfg.defaultTimeoutMs
        const cmdId = `c${(eng.commands.length + 1).toString()}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
        const nodeHit = asText(args.node) !== '' ? findNode(eng, args.node) : undefined
        if (asText(args.node) !== '' && nodeHit === undefined) {
          throw new Error(`要关联的节点不存在：${args.node}。候选：${candidateHint(eng, args.node).join(' ; ')}`)
        }
        const started = nowIso()
        /* 测绘密钥 → 环境变量：nmap/nuclei/curl 之外，fofa/github 的 CLI 也能直接读到 */
        const keyEnv = configStore !== undefined && configStore !== null ? configStore.keyEnv() : {}
        const envKeys = Object.keys(keyEnv)
        const outcome = await runShell(command, {
          cwd,
          timeoutMs,
          signal: exec.signal,
          env: { ...process.env, ...keyEnv },
        })
        const logDir = await ensureDir(join(store.cmdDir, eng.id))
        const outputPath = join(logDir, `${cmdId}.log`)
        const header = [
          `# command : ${command}`,
          `# purpose : ${asText(args.purpose, '-')}`,
          `# cwd     : ${cwd}`,
          `# started : ${started}`,
          `# exit    : ${outcome.exitCode === null ? 'null' : outcome.exitCode}${outcome.timedOut ? ' (timeout)' : ''}`
            + `${outcome.aborted ? ' (aborted)' : ''}${outcome.signal ? ` signal=${outcome.signal}` : ''}`,
          `# duration: ${outcome.durationMs} ms`,
          '',
          '## stdout',
          outcome.stdout,
          '',
          '## stderr',
          outcome.stderr,
          '',
        ].join('\n')
        await writeFile(outputPath, header, 'utf8')
        const record = await store.mutate(eng.id, (draft) => {
          const row = {
            id: cmdId,
            command,
            purpose: asText(args.purpose) || undefined,
            cwd,
            startedAt: started,
            exitCode: outcome.exitCode,
            durationMs: outcome.durationMs,
            timedOut: outcome.timedOut,
            aborted: Boolean(outcome.aborted),
            stdoutBytes: outcome.outBytes,
            stderrBytes: outcome.errBytes,
            truncated: outcome.truncated,
            outputPath,
            source: 'recon_run',
            envKeys,
            sessionId: info.id,
            nodeIds: nodeHit !== undefined ? [nodeHit.id] : [],
            tail: outcome.stdout.slice(-4000),
            stderrTail: outcome.stderr.slice(-2000),
          }
          draft.commands.push(row)
          if (nodeHit !== undefined) {
            nodeHit.updatedAt = nowIso()
            if (nodeHit.commandId === undefined) nodeHit.commandId = cmdId
          }
          return row
        })
        void trace?.push?.(eng.id, {
          kind: 'command',
          actor: who(exec),
          title: `${outcome.exitCode === 0 ? '✓' : '✗'} ${shortText(command, 120)}`,
          detail: asText(args.purpose),
          refs: { commandId: record.id, nodeIds: record.nodeIds || [] },
          meta: {
            exitCode: outcome.exitCode,
            durationMs: outcome.durationMs,
            source: 'recon_run',
            input: shortText(command, 600),
            out: shortText((outcome.stdout || '') + (outcome.stderr ? `\n[stderr]\n${outcome.stderr}` : ''), 600),
          },
        })
        const budget = Math.max(2000, Math.floor(cfg.maxOutputChars / 2))
        const outView = headTail(outcome.stdout, budget)
        const errView = headTail(outcome.stderr, Math.min(4000, budget))
        return json({
          ok: true,
          commandId: record.id,
          exitCode: outcome.exitCode,
          timedOut: outcome.timedOut,
          durationMs: outcome.durationMs,
          cwd,
          outputPath,
          stdout_chars: outcome.stdout.length,
          stderr_chars: outcome.stderr.length,
          clipped: outView.clipped || errView.clipped,
          stdout: outView.body,
          stderr: errView.body,
          hint: '把命令里发现的资产立即用 recon_asset / recon_ingest 落图，证据用 commandId 关联。',
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_view',
    description: '查看当前靶标的图谱（节点/关系/漏洞/最近命令）或某个节点的详情，用来决定下一步打哪儿。',
    parameters: {
      type: 'object',
      properties: {
        engagement: { type: 'string', description: '靶标 id 或名称' },
        node: { type: 'string', description: '只看这个节点及其邻居（id 或 value）' },
        limit: { type: 'number', description: '最多返回多少条，默认 400' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        if (asText(args.node) !== '') {
          const node = findNode(eng, args.node)
          if (node === undefined) {
            return json({ ok: false, error: `节点不存在：${args.node}`, candidates: candidateHint(eng, args.node) })
          }
          const neighbors = eng.edges
            .filter((e) => e.from === node.id || e.to === node.id)
            .map((e) => {
              const otherId = e.from === node.id ? e.to : e.from
              const other = eng.nodes.find((n) => n.id === otherId)
              return `${e.type} ${e.from === node.id ? '→' : '←'} ${other ? `${other.id} ${other.value}` : otherId}`
            })
          const vulns = eng.vulns.filter((v) => v.nodeId === node.id)
          const commands = eng.commands.filter((c) => (c.nodeIds || []).includes(node.id))
          return json({
            ok: true,
            node: nodeView(node, eng),
            neighbors,
            vulns,
            commands: commands.map((c) => ({ id: c.id, command: c.command, exitCode: c.exitCode })),
          })
        }
        return json({ ok: true, ...graphSummary(eng, { limit: args.limit }) })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })

  register({
    name: 'recon_nday',
    description:
      '按指纹 / 产品 / 版本检索历史 Nday 漏洞（只查 Exploit-DB 与 NVD 公开库，不对目标发包）。'
      + '信息收集手专用：测绘中探测到服务/中间件/产品/版本指纹（如 “Apache 2.4.49”“Spring Boot 2.3”“致远OA A8”）后，主动用它找 CVE / EDB 与受影响版本，不必等总指挥指派；'
      + '候选先写进 recon_board（kind=hypothesis，附来源），交 Web/QA 实测后再 recon_vuln。',
    parameters: {
      type: 'object',
      properties: {
        fingerprint: { type: 'string', description: '指纹 / 产品 + 版本，例如 “Apache 2.4.49”“Spring Boot 2.3”“致远OA A8”' },
        limit: { type: 'number', description: '每个来源最多返回多少条，默认 8，最大 20' },
      },
      required: ['fingerprint'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args) {
      try {
        const fingerprint = asText(args.fingerprint).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160)
        if (fingerprint.length < 2) throw new Error('缺少有效指纹：请给产品/版本/中间件特征，例如 “Apache 2.4.49”；只查历史库，不对目标发包')
        const limit = Number.isFinite(args.limit) ? Math.min(20, Math.max(1, Math.round(args.limit))) : 8
        const [exploitdb, nvd] = await Promise.all([
          searchExploitDb(fingerprint, limit),
          searchNvd(fingerprint, limit),
        ])
        const candidates = [...exploitdb.candidates, ...nvd.candidates].slice(0, limit * 2)
        return json({
          ok: true,
          fingerprint,
          sources: {
            exploitdb: { source: 'exploitdb', candidates: exploitdb.candidates.length, error: exploitdb.error || '' },
            nvd: { source: 'nvd', candidates: nvd.candidates.length, error: nvd.error || '' },
          },
          candidates,
          hint: '只查了公开历史漏洞库，没有对目标发包；候选必须实测后才 recon_vuln，先写看板 kind=hypothesis 并附来源。',
        })
      } catch (error) {
        return toolFailure(error)
      }
    },
  })
}

function guessKind(value) {
  const text = lower(value)
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(text)) return text.includes('/') ? 'cidr' : 'ip'
  if (/^https?:\/\//.test(text)) return 'url'
  if (/^\d{1,5}\/\w+$/.test(text)) return 'port'
  if (/^\d{1,5}$/.test(text)) return 'port'
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(text)) return text.split('.').length > 2 ? 'subdomain' : 'domain'
  if (/^[^\s@]+@[^\s@]+\.[a-z]{2,}$/.test(text)) return 'account'
  return 'note'
}

/* ────────────────────────── 驾驶舱 AI ────────────────────────── */

function shortText(value, max) {
  const text = String(value === undefined || value === null ? '' : value)
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

/** 模型档位 → agentOptions：dsh / 未配置档位都回落到 DSH 默认模型。 */
function modelSelectionFor(ctx, configStore, tier) {
  const config = configStore.get()
  const models = config.models || {}
  const wanted = MODEL_TIERS.includes(asText(tier))
    ? asText(tier)
    : (asText(tier) === 'dsh' ? 'dsh' : 'deep')
  if (wanted !== 'dsh') {
    const pick = models[wanted] || {}
    if (asText(pick.provider) !== '' && asText(pick.model) !== '') {
      const selection = { provider: asText(pick.provider), model: asText(pick.model) }
      const reasoning = asText(pick.reasoning)
      if (THINKING_LEVELS.includes(reasoning)) selection.reasoningEffort = reasoning
      return selection
    }
  }
  const fallback = ctx.get('agentDefaultModel')
  if (fallback !== undefined && fallback !== null && typeof fallback.currentSelection === 'function') {
    const selection = fallback.currentSelection()
    if (selection !== undefined && selection !== null && asText(selection.provider) !== '') return { ...selection }
  }
  return {}
}

/** 把一条消息的 content blocks 拼成纯文本（assistant/message 与 tool/result 共用）。 */
function blocksText(blocks) {
  if (!Array.isArray(blocks)) return ''
  const out = []
  for (const block of blocks) {
    if (block === null || typeof block !== 'object') continue
    if (typeof block.text === 'string') out.push(block.text)
    else if (block.type === 'tool-call') out.push(`[tool] ${block.name || ''}`)
  }
  return out.join('\n').trim()
}

class Cockpit {
  constructor(ctx, store, cfg, configStore, hub) {
    this.ctx = ctx
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.sessions = new Map()
    this.transcripts = new Map()
    this.saveTimers = new Map()
    this.counter = 0
    this.usage = new Map()
    this.lastNudge = new Map()
    this.pendingNudges = new Map()
    this.ensuring = new Map()
  }

  /** 项目被删除时丢掉它的驾驶舱会话与缓存，避免 session 泄漏 */
  async forget(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state !== undefined) {
      try { await state.handle?.dispose?.() } catch { /* 已释放 */ }
      this.sessions.delete(engagementId)
    }
    this.transcripts?.delete?.(engagementId)
    this.usage?.delete?.(engagementId)
    this.lastNudge?.delete?.(engagementId)
    this.pendingNudges?.delete?.(engagementId)
    this.promptCache?.delete?.(engagementId)
    this.ensuring?.delete?.(engagementId)
    const saveTimer = this.saveTimers?.get?.(engagementId)
    if (saveTimer !== undefined) clearTimeout(saveTimer)
    this.saveTimers?.delete?.(engagementId)
    /* 驾驶舱 session id 形如 recon-<eng>-<ts>-<n>：按前缀扫掉，别只删靶标 id（那永远删不到） */
    const commanderPrefix = `recon-${String(engagementId).replace(/[^a-zA-Z0-9]/g, '')}-`
    for (const id of Array.from(COMMANDER_SESSIONS)) {
      if (id.startsWith(commanderPrefix)) COMMANDER_SESSIONS.delete(id)
    }
  }

  chatDir() {
    return join(this.cfg.root, 'chat')
  }

  chatFile(engagementId) {
    return join(this.chatDir(), `${engagementId}.json`)
  }

  transcriptOf(engagementId) {
    if (!this.transcripts.has(engagementId)) this.transcripts.set(engagementId, [])
    return this.transcripts.get(engagementId)
  }

  async loadTranscript(engagementId) {
    if (this.transcripts.has(engagementId)) return this.transcripts.get(engagementId)
    let list = []
    try {
      const raw = JSON.parse(await readFile(this.chatFile(engagementId), 'utf8'))
      if (Array.isArray(raw)) list = raw
    } catch { /* 没有历史 */ }
    this.transcripts.set(engagementId, list)
    return list
  }

  scheduleSave(engagementId) {
    clearTimeout(this.saveTimers.get(engagementId))
    this.saveTimers.set(engagementId, setTimeout(() => {
      const list = this.transcriptOf(engagementId)
      ensureDir(this.chatDir())
        .then(() => writeFile(this.chatFile(engagementId), `${JSON.stringify(list, null, 2)}\n`, 'utf8'))
        .catch(() => { /* 会话记录写失败不影响对话 */ })
    }, 500))
  }

  pushMessage(engagementId, message) {
    const list = this.transcriptOf(engagementId)
    list.push(message)
    this.scheduleSave(engagementId)
  }

  /** 三档模型 → 真实 provider/model；dsh / 空配置回落到 Harness 默认选择。 */
  modelFor(tier) {
    return modelSelectionFor(this.ctx, this.configStore, tier)
  }

  /** 驾驶舱 AI 的系统提示：角色 + 靶标现场 + 记忆 + 密钥状态 + 技能。 */
  async cockpitPrompt(engagementId) {
    const config = this.configStore.get()
    const lines = []
    lines.push('## 你在「狩猎 · 驾驶舱」里工作')
    lines.push('')
    lines.push('## 【铁律】先派活，再动手')
    lines.push('- 你是指挥官，不是执行者。执行类工作（扫端口、跑 nuclei、抓页面、拆 JS、试注入、横向）一律 `recon_squad spawn` 派给专业角色；')
    lines.push('- 你自己执行 `recon_run` 的**唯一豁免**：只读核对已有产物（cat/ls/head/grep/jq/curl 读日志或接口）。');
    lines.push('  端口扫描、指纹识别、目录爆破、漏洞验证、抓页面、拆 JS、横向移动——这些一律派活，不许自己跑；')
    lines.push('- 违规信号：你自己连续跑第 2 条非核对命令。出现就立刻停手，把剩下的事 spawn 出去；')
    lines.push('- 派活时把要求写死：`name`（代号）、`prompt`（专属指令：目标/边界/产出/禁止事项）、`skills`（要加载哪些技能）、');
    lines.push('  `asRole`+`roleName`+`rolePrompt`（需要新兵种时现开，如 jsre/fuzzer/reporter/db-exploiter）；')
    lines.push('- 派完先回一句话「已派 X（代号）去做 Y」，然后继续推进下一步，不要自己顶上去干。')
    lines.push('- 成员用 `recon_group request` 报告卡点时，你要判断是否需要建立小组：需要就用 `recon_squad action=group`，把专业角色、模型档位、skills、MCP 一并指定；小组整体只算一个并发，组内由成员用 `recon_group ask` 串行协作。')
    lines.push('')
    lines.push('## 谁出方案：参谋，不是你')
    lines.push('- 「怎么打、先打谁、优先级排序、绕过思路、下一步路线」这类**方案**，一律 `recon_squad task` 派给参谋（role=staff）出；')
    lines.push('- 你的活是：把参谋的方案拆成可验收的任务 → 派给执行角色 → 收结果 → 交用户；方案本身不由你拍；')
    lines.push('- 参谋是常设席位（每场一个、自动补位），不在岗时等补位，不要尝试 recruit；把问题丢给参谋，别自己顶上；')
    lines.push('- 你只对「派谁、什么时候派、验收过没过」负责；对「这仗该怎么打」负责的是参谋。')
    /* 驾驶舱总指挥就是常设席位的总指挥：共用 core.commander 的人设与提示词 */
    const commanderRole = this.squad !== undefined && this.squad !== null
      ? this.squad.coreRoles().find((item) => item.id === 'commander')
      : DEFAULT_CORE_ROLES.find((item) => item.id === 'commander')
    lines.push(`角色：${commanderRole !== undefined ? asText(commanderRole.name, '总指挥') : '总指挥'}（最高统领）`)
    if (commanderRole !== undefined && asText(commanderRole.prompt) !== '') {
      lines.push('')
      lines.push(commanderRole.prompt)
    }
    const eng = await this.store.load(engagementId)
    if (eng !== undefined) {
      const stats = statsOf(eng)
      lines.push('')
      lines.push(`当前靶标：${eng.name}（id ${eng.id}）`)
      if (eng.scope.length > 0) lines.push(`授权范围：${eng.scope.join(', ')}`)
      lines.push(`图谱现状：节点 ${stats.nodes} · 关系 ${stats.edges} · 漏洞 ${stats.vulns} · 命令 ${stats.commands}`)
      const recent = eng.nodes.filter((node) => node.archived !== true).slice(-30).map((node) => `${node.kind}:${node.value}`)
      if (recent.length > 0) lines.push(`已收录资产（尾 30）：${recent.join(' , ')}`)
      const activeNodeIds = new Set(eng.nodes.filter((node) => node.archived !== true).map((node) => node.id))
      const openVulns = eng.vulns.filter((v) => activeNodeIds.has(v.nodeId) && v.status !== 'false-positive' && v.status !== 'fixed').slice(-10)
      if (openVulns.length > 0) {
        lines.push(`未闭环漏洞：${openVulns.map((v) => `${v.severity}/${v.title}`).join(' ; ')}`)
      }
    }
    /* 完整看板：所有 agent 必须看到全部文字，用户发言全文且无上限 */
    try {
      const boardText = await boardPromptText(this.board, engagementId, { actor: { key: 'lead' } })
      if (boardText !== '') {
        lines.push('')
        lines.push(boardText)
      }
    } catch { /* 取不到就跳过 */ }
    try {
      const taskRows = this.tasks === undefined || this.tasks === null ? [] : await this.tasks.list(engagementId, 80)
      const open = taskRows.filter((row) => row.status !== 'passed' && row.status !== 'failed')
      if (open.length > 0) {
        lines.push('')
        lines.push('未闭环任务：')
        for (const row of open.slice(-12)) {
          lines.push(`- ${row.id} [${row.role}/${row.status}] ${row.title}｜验收：${row.acceptance || '-'}`)
        }
      }
      const failed = taskRows.filter((row) => row.status === 'failed')
      if (failed.length > 0) {
        lines.push(`有 ${failed.length} 条任务被验收驳回，优先处理返工。`)
      }
    } catch { /* 任务读取失败不影响对话 */ }
    const memory = Array.isArray(config.memory) ? config.memory : []
    if (memory.length > 0) {
      lines.push('')
      lines.push('## 长期记忆（全局强制阅读，全部条目）')
      for (const item of memory) {
        const entry = memoryEntryOf(item)
        if (entry.content !== '') lines.push(`- [${entry.category || 'other'}] ${entry.title}：${entry.content}`)
      }
    }
    const enabledSkills = Array.isArray(config.skills && config.skills.enabled) ? config.skills.enabled : []
    if (enabledSkills.length > 0) lines.push(`\n可用技能（需要时用 recon_skill action=load 读取完整技能；若会话另有 skill 工具也可用）：${enabledSkills.join(', ')}`)
    const presence = this.configStore.keyPresence()
    const ready = Object.entries(presence).filter(([, ok]) => ok).map(([key]) => key)
    const missing = Object.entries(presence).filter(([, ok]) => !ok).map(([key]) => key)
    lines.push(`\n测绘密钥：已配置 ${ready.length > 0 ? ready.join('/') : '（无）'}；未配置 ${missing.length > 0 ? missing.join('/') : '（无）'}`)
    lines.push('密钥已注入命令环境（如 FOFA_KEY / GITHUB_TOKEN / SHODAN_API_KEY），recon_run 里可直接引用，不要在回答里回显明文。')
    lines.push('')
    lines.push('你也可以当指挥：`recon_squad` 派独立 Agent 并行推进（不用等），`recon_board` 读写团队看板，`recon_browser` 做真实页面操作。')
    lines.push('')
    lines.push('组织编制（谁干什么）：')
    const orgRoles = this.squad !== undefined && this.squad !== null
      ? [...this.squad.coreRoles(), ...this.squad.roles()]
      : this.roles()
    for (const role of orgRoles) {
      const isCore = role.core === true || CORE_ROLES.has(role.id)
      const roleSkills = asList(role.skills).filter((name) => asText(name) !== '')
      const roleMcp = asMcpList(role.mcp).filter((row) => row.enabled !== false).map((row) => row.name)
      const detail = [
        roleSkills.length > 0 ? `技能：${roleSkills.join(', ')}` : '',
        roleMcp.length > 0 ? `MCP：${roleMcp.join(', ')}` : '',
      ].filter((line) => line !== '').join('；')
      lines.push(`- ${role.name}（${role.id}，${role.tier}）${isCore ? '（常设席位，每靶标各一个，不可召唤）' : (role.reportsTo ? `→ 向 ${role.reportsTo} 汇报` : '（最高指挥）')}${detail !== '' ? `｜${detail}` : ''}`)
    }
    lines.push('职责边界：Web 页面操作归 web 手；JS/APK/EXE 逆向归 reverser；内网横向/隧道归 intranet；')
    lines.push('漏洞真伪实测与任务达标判定归 qa；方案与优先级归 staff；commander 只调度不亲自扫。')
    lines.push('指纹 Nday：把指纹交给信息收集手（scout），用 `recon_nday` 查 Exploit-DB/NVD 历史漏洞；只查库，不对目标发包，候选先写看板。')
    lines.push('强制工作闭环：commander 先让 staff 把整体方案写进看板 kind=hypothesis → commander 读方案后用 `recon_task mission set` 登记目标 →')
    lines.push('`recon_task create` 拆成可验收任务 → 给每个成员指定模型档位/skills/MCP/上下文并派活 → 成员完成主动回报 →')
    lines.push('commander 安排 qa 核查上一个角色的命令/范围/证据/结果 → qa 只能 accept/reject；reject 自动生成返工任务回到 commander →')
    lines.push('全部任务有 verifiedBy=qa 后，qa 提交最终验收报告 → commander 复核并 `mission close` 宣布结束，系统停止并回收非核心队员。')
    lines.push('需要临时兵种（写工具、出报告、做钓鱼页）用 `recon_org recruit` 传新 role 与 rolePrompt 即可开新角色。')
    lines.push('你还能改系统配置：')
    lines.push('- 用户说「每发现一个新资产就让漏洞猎手去探测」→ `recon_watch` add, on=node.created, role=hunter（kinds 默认 subdomain/ip/url/service/endpoint）')
    lines.push('- 用户说「新漏洞自动用浏览器验证」→ `recon_watch` add, on=vuln.created, role=browser, tier=vision')
    lines.push('- 用户说「每 30 分钟巡检一次」→ `recon_watch` add, on=interval, everyMs=1800000, role=scout')
    lines.push('- 用户说「把 FOFA key 配成 xxx」→ `recon_config` set, section=keys, values={fofa:"xxx"}（其它 key 同理：github/shodan/virustotal/quake/…）')
    lines.push('- 用户说「高复杂模型换成 …」→ `recon_config` set, section=models, values={deep:{provider,model}}')
    lines.push('配完用一句话确认结果（不要把密钥明文回显给用户）。')
    lines.push('工作方式：用户在这里用一句话下指令，你负责拆解、派活、验收和收结果；')
    lines.push('只有读日志/看图谱这类只读核对可以自己用 recon_run，扫描、爆破、验证、抓页面一律派给队员；')
    lines.push('派活时写清 purpose、边界和证据要求；不要反问“要不要继续”，把当前能推进的一步做完再汇报。')
    return safePromptText(withCommonPrompt(this.configStore.get(), lines.join('\n')))
  }

  async ensure(engagementId) {
    const existing = this.sessions.get(engagementId)
    if (existing !== undefined && existing.agent !== null) return existing
    const pending = this.ensuring.get(engagementId)
    if (pending !== undefined) return pending
    const promise = this.ensureInner(engagementId).finally(() => { this.ensuring.delete(engagementId) })
    this.ensuring.set(engagementId, promise)
    return promise
  }

  async ensureInner(engagementId) {
    const agents = this.ctx.get('agents')
    if (agents === undefined || agents === null) throw new Error('agents 服务不可用：当前 profile 没有 agent 驱动')
    const eng = await this.store.load(engagementId)
    if (eng === undefined) throw new Error(`靶标不存在：${engagementId}`)
    const workDir = await ensureDir(join(this.store.workDir, engagementId))
    const tier = MODEL_TIERS.includes(asText(this.configStore.get().chat && this.configStore.get().chat.tier))
      ? asText(this.configStore.get().chat.tier)
      : 'deep'
    const selection = this.modelFor(tier)
    this.counter += 1
    const sessionId = `recon-${String(engagementId).replace(/[^a-zA-Z0-9]/g, '')}-${Date.now().toString(36)}-${this.counter}`
    const state = {
      engagementId,
      sessionId,
      tier,
      agent: null,
      handle: null,
      busy: false,
      buffers: { text: '', reasoning: '' },
      turnText: '',
      turnReasoning: '',
      turnModel: undefined,
      lastSegment: null,
    }
    const cockpit = this
    const setup = (agentCtx) => {
      try {
        const prompt = typeof agentCtx.get === 'function' ? agentCtx.get('systemPrompt') : undefined
        if (prompt !== undefined && prompt !== null && typeof prompt.section === 'function') {
          prompt.section({
            name: 'recon-cockpit',
            order: 4901,
            text: () => {
              const cached = cockpit.cockpitPromptSync(engagementId)
              return cached
            },
          })
        }
      } catch { /* 提示词注入失败不影响对话 */ }
    }
    this.promptCache = this.promptCache || new Map()
    await this.refreshPrompt(engagementId)
    const handle = await agents.create({
      sessionId,
      meta: { cwd: workDir },
      agentOptions: selection,
      setup,
    })
    state.agent = handle.agent
    COMMANDER_SESSIONS.add(sessionId)
    state.handle = handle
    this.sessions.set(engagementId, state)
    this.hub.broadcast({ type: 'chat.status', engagementId, status: 'idle', sessionId })
    return state
  }

  /** 组织编制（与 Squad 同一份配置） */
  roles() {
    const configured = this.configStore.get().roles
    return configured && Array.isArray(configured.squad) && configured.squad.length > 0 ? configured.squad : DEFAULT_ROLES
  }

  cockpitPromptSync(engagementId) {
    return (this.promptCache && this.promptCache.get(engagementId)) || '## 狩猎驾驶舱\n直接调用 recon_* 工具写图。'
  }

  async refreshPrompt(engagementId) {
    this.promptCache = this.promptCache || new Map()
    try {
      this.promptCache.set(engagementId, await this.cockpitPrompt(engagementId))
    } catch { /* 现场信息取不到就用兜底 */ }
  }

  stateOf(engagementId) {
    const state = this.sessions.get(engagementId)
    return {
      usage: this.usage.get(engagementId) || { input: 0, output: 0, total: 0, turns: 0 },
      engagementId,
      sessionId: state ? state.sessionId : null,
      tier: state ? state.tier : asText(this.configStore.get().chat.tier, 'deep'),
      busy: state ? state.busy : false,
      running: state ? state.agent !== null : false,
    }
  }

  async send({ engagement, text, tier, images: arguments0Images, attachments: arguments0Files, interrupt: rawInterrupt }) {
    const engagementId = await this.resolveEngagementId(engagement)
    const message = asText(text)
    if (message === '') throw new Error('消息不能为空')
    const wantsVision = Array.isArray(arguments0Images) && arguments0Images.length > 0
    if (wantsVision) {
      const visionSelection = this.modelFor('vision')
      if (asText(visionSelection.provider) === '' || asText(visionSelection.model) === '') {
        throw new Error('视觉档位未配置：先进「控制台 → 模型」给 vision 档位选一个支持图片的模型，再贴图')
      }
    }
    const state = await this.ensure(engagementId)
    /* 插入发送：先打断正在跑的这一轮，再把新消息插进去（对应 DSH 的 interrupt 模式） */
    const interrupt = rawInterrupt === true
    if (interrupt && state.agent !== null) {
      try { state.agent.cancel({ kind: 'user', reason: 'interrupt' }) } catch { /* 没在跑 */ }
      this.hub.broadcast({ type: 'chat.status', engagementId, status: 'idle' })
    }
    const tierArg = wantsVision ? 'vision' : asText(tier)
    const wantedTier = MODEL_TIERS.includes(tierArg) ? tierArg : state.tier
    if (wantedTier !== state.tier) {
      try {
        state.agent.model.select(this.modelFor(wantedTier))
        state.tier = wantedTier
        await this.configStore.patch({ chat: { tier: wantedTier } })
      } catch { /* 切模型失败就按原模型继续 */ }
    }
    await this.refreshPrompt(engagementId)
    void this.trace?.push?.(engagementId, {
      kind: 'chat',
      actor: { role: 'user', name: '你（指挥席）' },
      title: '你对总指挥发话',
      detail: message,
      meta: { tier: wantedTier, images: Array.isArray(arguments0Images) ? arguments0Images.length : 0 },
    })
    state.buffers = { text: '', reasoning: '' }
    /* 先把图片落到 attachment 服务，再发消息：content 决定模型实际看到什么 */
    const content = [{ type: 'text', text: message }]
    const images = Array.isArray(arguments0Images) ? arguments0Images : []
    if (images.length > 0) {
      const attachments = this.ctx.get('attachments')
      if (attachments !== undefined && attachments !== null && typeof attachments.saveImage === 'function') {
        for (const image of images.slice(0, 4)) {
          if (image === null || typeof image !== 'object' || typeof image.base64 !== 'string') continue
          const mediaType = ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(image.mediaType)
            ? image.mediaType
            : 'image/png'
          try {
            const ref = await attachments.saveImage({
              data: Buffer.from(image.base64, 'base64'),
              mediaType,
              name: asText(image.name) || undefined,
            })
            content.push({ type: 'image', attachment: ref })
          } catch { /* 单张图失败跳过 */ }
        }
      }
    }
    /* 任意文件附件：只认 uploads 目录内的路径，名字进消息正文，AI 可以直接拿路径去处理 */
    const files = []
    for (const file of Array.isArray(arguments0Files) ? arguments0Files.slice(0, 12) : []) {
      if (file === null || typeof file !== 'object') continue
      const path = asText(file.path)
      if (path === '') continue
      const uploadsRoot = resolve(this.cfg.root, 'uploads', engagementId)
      const resolved = resolve(path)
      if (!resolved.startsWith(`${uploadsRoot}${sep}`)) continue
      files.push({ path: resolved, name: asText(file.name, resolved.split(sep).pop()), bytes: Number.isFinite(file.bytes) ? file.bytes : 0 })
    }
    if (files.length > 0) {
      content[0] = {
        type: 'text',
        text: `${message}\n\n【用户上传的附件 · 直接用 shell/工具处理这些本地路径】\n${files
          .map((file) => `- ${file.name} (${file.bytes} bytes) → ${file.path}`)
          .join('\n')}`,
      }
    }
    const record = {
      id: `u_${Date.now().toString(36)}`,
      role: 'user',
      text: message,
      ts: Date.now(),
      tier: state.tier,
      images: content.filter((block) => block.type === 'image').length,
      attachments: files,
    }
    this.pushMessage(engagementId, record)
    this.hub.broadcast({ type: 'chat.user', engagementId, message: record })
    state.agent.followup({ id: record.id, role: 'user', content, source: { kind: 'user' } })
    this.hub.broadcast({ type: 'chat.status', engagementId, status: 'running' })
    return { ok: true, engagementId, sessionId: state.sessionId, tier: state.tier }
  }

  /**
   * 主动通知指挥席。默认只在有返工/指挥官待办时催办；
   * options.always=true 允许成员完成回报等场景；
   * options.final=true 是 QA 全部验收后的强制收尾通知，必须把指挥席叫醒。
   */
  async nudge(engagementId, reason, options = {}) {
    let state = this.sessions.get(engagementId)
    if ((state === undefined || state.agent === null) && options.final === true) {
      try { state = await this.ensure(engagementId) } catch { state = undefined }
    }
    if (state === undefined) return { skipped: 'no-session' }
    if (state.agent === null) return { skipped: 'no-agent' }
    const force = options.force === true
    const final = options.final === true
    const always = options.always === true
    /* 指挥官正在跑时不要打断；保留一条待发通知，turn/end 后自动补发。
       final 通知优先级最高，不能被普通成员完成通知覆盖。 */
    if (state.busy) {
      const pending = this.pendingNudges.get(engagementId)
      if (pending === undefined || pending.options.final !== true || final) {
        this.pendingNudges.set(engagementId, { reason: asText(reason), options: { ...options } })
      }
      return { ok: true, queued: true, reason: 'commander-busy' }
    }
    const last = this.lastNudge.get(engagementId) || 0
    if (!force && nowMs() - last < 90000) return { skipped: 'cooldown' }
    if (this.tasks === undefined || this.tasks === null) return { skipped: 'no-tasks' }
    const rows = await this.tasks.list(engagementId, 200)
    const allPassed = rows.length > 0 && rows.every((row) => row.status === 'passed')
    if (final && !allPassed) return { skipped: 'not-ready' }
    if (final) {
      const mission = await this.tasks.missionOf(engagementId)
      if (mission !== null && mission !== undefined && mission.status === 'done') return { skipped: 'already-closed' }
    }
    const failed = rows.filter((row) => row.status === 'failed')
    const mine = rows.filter((row) => row.role === 'commander' && row.status !== 'passed' && row.status !== 'failed')
    const pending = rows.filter((row) => row.status === 'failed' || (row.role === 'commander' && row.status === 'open'))
    if (pending.length === 0 && !final && !always) return { skipped: 'nothing-to-do' }
    if (rows.length === 0 && !always) return { skipped: 'no-tasks' }
    this.lastNudge.set(engagementId, nowMs())
    void this.trace?.push?.(engagementId, {
      kind: 'nudge',
      actor: { role: 'system', name: '调度台' },
      title: final ? '通知总指挥：QA 已全部验收' : '主动催办总指挥',
      detail: asText(reason),
    })
    const lines = []
    if (final) {
      lines.push('【QA 终验完成 · 等总指挥宣布结束】')
      lines.push(`验收员已完成全部 ${rows.length} 条任务的核查，任务账本全部为 passed。现在必须由你（总指挥）做最终决定：`)
      for (const row of rows.slice(-12)) {
        lines.push(`- ${row.id} ${row.title}｜${row.status}${row.verifiedBy && row.verifiedBy.role ? `｜验收：${row.verifiedBy.name || row.verifiedBy.role}` : ''}`)
      }
      lines.push('① 先用 `recon_task action=list` 复核每条任务和证据；')
      lines.push('② 若确认目标达成，立即执行 `recon_task action=mission missionAction=close`；close 会停止并回收所有非核心队员，只保留总指挥/参谋常设席位；')
      lines.push('③ 若仍有缺口，明确说明并重新拆任务或让 QA 驳回，绝对不要口头宣布完成。')
      lines.push('不要在收尾前继续扫描，也不要自己冒充 QA。')
    } else {
      lines.push('【调度台提醒】任务账本有新情况，先处理这些再继续别的事：')
      if (failed.length > 0) {
        lines.push(`被验收驳回 ${failed.length} 条：`)
        for (const row of failed.slice(-6)) lines.push(`- ${row.id} ${row.title}｜缺口：${row.note || '未达标'}`)
      }
      if (mine.length > 0) {
        lines.push('等你重新拆解/分派：')
        for (const row of mine.slice(-6)) lines.push(`- ${row.id} ${row.title}｜目标：${row.goal || '-'}`)
      }
      lines.push('要求：读 `recon_task list` 确认状态；有返工就重新拆成可验收小任务并派给合适角色；')
      lines.push('成员完成后先安排 QA 核验证据，再决定是否通过；不要自己下场扫。')
    }
    if (asText(reason) !== '') lines.push(`触发原因：${reason}`)
    const text = lines.join('\n')
    await this.refreshPrompt(engagementId)
    state.buffers = { text: '', reasoning: '' }
    const record = { id: `n_${nowMs().toString(36)}`, role: 'user', text, ts: nowMs(), tier: state.tier, system: true }
    this.pushMessage(engagementId, record)
    this.hub.broadcast({ type: 'chat.user', engagementId, message: record })
    state.agent.followup({
      id: record.id,
      role: 'user',
      content: [{ type: 'text', text }],
      source: { kind: 'user' },
    })
    this.hub.broadcast({ type: 'chat.status', engagementId, status: 'running' })
    return { ok: true, nudged: pending.length, final }
  }

  /** turn/end 或 agent error 后补发被 busy 挡住的指挥席通知。 */
  flushPendingNudge(engagementId) {
    const pending = this.pendingNudges.get(engagementId)
    if (pending === undefined) return
    this.pendingNudges.delete(engagementId)
    setTimeout(() => {
      void this.nudge(engagementId, pending.reason, pending.options).catch(() => {})
    }, 0)
  }

  async stop(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state === undefined || state.agent === null) return { ok: true, stopped: false }
    try { state.agent.cancel({ kind: 'user' }) } catch { /* 已停 */ }
    this.hub.broadcast({ type: 'chat.status', engagementId, status: 'idle' })
    return { ok: true, stopped: true }
  }

  async clear(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state !== undefined) {
      try { state.agent?.cancel?.({ kind: 'user', reason: 'clear' }) } catch { /* 没在跑 */ }
      try { await state.handle?.dispose?.() } catch { /* 已释放 */ }
      this.sessions.delete(engagementId)
      if (typeof state.sessionId === 'string') COMMANDER_SESSIONS.delete(state.sessionId)
    }
    const timer = this.saveTimers.get(engagementId)
    if (timer !== undefined) clearTimeout(timer)
    this.saveTimers.delete(engagementId)
    this.ensuring.delete(engagementId)
    this.transcripts.set(engagementId, [])
    this.usage.set(engagementId, { input: 0, output: 0, total: 0, turns: 0 })
    this.lastNudge.delete(engagementId)
    this.pendingNudges.delete(engagementId)
    try {
      await ensureDir(this.chatDir())
      await writeFile(this.chatFile(engagementId), '[]\n', 'utf8')
    } catch { /* 落盘失败不影响清空界面 */ }
    this.hub.broadcast({ type: 'chat.cleared', engagementId })
    return { ok: true }
  }

  async resolveEngagementId(explicit) {
    const wanted = asText(explicit)
    if (wanted !== '') {
      const eng = await this.store.load(wanted)
      if (eng !== undefined) return eng.id
    }
    const active = await this.store.activeEngagement()
    if (active === undefined) throw new Error('还没有靶标：先建一个靶标再对话')
    return active.id
  }

  stateForAgent(agent) {
    for (const state of this.sessions.values()) {
      if (state.agent === agent) return state
    }
    return undefined
  }

  stateForSession(session) {
    if (session === undefined || session === null) return undefined
    const header = session.header
    const id = header && header.id
    for (const state of this.sessions.values()) {
      if (state.sessionId === id) return state
    }
    return undefined
  }

  install() {
    const ctx = this.ctx
    const offStream = ctx.on('agent/assistant-stream', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        const frame = payload.frame
        if (frame.type === 'start') {
          state.buffers = { text: '', reasoning: '' }
          return
        }
        if (frame.type !== 'chunk') return
        const chunk = frame.chunk
        if (chunk.type === 'text-delta') {
          state.buffers.text += chunk.text
          this.hub.broadcast({ type: 'chat.delta', engagementId: state.engagementId, text: chunk.text })
        } else if (chunk.type === 'reasoning-delta') {
          state.buffers.reasoning += chunk.text
          this.hub.broadcast({ type: 'chat.reasoning', engagementId: state.engagementId, text: chunk.text })
        }
      } catch { /* 观察者不干扰模型流 */ }
    })
    const offEvent = ctx.on('session/event', (session, event) => {
      try {
        const state = this.stateForSession(session)
        if (state === undefined) return
        const engagementId = state.engagementId
        if (event.type === 'tool/call') {
          this.hub.broadcast({
            type: 'chat.tool',
            engagementId,
            name: event.data.name,
            args: event.data.arguments,
          })
        } else if (event.type === 'tool/result') {
          const text = blocksText(event.data.message.content)
          this.hub.broadcast({
            type: 'chat.tool-result',
            engagementId,
            ok: event.data.error === undefined,
            text,
          })
        } else if (event.type === 'assistant/message') {
          const blocks = event.data.message.content
          const text = blocks.filter((b) => b && b.type === 'text').map((b) => b.text).join('').trim()
          const reasoning = blocks.filter((b) => b && b.type === 'reasoning').map((b) => b.text).join('').trim()
          /* 一轮里 agent 可能因为工具调用分成好几段输出；以前每段都单独发一条消息，
             前端一收到就清空流式缓冲，于是长回复永远停在第一段——看起来「输出一直不变」。
             现在整轮累积，turn 结束时合并成一条消息下发。 */
          if (text !== '') state.turnText = state.turnText === '' ? text : `${state.turnText}\n\n${text}`
          if (reasoning !== '') state.turnReasoning = state.turnReasoning === '' ? reasoning : `${state.turnReasoning}\n\n${reasoning}`
          if (state.turnModel === undefined && event.data.message.source !== undefined) {
            state.turnModel = `${event.data.message.source.provider}/${event.data.message.source.model}`
          }
          const record = {
            id: `a_${event.seq}_${Date.now().toString(36)}`,
            role: 'assistant',
            text: text || state.buffers.text,
            reasoning: reasoning || state.buffers.reasoning,
            ts: Date.now(),
            tier: state.tier,
            model: event.data.message.source ? `${event.data.message.source.provider}/${event.data.message.source.model}` : undefined,
          }
          if (event.data.usage !== undefined && event.data.usage !== null) {
            const usage = event.data.usage
            const prev = this.usage.get(engagementId) || { input: 0, output: 0, total: 0, turns: 0 }
            this.usage.set(engagementId, {
              input: prev.input + (Number(usage.inputTokens) || 0),
              output: prev.output + (Number(usage.outputTokens) || 0),
              total: prev.total + (Number(usage.totalTokens) || 0),
              turns: prev.turns + 1,
            })
            this.hub.broadcast({ type: 'chat.usage', engagementId, usage: this.usage.get(engagementId) })
          }
          state.buffers = { text: '', reasoning: '' }
          state.lastSegment = { seq: event.seq, tier: state.tier, model: record.model, ts: record.ts }
        } else if (event.type === 'turn/start') {
          state.busy = true
          state.turnText = ''
          state.turnReasoning = ''
          state.turnModel = undefined
          this.hub.broadcast({ type: 'chat.status', engagementId, status: 'running' })
        } else if (event.type === 'turn/end') {
          state.busy = false
          state.busySince = 0
          const fullText = (state.turnText || '').trim()
          const fullReasoning = (state.turnReasoning || '').trim()
          state.turnText = ''
          state.turnReasoning = ''
          if (fullText !== '' || fullReasoning !== '') {
            const seg = state.lastSegment || {}
            const record = {
              id: `a_${seg.seq === undefined ? 'x' : seg.seq}_${Date.now().toString(36)}`,
              role: 'assistant',
              text: fullText,
              reasoning: fullReasoning,
              ts: Date.now(),
              tier: seg.tier || state.tier,
              model: seg.model,
            }
            this.pushMessage(engagementId, record)
            this.hub.broadcast({ type: 'chat.message', engagementId, message: record })
            void this.trace?.push?.(engagementId, {
              kind: 'chat',
              actor: { role: 'commander', name: '总指挥' },
              title: '总指挥回复',
              detail: fullText || fullReasoning,
            })
          }
          state.lastSegment = undefined
          this.flushPendingNudge(engagementId)
          this.hub.broadcast({
            type: 'chat.turn-end',
            engagementId,
            reason: event.data.reason && event.data.reason.kind ? event.data.reason.kind : 'completed',
          })
        }
      } catch (error) {
          /* 同上 */
      }
    })
    const offStatus = ctx.on('agent/status', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        state.busy = payload.status === 'running'
        this.hub.broadcast({ type: 'chat.status', engagementId: state.engagementId, status: payload.status })
        if (payload.status === 'idle') {
          this.refreshPrompt(state.engagementId)
          this.flushPendingNudge(state.engagementId)
        }
      } catch { /* 同上 */ }
    })
    const offError = ctx.on('agent/error', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        const error = payload.error
        state.busy = false
        this.flushPendingNudge(state.engagementId)
        this.hub.broadcast({
          type: 'chat.error',
          engagementId: state.engagementId,
          text: error && error.message ? error.message : String(error),
        })
      } catch { /* 同上 */ }
    })
    return () => {
      offStream()
      offEvent()
      offStatus()
      offError()
    }
  }

  async dispose() {
    for (const state of this.sessions.values()) {
      try { await state.handle.dispose() } catch { /* 已释放 */ }
    }
    for (const timer of this.saveTimers.values()) clearTimeout(timer)
    this.sessions.clear()
  }

  async dropEngagement(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state !== undefined) {
      if (typeof state.sessionId === 'string') COMMANDER_SESSIONS.delete(state.sessionId)
      try { await state.handle.dispose() } catch { /* 已释放 */ }
      this.sessions.delete(engagementId)
    }
    const timer = this.saveTimers.get(engagementId)
    if (timer !== undefined) clearTimeout(timer)
    this.saveTimers.delete(engagementId)
    this.ensuring.delete(engagementId)
    this.transcripts.delete(engagementId)
    try { await unlink(this.chatFile(engagementId)) } catch { /* 没有记录 */ }
  }
}


/* ────────────────────────── 汇报席（fork 出来的独立对话） ────────────────────────── */

/**
 * 汇报席 = 给指挥席用的「参谋对话」。
 *
 * 三条硬约束：
 * 1) 独立会话：自己的 sessionId（recon-brief-<eng>），不进 COMMANDER_SESSIONS；
 * 2) 不污染：它的问答不发 chat.* 事件、不写 cockpit 的 transcript，所以总指挥的上下文里
 *    永远看不到「你问了进度如何」这种话；
 * 3) 时刻同步：每轮提问前现场重算一份 <situation>（任务账本/看板/命令/队员/漏洞/断点），
 *    随消息一起发过去。快照只进当轮，不进历史，避免上下文无限膨胀。
 */
class Brief {
  constructor(ctx, store, cfg, configStore, hub, deps) {
    this.ctx = ctx
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.tasks = deps.tasks
    this.board = deps.board
    this.squad = deps.squad
    this.trace = deps.trace
    this.runner = deps.runner
    this.meeting = deps.meeting
    this.audit = deps.audit
    this.sessions = new Map()
    this.history = new Map()
    this.ensuring = new Map()
  }

  dir() { return join(this.cfg.root, 'brief') }
  file(engagementId) { return join(this.dir(), `${engagementId}.json`) }

  async readHistory(engagementId) {
    if (this.history.has(engagementId)) return this.history.get(engagementId)
    let rows = []
    try {
      const raw = await readFile(this.file(engagementId), 'utf8')
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) rows = parsed
    } catch { /* 还没聊过 */ }
    this.history.set(engagementId, rows)
    return rows
  }

  async writeHistory(engagementId, rows) {
    const kept = rows
    this.history.set(engagementId, kept)
    try {
      await mkdir(this.dir(), { recursive: true })
      await writeJsonAtomic(this.file(engagementId), kept)
    } catch { /* 落盘失败不影响当轮回答 */ }
  }

  /** 汇报席的系统提示：只读、不派活、不写图 */
  briefPrompt() {
    const lines = []
    lines.push('## 你是「汇报席」')
    lines.push('你是红队指挥席的参谋。指挥席会随时问你作战进展，你只负责把当前真实情况讲清楚。')
    lines.push('')
    lines.push('### 硬约束')
    lines.push('- 只读：不派活、不跑命令、不改图谱、不写看板。需要推进的事，回答里告诉指挥席去做。')
    lines.push('- 这段对话是 fork 出来的独立上下文，你的回答不会回灌总指挥，所以不必顾及「打断它」。')
    lines.push('- 每轮消息开头会带一段 <situation>，那是总指挥此刻的真实状态，一切结论以它为准。')
    lines.push('- 数字必须来自 <situation>；确实没有的信息，直接说「当前状态下没看到」。')
    lines.push('')
    lines.push('### 回答风格')
    lines.push('- 先结论，后依据，三到八行。')
    lines.push('- 讲进展就讲「已经拿下什么 / 正在打什么 / 卡在哪 / 下一步建议」。')
    lines.push('- 有返工、有被驳回、有 stalled，就直说，不要粉饰。')
    return safePromptText(withCommonPrompt(this.configStore.get(), lines.join('\n')))
  }

  /** 现场快照：每次提问都重新算，保证「时刻」拥有总指挥的最新状态 */
  async situation(engagementId) {
    const lines = ['<situation>']
    const eng = await this.store.load(engagementId)
    if (eng === undefined) {
      lines.push('当前没有打开的靶标。')
      lines.push('</situation>')
      return lines.join('\n')
    }
    const stats = statsOf(eng)
    lines.push(`靶标：${eng.name}（id ${eng.id}）`)
    if (eng.scope.length > 0) lines.push(`授权范围：${eng.scope.join(', ')}`)
    lines.push(`图谱：节点 ${stats.nodes} · 关系 ${stats.edges} · 漏洞 ${stats.vulns} · 命令 ${stats.commands}`)

    /* 运行状态与断点 */
    try {
      if (this.runner !== undefined && this.runner !== null) {
        const phase = await this.runner.status?.(eng)
        if (phase !== undefined && phase !== null) {
          lines.push(`运行状态：${asText(phase.phase, 'idle')}${Number(phase.running) > 0 ? ` · 在跑 ${phase.running}` : ''}`)
          if (phase.checkpoint !== undefined && phase.checkpoint !== null) {
            lines.push(`断点：${new Date(phase.checkpoint.savedAt).toLocaleString('zh-CN')} · 未完成 ${phase.checkpoint.pending} 条（${asText(phase.checkpoint.reason, '手动')}）`)
          }
        }
      }
    } catch { /* 取不到就跳过 */ }

    /* 作战目标 */
    try {
      const mission = await this.tasks?.missionOf?.(engagementId)
      if (mission !== undefined && mission !== null && asText(mission.goal) !== '') {
        lines.push(`作战目标：${asText(mission.goal)}（${asText(mission.status, 'open')}）`)
      }
    } catch { /* 同上 */ }

    /* 任务账本 */
    try {
      const rows = await this.tasks?.list?.(engagementId, 200)
      if (Array.isArray(rows) && rows.length > 0) {
        const doing = rows.filter((row) => row.status === 'doing')
        const open = rows.filter((row) => row.status === 'open')
        const failed = rows.filter((row) => row.status === 'failed')
        const passed = rows.filter((row) => row.status === 'passed')
        const blocked = rows.filter((row) => row.status === 'blocked')
        lines.push(`任务账本：共 ${rows.length} · 进行中 ${doing.length} · 待领 ${open.length} · 受阻 ${blocked.length} · 被驳回 ${failed.length} · 已通过 ${passed.length}`)
        for (const row of doing.slice(-6)) lines.push(`  · [doing] ${row.id} ${row.title}（${asText(row.assignee || row.role, '-')}）`)
        for (const row of open.slice(-5)) lines.push(`  · [open] ${row.id} ${row.title}（${asText(row.role, '-')}）`)
        for (const row of blocked.slice(-4)) lines.push(`  · [blocked] ${row.id} ${row.title}｜${shortText(row.note || '-', 90)}`)
        for (const row of failed.slice(-4)) lines.push(`  · [被驳回] ${row.id} ${row.title}｜缺口：${shortText(row.note || '-', 90)}`)
        for (const row of passed.slice(-4)) lines.push(`  · [通过] ${row.id} ${row.title}`)
      }
    } catch { /* 同上 */ }

    /* 在岗队员 */
    try {
      const members = this.squad?.list?.(engagementId)
      if (Array.isArray(members) && members.length > 0) {
        lines.push(`在岗：${members.map((m) => `${asText(m.name || m.key, '-')}(${asText(m.role, '-')}${m.status === 'running' ? '·忙' : ''})`).join(' , ')}`)
      }
    } catch { /* 同上 */ }

    /* 未闭环漏洞 */
    const briefActiveNodeIds = new Set(eng.nodes.filter((node) => node.archived !== true).map((node) => node.id))
    const openVulns = eng.vulns.filter((v) => briefActiveNodeIds.has(v.nodeId) && v.status !== 'false-positive' && v.status !== 'fixed')
    if (openVulns.length > 0) {
      const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      const sorted = openVulns.slice().sort((a, b) => (rank[a.severity] === undefined ? 9 : rank[a.severity]) - (rank[b.severity] === undefined ? 9 : rank[b.severity]))
      lines.push(`未闭环漏洞 ${openVulns.length} 条：`)
      for (const v of sorted.slice(0, 8)) {
        lines.push(`  · ${v.severity}/${v.status} ${v.title}${asText(v.endpoint) !== '' ? ` @ ${shortText(v.endpoint, 60)}` : ''}`)
      }
    }

    /* 完整看板：用户发言全文 + 全部 agent 条目全文 */
    try {
      const boardText = await boardPromptText(this.board, engagementId, { actor: { key: 'brief' } })
      if (boardText !== '') {
        lines.push('')
        lines.push(boardText)
      }
    } catch { /* 同上 */ }

    /* 最近命令 */
    try {
      const commands = (eng.commands || []).slice(-10)
      if (commands.length > 0) {
        lines.push('最近命令：')
        for (const cmd of commands) {
          const member = cmd.sessionId ? this.squad?.memberBySessionId?.(cmd.sessionId) : undefined
          const who = member !== undefined ? member.name : '总指挥'
          const tail = shortText((asText(cmd.tail) || asText(cmd.stderrTail)).replace(/\s+/g, ' '), 90)
          const status = cmd.timedOut === true ? 'timeout' : (cmd.exitCode === null ? 'running' : `exit=${cmd.exitCode}`)
          lines.push(`  · ${who}｜${shortText(asText(cmd.command), 70)}｜${status}${tail !== '' ? `｜${tail}` : ''}`)
        }
      }
    } catch { /* 同上 */ }


    /* 停滞判定 */
    try {
      const status = await this.meeting?.verdict?.(eng)
      if (status !== undefined && status !== null && status.stalled === true) {
        lines.push(`停滞告警：${Array.isArray(status.reasons) ? status.reasons.join('；') : '任务已派完但无新进展'}`)
      }
    } catch { /* 同上 */ }

    try {
      const config = this.configStore.get()
      const memory = Array.isArray(config.memory) ? config.memory : []
      if (memory.length > 0) {
        lines.push('')
        lines.push('## 长期记忆（全局强制阅读，全部条目）')
        for (const item of memory) {
          const entry = memoryEntryOf(item)
          if (entry.content !== '') lines.push(`- [${entry.category || 'other'}] ${entry.title}：${entry.content}`)
        }
      }
    } catch { /* 取不到记忆就不带 */ }

    lines.push('</situation>')
    return lines.join('\n')
  }

  async ensure(engagementId) {
    const existing = this.sessions.get(engagementId)
    if (existing !== undefined && existing.agent !== null) return existing
    const pending = this.ensuring.get(engagementId)
    if (pending !== undefined) return pending
    const promise = this.ensureInner(engagementId).finally(() => { this.ensuring.delete(engagementId) })
    this.ensuring.set(engagementId, promise)
    return promise
  }

  async ensureInner(engagementId) {
    const agents = this.ctx.get('agents')
    if (agents === undefined || agents === null) throw new Error('agent 服务不可用')
    const config = this.configStore.get()
    const tier = asText(config.chat && config.chat.tier, 'deep')
    const state = {
      engagementId,
      sessionId: `recon-brief-${engagementId}`,
      tier,
      agent: null,
      handle: null,
      busy: false,
      buffers: { text: '', reasoning: '' },
      turnText: '',
      turnReasoning: '',
    }
    const brief = this
    const setup = (agentCtx) => {
      try {
        const prompt = typeof agentCtx.get === 'function' ? agentCtx.get('systemPrompt') : undefined
        if (prompt !== undefined && prompt !== null && typeof prompt.section === 'function') {
          prompt.section({ name: 'recon-brief', order: 4911, text: () => brief.briefPrompt() })
        }
      } catch { /* 提示词注入失败不影响对话 */ }
      /* 只读：把改动类工具全禁掉，汇报席不可能弄脏图谱 */
      try {
        const tools = typeof agentCtx.get === 'function' ? agentCtx.get('tools') : undefined
        if (tools !== undefined && tools !== null && typeof tools.restrict === 'function') {
          tools.restrict({
            deny: [
              'recon_start', 'recon_run', 'recon_asset', 'recon_asset_remove', 'recon_link', 'recon_ingest',
              'recon_vuln', 'recon_update', 'recon_watch', 'recon_browser', 'recon_squad', 'recon_org',
              'recon_task', 'recon_checkpoint', 'recon_config', 'recon_meeting',
              'recon_board', 'recon_audit',
              'bash', 'write', 'edit', 'terminal_open', 'terminal_send', 'subagent',
            ],
          })
        }
      } catch { /* 限制失败就靠提示词约束 */ }
    }
    const selection = this.modelForTier(tier)
    let handle
    try {
      handle = await agents.create({
        sessionId: state.sessionId,
        meta: { cwd: this.workDirOf() },
        agentOptions: selection,
        setup,
      })
    } catch (error) {
      /* 插件重载后内存表是空的，但会话库里有同名 session：换一个新 id，
         历史 Q&A 由 send() 回灌，不与旧会话冲突 */
      const detail = error && error.message ? error.message : String(error)
      if (!/already exists/i.test(detail)) throw error
      state.sessionId = `recon-brief-${engagementId}-${Date.now().toString(36)}`
      state.fresh = true
      handle = await agents.create({
        sessionId: state.sessionId,
        meta: { cwd: this.workDirOf() },
        agentOptions: selection,
        setup,
      })
    }
    state.agent = handle.agent
    state.handle = handle
    this.sessions.set(engagementId, state)
    return state
  }

  /** 模型档位解析：与驾驶舱同一套逻辑，dsh / 未配置时回落到宿主默认模型 */
  modelForTier(tier) {
    return modelSelectionFor(this.ctx, this.configStore, tier)
  }

  workDirOf() {
    const work = this.cfg && this.cfg.workDir ? this.cfg.workDir : this.cfg.root
    return work
  }

  async resolveEngagementId(explicit) {
    const wanted = asText(explicit)
    if (wanted !== '') {
      const eng = await this.store.load(wanted)
      if (eng !== undefined) return eng.id
    }
    const active = await this.store.activeEngagement()
    if (active === undefined) throw new Error('还没有靶标：先建一个靶标再问')
    return active.id
  }

  async send(explicit, rawQuestion) {
    const engagementId = await this.resolveEngagementId(explicit)
    const question = asText(rawQuestion)
    if (question === '') throw new Error('问题不能为空')
    const state = await this.ensure(engagementId)
    if (state.busy === true) {
      const stalled = nowMs() - (Number(state.busySince) || 0) > 180000
      if (stalled === false) return { ok: false, error: '汇报席还在回答上一问，稍等一下再问' }
      /* 超过 3 分钟没有 turn 结束也没有报错：判定为卡死，放行本次提问 */
      state.busy = false
    }
    state.busySince = nowMs()
    const snapshot = await this.situation(engagementId)
    let history = ''
    if (state.fresh === true) {
      state.fresh = false
      const rows = await this.readHistory(engagementId)
      const pairs = []
      for (let i = 0; i < rows.length; i += 1) {
        const user = rows[i]
        if (user === null || user.role !== 'user') continue
        const answer = rows.slice(i + 1).find((row) => row && row.role === 'assistant')
        if (answer === undefined) continue
        pairs.push(`Q：${asText(user.text)}\nA：${asText(answer.text)}`)
      }
      if (pairs.length > 0) {
        history = '\n\n<history>\n下面是你和指挥席之前的问答（上下文已换新会话，仅供你接续，不要复述）：\n'
          + pairs.slice(-8).join('\n')
          + '\n</history>'
      }
    }
    const text = `${snapshot}${history}\n\n【指挥席提问】${question}`
    const record = { id: `b_${nowMs().toString(36)}`, role: 'user', text: question, ts: nowMs() }
    /* 提问也进汇报席自己的历史（只在这个文件里，不进 cockpit transcript） */
    void (async () => {
      const rows = await this.readHistory(engagementId)
      await this.writeHistory(engagementId, rows.concat([record]))
    })()
    this.hub.broadcast({ type: 'brief.user', engagementId, message: record })
    state.buffers = { text: '', reasoning: '' }
    state.turnText = ''
    state.turnReasoning = ''
    state.busy = true
    this.hub.broadcast({ type: 'brief.status', engagementId, status: 'running' })
    state.agent.followup({
      id: record.id,
      role: 'user',
      content: [{ type: 'text', text }],
      source: { kind: 'user' },
    })
    return { ok: true, engagementId, sessionId: state.sessionId }
  }

  async clear(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state !== undefined && state.agent !== null) {
      try { await state.handle?.dispose?.() } catch { /* 已释放 */ }
      this.sessions.delete(engagementId)
    }
    this.ensuring.delete(engagementId)
    await this.writeHistory(engagementId, [])
    this.hub.broadcast({ type: 'brief.cleared', engagementId })
    return { ok: true }
  }

  async forget(engagementId) {
    const state = this.sessions.get(engagementId)
    if (state !== undefined) {
      try { await state.handle?.dispose?.() } catch { /* 已释放 */ }
      this.sessions.delete(engagementId)
    }
    this.history.delete(engagementId)
    this.ensuring.delete(engagementId)
  }

  stateForAgent(agent) {
    for (const state of this.sessions.values()) {
      if (state.agent === agent) return state
    }
    return undefined
  }

  stateForSession(session) {
    if (session === undefined || session === null) return undefined
    const id = session.header && session.header.id
    for (const state of this.sessions.values()) {
      if (state.sessionId === id) return state
    }
    return undefined
  }

  install() {
    const ctx = this.ctx
    const offStream = ctx.on('agent/assistant-stream', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        const frame = payload.frame
        if (frame.type === 'start') { state.buffers = { text: '', reasoning: '' }; return }
        if (frame.type !== 'chunk') return
        const chunk = frame.chunk
        if (chunk.type === 'text-delta') {
          state.buffers.text += chunk.text
          this.hub.broadcast({ type: 'brief.delta', engagementId: state.engagementId, text: chunk.text })
        } else if (chunk.type === 'reasoning-delta') {
          state.buffers.reasoning += chunk.text
          this.hub.broadcast({ type: 'brief.reasoning', engagementId: state.engagementId, text: chunk.text })
        }
      } catch { /* 观察者不干扰模型流 */ }
    })
    const offEvent = ctx.on('session/event', (session, event) => {
      try {
        const state = this.stateForSession(session)
        if (state === undefined) return
        const engagementId = state.engagementId
        if (event.type === 'assistant/message') {
          const blocks = event.data.message.content || []
          const text = blocks.filter((b) => b && b.type === 'text').map((b) => b.text).join('').trim()
          const reasoning = blocks.filter((b) => b && b.type === 'reasoning').map((b) => b.text).join('').trim()
          if (text !== '') state.turnText = state.turnText === '' ? text : `${state.turnText}\n\n${text}`
          if (reasoning !== '') state.turnReasoning = state.turnReasoning === '' ? reasoning : `${state.turnReasoning}\n\n${reasoning}`
        } else if (event.type === 'turn/start') {
          state.busy = true
          this.hub.broadcast({ type: 'brief.status', engagementId, status: 'running' })
        } else if (event.type === 'turn/end') {
          state.busy = false
          state.busySince = 0
          const fullText = (state.turnText || '').trim()
          const fullReasoning = (state.turnReasoning || '').trim()
          state.turnText = ''
          state.turnReasoning = ''
          if (fullText !== '' || fullReasoning !== '') {
            const record = {
              id: `ba_${event.seq}_${Date.now().toString(36)}`,
              role: 'assistant',
              text: fullText,
              reasoning: fullReasoning,
              ts: Date.now(),
            }
            /* 只进汇报席自己的历史文件，不进 cockpit transcript */
            void (async () => {
              const rows = await this.readHistory(engagementId)
              await this.writeHistory(engagementId, rows.concat([{ ...record, role: 'assistant', answered: true }]))
            })()
            this.hub.broadcast({ type: 'brief.message', engagementId, message: record })
          }
          this.hub.broadcast({ type: 'brief.status', engagementId, status: 'idle' })
        }
      } catch { /* 同上 */ }
    })
    const offStatus = ctx.on('agent/status', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        state.busy = payload.status === 'running'
        if (state.busy === false) state.busySince = 0
        this.hub.broadcast({ type: 'brief.status', engagementId: state.engagementId, status: payload.status })
      } catch { /* 同上 */ }
    })
    const offError = ctx.on('agent/error', (payload) => {
      try {
        const state = this.stateForAgent(payload.agent)
        if (state === undefined) return
        const error = payload.error
        state.busy = false
        state.busySince = 0
        this.hub.broadcast({
          type: 'brief.error',
          engagementId: state.engagementId,
          text: error && error.message ? error.message : String(error),
        })
      } catch { /* 同上 */ }
    })
    return () => { offStream(); offEvent(); offStatus(); offError() }
  }

  async dispose() {
    for (const state of this.sessions.values()) {
      try { await state.handle?.dispose?.() } catch { /* 已释放 */ }
    }
    this.sessions.clear()
  }
}

/* ────────────────────────── MCP 绑定 ────────────────────────── */

function normalizeMcpEntry(row) {
  const transport = row.transport === 'streamable-http' ? 'streamable-http' : 'stdio'
  const base = {
    transport,
    enabled: true,
    toolCallTimeoutMs: Number.isFinite(row.toolCallTimeoutMs) ? row.toolCallTimeoutMs : 120000,
    startupTimeoutMs: Number.isFinite(row.startupTimeoutMs) ? row.startupTimeoutMs : 30000,
    closeTimeoutMs: Number.isFinite(row.closeTimeoutMs) ? row.closeTimeoutMs : 5000,
    reconnect: {
      enabled: row.reconnectEnabled !== false,
      maxAttempts: Number.isFinite(row.reconnectMaxAttempts) ? row.reconnectMaxAttempts : 5,
      initialDelayMs: 1000,
      maxDelayMs: 30000,
    },
  }
  if (transport === 'stdio') {
    return {
      ...base,
      command: asText(row.command),
      args: Array.isArray(row.args) ? row.args.map(String) : asList(row.args),
      env: row.env && typeof row.env === 'object' && !Array.isArray(row.env) ? row.env : {},
      cwd: asText(row.cwd),
    }
  }
  return {
    ...base,
    url: asText(row.url),
    headers: row.headers && typeof row.headers === 'object' && !Array.isArray(row.headers) ? row.headers : {},
  }
}

function redactMcpSecrets(row) {
  if (row === null || typeof row !== 'object') return row
  const next = { ...row }
  for (const field of ['env', 'headers']) {
    if (next[field] !== null && typeof next[field] === 'object' && !Array.isArray(next[field])) {
      next[field] = Object.fromEntries(Object.keys(next[field]).map((key) => [key, '••••••••']))
    }
  }
  return next
}

class McpBinder {
  constructor(ctx, hub) {
    this.ctx = ctx
    this.hub = hub
    this.registered = new Map()
    this.last = { available: false, results: [] }
  }

  unregister(name) {
    const current = this.registered.get(name)
    if (current === undefined) return
    try { current.dispose() } catch { /* 已卸载 */ }
    this.registered.delete(name)
  }

  sync(config) {
    const manager = this.ctx.get('mcpManager')
    if (manager === undefined || manager === null) {
      this.last = { available: false, results: [], error: 'mcpManager 不可用：profile 未装 MCP 管理器' }
      return this.last
    }
    const wanted = Array.isArray(config.mcp) ? config.mcp : []
    const results = []
    const keep = new Set()
    for (const row of wanted) {
      const name = asText(row && row.name)
      if (name === '') continue
      keep.add(name)
      if (row.enabled === false) {
        this.unregister(name)
        results.push({ name, state: 'disabled' })
        continue
      }
      const entry = normalizeMcpEntry(row)
      const signature = JSON.stringify(entry)
      const current = this.registered.get(name)
      if (current !== undefined && current.signature === signature) {
        results.push({ name, state: 'unchanged' })
        continue
      }
      this.unregister(name)
      try {
        const dispose = manager.register(name, entry)
        this.registered.set(name, { dispose, signature })
        results.push({ name, state: 'registered' })
      } catch (error) {
        results.push({ name, state: 'failed', error: error && error.message ? error.message : String(error) })
      }
    }
    for (const name of Array.from(this.registered.keys())) {
      if (!keep.has(name)) this.unregister(name)
    }
    this.last = { available: true, results }
    return this.last
  }

  dispose() {
    for (const name of Array.from(this.registered.keys())) this.unregister(name)
  }
}

/* ────────────────────────── 协作层：看板 / 队伍 / 浏览器 / 自动化 ────────────────────────── */

/** 信息收集手的固定 Nday 检索职能；现有配置缺失时会自动补进 scout 提示词。 */
/** 旧版 Nday 段落：用于把已有 scout 提示词升级成「探测到指纹后主动查」的版本。 */
const SCOUT_NDAY_PROMPT_LEGACY = '**指纹 Nday 检索（固定职能，只查历史漏洞，不对目标发包）**：总指挥给你一个指纹/产品/版本时，调用 `recon_nday fingerprint="..."` 查 Exploit-DB 与 NVD，产出候选 CVE/EDB、受影响版本与来源链接，写进看板 kind=hypothesis；需要实测的交 Web 手或 QA。没有指纹时不要主动扫目标。'
const SCOUT_NDAY_PROMPT = '**指纹 Nday 检索**：一旦确认产品/中间件/服务/版本指纹，立刻用 `recon_nday fingerprint="产品 版本"` 查 Exploit-DB 与 NVD；每个指纹至少查一次，把候选 CVE/EDB、受影响版本、来源链接和可信度写进看板 kind=hypothesis；需要实测的交 Web 手或 QA。只查公开历史漏洞库，不对目标发包；没有指纹时不要主动扫目标。'

/** 旧版默认 scout 提示词，仅用于自动升级；用户自定义内容不会被覆盖。 */
const SCOUT_PROMPT_LEGACY = '你是信息收集手（Scout）。只做测绘：子域、端口、指纹、目录、接口、证书、泄露面。'
  + '每条发现立刻 `recon_asset` / `recon_ingest` 上图并连边，note 写清判断依据；'
  + '不做破坏性验证，也不做漏洞结论——发现交互点就写进看板点名 Web 手或逆向手。'
  + SCOUT_NDAY_PROMPT

const SCOUT_PROMPT = [
  '你是信息收集手（Scout）。你负责在授权范围内扩大并整理攻击面，不负责漏洞利用和最终漏洞定性。',
  '',
  '## 工作边界',
  '- 开始前先读作战目标、看板和授权范围；不确定目标或范围时先报告总指挥，不得越界。',
  '- 只做信息收集：DNS/子域、端口、服务版本、Web 指纹、目录/接口、证书、公开泄露面、源码地图。',
  '- 不做破坏性验证、不爆破登录、不执行 DoS、不手工利用漏洞；发现疑似漏洞只报告并交给 Web/QA。',
  '- 主动扫描前先确认速率和影响；全端口扫描必须分段、限速、记录进度，不能一次性把目标打崩。',
  '',
  '## 标准工作顺序',
  '1. 读 `recon_view`、任务账本和看板，确认已有资产、历史结论和未覆盖区域，禁止重复扫同一范围。',
  '2. 先做 DNS/子域/证书/ASN 等外部发现，再用 `recon_asset` 或 `recon_ingest` 记录资产并连边。',
  '3. 对每个存活主机尽可能做全端口扫描（TCP 1-65535；先确认 nmap/masscan/naabu 等工具可用，再分段完成），并做服务版本识别；确认协议、版本、响应特征和异常服务，不要只扫常见端口。',
  '4. 对 Web/API 做技术指纹、目录/路由和公开接口发现；把框架、中间件、组件版本、隐藏接口和源码片段落到指纹/接口/源码节点。',
  '5. 对每个确认的产品/版本指纹调用 `recon_nday` 查历史漏洞库，候选结论写看板 kind=hypothesis，不要把候选当已验证漏洞。',
  '6. 一轮结束后汇总新增资产、高价值攻击面、证据命令、未覆盖范围和下一步建议。',
  '',
  '## 证据与图谱',
  '- 每条外发命令必须走 `recon_run`，保留 commandId、原始输出和失败原因；不要用记忆代替命令结果。',
  '- 每个资产/接口/证书/指纹/密钥/源码都要上图；用 parent + edge 说明来源关系，孤立节点视为没做完。',
  '- note 至少写清：发现来源、命令 commandId、判断依据、可信度和下一步。',
  '- 事实用 finding/资产节点；未验证猜测用 hypothesis；不要把猜测写成已确认漏洞。',
  '- 发现注入点、接口、上传点、认证/授权逻辑时，写进看板点名 Web 手；发现 JS/APK/EXE 逆向需求时点名逆向手；需要跨角色直接协作时用 `recon_group action=request` 请求总指挥编组。',
  '',
  '## 交接与汇报',
  '- 成员完成后总指挥会收到通知；你的汇报必须能被下一个角色直接接手：目标资产、入口、参数、复现命令、已知限制。',
  '- 默认按「新增资产 / 高价值发现 / 指纹与 Nday / 未覆盖 / 建议下一步」五段输出。',
  '- 发现范围外资产或业务影响风险，立即停止并对总指挥报告。',
  '',
  SCOUT_NDAY_PROMPT,
].join('\n')

const WEB_PROMPT_LEGACY = '你是 Web 渗透手（Web）。负责 Web 相关的发现与验证：注入、越权/IDOR、上传、SSRF、XSS、逻辑漏洞、未授权接口。'
  + '**浏览器操作归你**：用 `recon_browser` 真开页面、登录、点按钮、填表单、截图存证（截图写进看板 shots）。'
  + '每个漏洞必须 `recon_run` 复现一次并带 commandId；拿不准的写看板当猜想，别当结论。'
  + '前端 JS 里的接口/密钥自己提取；需要还原混淆/逆向 JS 逻辑时，交回看板点名逆向手。'
  + '页面里看到的指纹、框架、隐藏接口、源码片段都要上图（kind=fingerprint / source），别只写在回复里。'

const WEB_PROMPT = [
  '你是 Web 渗透手（Web）。负责 Web/API 的攻击面发现、验证和证据固化：注入、越权/IDOR、上传、SSRF、XSS、逻辑漏洞、未授权接口。',
  '',
  '## 标准工作流程',
  '1. 先读任务、看板、完整记忆、授权范围和已有资产；确认目标域名/URL、账号、角色、入口和禁止边界。',
  '2. 对每个 Web 根路径和关键入口必须做目录/路由扫描（优先 ffuf/gobuster/dirsearch/feroxbuster，按工具实际可用性选择），不能只手工访问首页或只试几个常见路径；记录命令、字典、状态码、响应长度和结果。',
  '3. 对发现的目录、接口、参数和 JS 入口继续做指纹与路由提取；把接口、参数、框架、组件版本、源码片段落到图谱节点。',
  '4. 每个可疑点必须用 `recon_run` 复现一次，保留 commandId、请求/响应摘要、影响和前置条件；不能复现的只能写 hypothesis，不能当漏洞结论。',
  '5. 需要登录、会话、验证码、前端交互或可视化证据时，调用 `recon_browser`：打开页面、登录、点击、填表、执行步骤并截图；截图路径写进看板 shots。',
  '6. 发现 JS 混淆、签名算法、APK/客户端协议等逆向需求时，先在任务/看板点名逆向手，或用 `recon_group action=request` 请总指挥编组；不要自己假装完成逆向。',
  '7. 完成后输出：目标入口 / 目录与接口发现 / 可复现漏洞与 commandId / 浏览器截图 / 影响与限制 / 建议 QA 如何验收。',
  '',
  '## 纪律',
  '- 所有外发请求和扫描走 `recon_run`，浏览器操作走 `recon_browser`；不要只在回复里说“测过了”。',
  '- 目录扫描和参数测试要限速、分段、避免破坏性方法；越界或高风险操作先报告总指挥。',
  '- 事实与猜测分开；漏洞必须有复现证据和范围，不能把 scanner 输出直接当结论。',
  '- 页面看到的指纹、接口、隐藏参数、源码片段都要上图并写看板，别只留在上下文里。',
].join('\n')

const STAFF_PROMPT_LEGACY = '你是参谋（Staff）。只出谋划策，不执行扫描、不写漏洞。'
  + '吃透图谱现状与看板，给出：攻击面优先级、最可能的突破点（含依据）、被忽略了什么、'
  + '以及一份可执行的任务拆解建议（每条：目标 / 建议角色 / 验收标准）。'
  + '先把整体方案写到 `recon_board`（kind=hypothesis）：攻击面、优先级、每步派谁、需要什么模型/skills/MCP、上下文边界和验收标准。'
  + '方案写完后明确 @总指挥 请其拆任务；不要直接派发 Agent，也不要自己动手扫描。'
  + '返工模式：当验收驳回时，你会收到缺口说明；这时给出 3 条可执行改进方案（怎么做 / 派给谁 / 验收标准），让总指挥直接挑一条重排。'

const STAFF_PROMPT = [
      '你是参谋（Staff）。负责方案、优先级、攻击路径和环境评估；不要冒充执行手做漏洞验证。',
      '',
      '## 每次进入项目先做环境检查',
      '当你第一次为项目出方案，或环境/工具状态可能变化时，必须在规划前做一次只读环境检查：',
      '1. 用 `recon_run` 检查操作系统、内核、当前用户、权限、工作目录、网络/代理：例如 `uname -a`、`cat /etc/os-release`、`id`、`pwd`、`env`。',
      '2. 检查各角色实际可用的工具：web 手所需的浏览器/HTTP/目录与漏洞工具，逆向手所需的反编译/调试/脚本工具，内网手所需的隧道/横向工具；逐项记录有/没有、版本、路径。',
      '3. 查看 `recon_config get` 里当前 skills、MCP、角色配置，以及 `recon_squad list` 的在岗成员；确认哪些能力是真实可用，哪些只是配置了但未验证。',
      '4. 把环境结论写入记忆：`recon_memory action=add category=environment importance=high`，标题写清环境范围，正文写清 OS、可用/缺失工具、角色能力、MCP/技能和限制。',
      '环境检查只做只读命令，不扫描目标、不扩大攻击面；检查完再把方案交给总指挥。',
      '',
      '## 方案职责',
      '吃透图谱现状、完整看板和记忆，给出：攻击面优先级、最可能的突破点（含依据）、被忽略了什么，以及可执行的任务拆解建议（目标 / 建议角色 / 模型档位 / skills / MCP / 验收标准）。',
      '整体方案写到 `recon_board`（kind=hypothesis），写完后明确 @总指挥 请其拆任务；不要直接派发 Agent，不要自己扫描目标。',
      '需要跨角色能力时，建议总指挥用 `recon_squad action=group` 编组；组内由成员用 `recon_group ask` 串行协作。',
      '',
      '## 记忆规则',
      '记忆是所有 agent 强制完整阅读的全局事实库；只有总指挥和参谋可以写入。',
      '只写最重要、最全局、可复用的事实：项目概况、总体目标、环境/工具结论、特殊攻击手法、已确认漏洞、账号密码/凭据。不要把过程流水账、普通汇报或离职交接写进记忆；离职交接只写看板。',
      '',
      '返工模式：当验收驳回时，根据缺口给出 3 条可执行改进方案（怎么做 / 派给谁 / 验收标准），让总指挥直接挑一条重排。',
    ].join('\n')

const DEFAULT_ROLES = [
  {
    id: 'commander', name: '总指挥', tier: 'deep', reportsTo: null, model: null, skills: [],
    prompt: '你是总指挥（Commander）。你自己几乎不动手：只有「没有任何合适角色」且「一条命令就能收尾」时才自己做，其余一律下派。'
      + '每次派活都要把要求写死：`recon_squad spawn` 支持 name（给队员起代号）、prompt（专属指令：目标/边界/产出/禁止事项）、'
      + 'skills（要给这名队员加载哪些 skills）、asRole+roleName+rolePrompt（需要新兵种时现开一个，如 fuzzer/reporter/db-exploiter）。'
      + '工作方式：① 先让参谋（staff）出方案；② 用 `recon_task` 把方案拆成可验收的任务（每条形如：目标 / 验收标准 / 负责角色）；'
      + '③ 用 `recon_org recruit` 招人、`recon_squad spawn/task` 派活、`recon_org recall` 回收；'
      + '④ 盯 `recon_task list` 与看板，验收驳回（failed）就立刻重新拆任务再派；⑤ 需要临时兵种时（写工具、做钓鱼页、整报告），'
      + '用 `recon_org recruit` 传 role 名与职责说明即时开一个新角色，不必等内置编制。'
      + '收官协议（必须走完，不许半途宣布成功）：① 每条任务都要有 qa 的 accept；② 全部通过后你宣布完成（`recon_task action=mission missionAction=close`）；'
      + '③ close 会自动回收空闲队员，正在跑的可保留；④ 只要有 reject，就拉参谋出方案 → 重排任务 → 再验收，循环到全部通过为止。'
      + '记忆规则：记忆是全局强制阅读的事实库，所有成员都必须完整看；只有你和参谋可以写入，只写项目概况、总体目标、环境/工具结论、特殊攻击手法、已确认漏洞、账号密码/凭据，不写过程流水账和离职交接。'
      + '纪律：同一资产不要重复派两个人；并发满了先回收空闲；对外输出只给结论与证据引用。',
  },
  {
    id: 'staff', name: '参谋', tier: 'deep', reportsTo: 'commander', model: null, skills: [],
    prompt: STAFF_PROMPT,
  },
  {
    id: 'scout', name: '信息收集', tier: 'fast', reportsTo: 'commander', model: null, skills: [],
    prompt: SCOUT_PROMPT,
  },
  {
    id: 'web', name: 'Web 手', tier: 'deep', reportsTo: 'commander', model: null, skills: [],
    prompt: WEB_PROMPT,
  },
  {
    id: 'reverser', name: '逆向手', tier: 'deep', reportsTo: 'commander', model: null, skills: [],
    prompt: '你是逆向手（Reverser）。负责 JS 逆向、APK 逆向、EXE/ELF 逆向与协议还原。'
      + 'JS：去混淆、还原接口与签名算法、找硬编码密钥；APK：apktool/jadx 反编译、看 manifest 与加固、找 exported 组件与密钥；'
      + 'EXE/ELF：file/strings/objdump/ghidra 无头脚本/gdb 动态跟踪。'
      + '产出两类东西：① 可复用的分析结论与利用线索（写进看板，kind=finding）；② 需要固化的脚本/工具（写进 work 目录并说明用法）。'
      + '**所有中间产物都要上图**：源码/JS 文件/反编译结果用 recon_asset kind=source（value=文件或片段摘要，note=关键代码），'
      + '指纹串/版本/中间件用 kind=fingerprint，硬编码密钥用 kind=secret，并用 edge=extracted_from 连回它所属的资产。'
      + '不要碰 Web 页面交互（那是 Web 手）与内网横向（那是内网手）。',
  },
  {
    id: 'intranet', name: '内网手', tier: 'deep', reportsTo: 'commander', model: null, skills: [],
    prompt: '你是内网手（Intranet）。负责落地后的横向与纵深：凭据复用、隧道（frp/chisel/suo5）、代理、端口转发、'
      + '内网扫描（fscan/gogo）、域内信息（netexec/ldapsearch）、提权与持久化验证。'
      + '每条链路都要留痕：命令走 `recon_run`，节点与边 `recon_asset`/`recon_link`（credentialed_by / exploited_by）。'
      + '不碰 Web 前端逻辑与逆向（交给对应角色）。',
  },
  {
    id: 'qa', name: '验收', tier: 'deep', reportsTo: 'commander', model: null, skills: [],
    prompt: '你是验收员（QA）。你的职责只有两件：'
      + '① **漏洞实测**：对图谱里每条 status=open 的漏洞独立复现一次（命令或 `recon_browser` 均可），'
      + '判定 verified / false-positive，用 `recon_update` 改状态，并把复现命令/截图写进看板。'
      + '② **任务达标判定**：用 `recon_task list` 看每个任务的目标与验收标准，'
      + '达成 → `recon_task accept`（附证据）；没达成 → `recon_task reject` 写明缺什么，'
      + '系统会把驳回意见作为新任务回给总指挥。'
      + '③ **命令审计**：总指挥让你审某个队员/某个模块时，用 `recon_audit action=members` 找到他，'
      + '`action=list` 看他到底跑了什么，`action=inspect` 按覆盖度规则体检（是否全端口、有没有 -sV、'
      + '字典是不是 small、有没有带扩展名、子域是否 -all、失败率与重复命令），'
      + '确认覆盖不足就用 `action=rework` 建返工任务派回原队员，并在看板写清「哪儿不够、该怎么补」。'
      + '你只判定，不替别人干活：发现需要补测，写看板点名对应角色。'
      + '纪律：① 只按验收标准判，不接受"大概"；② 通过就叫 accept，缺证据就叫 reject 并写清缺口；'
      + '③ 所有任务都 accept 之后，系统会自动通知总指挥收官——你不需要自己去宣布完成。',
  },
]

/** 角色别名：老配置里的 hunter/browser/analyst 仍然可用。 */
const ROLE_ALIASES = {
  hunter: 'web',
  browser: 'web',
  analyst: 'scout',
  recon: 'scout',
  pentest: 'web',
  reverse: 'reverser',
  internal: 'intranet',
  validator: 'qa',
  leader: 'commander',
  temp: 'staff',
}

/** 本机技能目录：DSH 用户技能、红队技能、用户提供的成熟技能包。 */
function skillRoots() {
  const roots = []
  const add = (dir) => { if (asText(dir) !== '' && roots.includes(dir) === false) roots.push(dir) }
  add(join(dshHome(), 'skills'))
  add(join(dshHome(), 'redteam', 'skills'))
  const extra = asText(process.env.DSH_SKILL_DIRS)
  if (extra !== '') for (const dir of extra.split(',')) add(dir.trim())
  const publicSkills = process.env.DSH_PUBLIC_SKILLS || join(homedir(), 'Public', 'skills')
  add(join(publicSkills, 'hack-skills', 'skills'))
  add(join(publicSkills, 'Anthropic-Cybersecurity-Skills', 'skills'))
  return roots
}

function parseSkillMeta(text, fallbackName) {
  const raw = String(text || '')
  const fm = /^---\s*\n([\s\S]*?)\n---/.exec(raw)
  const head = fm === null ? '' : fm[1]
  const field = (key) => {
    const hit = new RegExp(`^${key}:\\s*(.+)$`, 'm').exec(head)
    return hit === null ? '' : hit[1].trim().replace(/^['"]|['"]$/g, '')
  }
  return {
    name: field('name') || fallbackName,
    description: field('description') || '',
    whenToUse: field('whenToUse') || '',
  }
}

async function discoverSkills() {
  const out = []
  const seen = new Set()
  for (const root of skillRoots()) {
    let entries = []
    try { entries = await readdir(root, { withFileTypes: true }) } catch { continue }
    for (const entry of entries) {
      const path = entry.isDirectory()
        ? join(root, entry.name, 'SKILL.md')
        : (entry.name.endsWith('.md') ? join(root, entry.name) : '')
      if (path === '') continue
      let text = ''
      try { text = await readFile(path, 'utf8') } catch { continue }
      const meta = parseSkillMeta(text, entry.name.replace(/\.md$/i, ''))
      if (seen.has(meta.name)) continue
      seen.add(meta.name)
      out.push({ ...meta, path })
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

async function loadSkill(name) {
  const wanted = asText(name)
  if (wanted === '') return undefined
  const all = await discoverSkills()
  return all.find((item) => item.name === wanted)
}

function canonicalRoleId(squad, value, fallback = 'web') {
  const wanted = asText(value, fallback)
  if (squad === undefined || squad === null) return wanted
  const direct = squad.roles().find((role) => role.id === wanted || role.name === wanted)
  if (direct !== undefined) return direct.id
  const core = squad.coreRoleIdOf(wanted)
  if (core !== '') return core
  const alias = ROLE_ALIASES[wanted]
  if (alias !== undefined) return squad.roleOf(alias).id
  throw new Error(`未知角色：${wanted}。可用角色：${squad.roles().map((role) => `${role.id}(${role.name})`).join(', ')}`)
}

async function latestStaffPlan(board, engagementId, since = 0) {
  if (board === undefined || board === null) return undefined
  const rows = await board.list(engagementId, 500)
  return rows
    .filter((row) => row && row.author && row.author.role === 'staff'
      && ['hypothesis', 'finding', 'note', 'task', 'conclusion'].includes(row.kind)
      && (Number(row.ts) || 0) > (Number(since) || 0))
    .sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0))
    .slice(-1)[0]
}

const DEFAULT_AUTOMATION = {
  enabled: true,
  maxAgents: 8,
  maxAutomationAgents: 3,
  rules: [
    {
      id: 'asset-hunt', on: 'node.created', enabled: true, role: 'web', tier: 'deep',
      whenKinds: ['subdomain', 'ip', 'url', 'service', 'endpoint', 'host'],
      cooldownMs: 45000,
      task: '新资产 {{kind}}:{{value}}（节点 {{nodeId}}）刚进图谱。做一轮针对性探测：指纹与服务识别 → 已知漏洞 → 未授权接口，'
        + '每条结论用 recon_run 复现并把 commandId 写进 recon_vuln；过程中把猜想写进 recon_board。',
    },
    {
      id: 'vuln-verify', on: 'vuln.created', enabled: true, role: 'web', tier: 'vision',
      whenSeverity: ['critical', 'high', 'medium'],
      cooldownMs: 30000,
      task: '看板新漏洞 {{title}}（{{severity}}，节点 {{nodeId}}，位置 {{endpoint}}）。用 recon_browser 打开相关页面做一次真实复现：'
        + '定位参数/交互点，截图存证，把「可复现 / 不可复现 / 需要前置条件」写进看板并更新漏洞状态。',
    },
  ],
}

function nowMs() {
  return Date.now()
}

/** 看板：多智能体共用的"协同办公"记录。 */
/** 看板上限与合并策略：到 100 条就把最早的 50 条压成一条摘要，避免无限增长也很难翻。 */
/** 轨迹面板保留/下发的条数上限。 */
const TRACE_LIMIT = 500
/** 轨迹显示上限：控制台可覆盖，范围 100–5000（轨迹本身最多保留 5000 条）。 */
function traceLimitOf(configStore) {
  const raw = configStore !== undefined && configStore !== null && typeof configStore.get === 'function'
    ? (configStore.get().trace || {})
    : {}
  const value = Number(raw.limit)
  return Number.isFinite(value) ? Math.max(100, Math.min(5000, Math.floor(value))) : TRACE_LIMIT
}

const BOARD_LIMIT = 100
const BOARD_MERGE_COUNT = 50
/** 看板阈值：允许 50/100/200 三档，合并条数允许 25/50/100；越界一律夹到合法值。 */
function boardOptions(configStore) {
  const raw = configStore !== undefined && configStore !== null && typeof configStore.get === 'function'
    ? (configStore.get().board || {})
    : {}
  const limit = [50, 100, 200].includes(Number(raw.limit)) ? Number(raw.limit) : BOARD_LIMIT
  const wantedMerge = [25, 50, 100].includes(Number(raw.mergeCount)) ? Number(raw.mergeCount) : BOARD_MERGE_COUNT
  /* 合并条数不能超过阈值的一半，否则一次合并就把看板清空 */
  const mergeCount = Math.min(wantedMerge, Math.max(10, Math.floor(limit / 2)))
  const mergeMode = raw.mergeMode === 'ai' ? 'ai' : 'deterministic'
  const mergeModel = ['deep', 'fast'].includes(asText(raw.mergeModel)) ? asText(raw.mergeModel) : 'fast'
  return { limit, mergeCount, mergeMode, mergeModel }
}

/** 看板概括只接受真实 summary；禁止用正文截断伪造概括。 */
function boardSummaryOf(row) {
  if (row === null || row === undefined || typeof row !== 'object') return ''
  if (row.author && row.author.role === 'user') return ''
  const text = asText(row.text).replace(/\s+/g, ' ').trim()
  const explicit = asText(row.summary).replace(/\s+/g, ' ').trim()
  if (explicit === '') return ''
  /* 压缩摘要本身既是概括也是正文，允许通过 merged 标记识别。 */
  if (row.refs && row.refs.merged) return explicit
  const bodyPrefix = explicit.replace(/…$/g, '').trim()
  if (explicit === text || (bodyPrefix.length >= 80 && text.startsWith(bodyPrefix))) return ''
  return explicit
}

class Board {
  constructor(root, hub, configStore, ctx) {
    this.root = root
    this.hub = hub
    this.configStore = configStore
    this.ctx = ctx
    this.dir = join(root, 'board')
    this.cache = new Map()
    this.seq = 0
    this.locks = new Map()
    /* agent 已经通过 view 看过的条目：后续该 agent 的提示词用正文替换概括。 */
    this.viewed = new Map()
  }

  withLock(id, operation) {
    const key = String(id)
    const previous = this.locks.get(key) || Promise.resolve()
    const next = previous.then(operation, operation)
    const tail = next.then(() => undefined, () => undefined)
    this.locks.set(key, tail)
    void tail.finally(() => { if (this.locks.get(key) === tail) this.locks.delete(key) })
    return next
  }

  fileOf(engagementId) {
    return join(this.dir, `${engagementId}.json`)
  }

  async init() {
    await ensureDir(this.dir)
    return this
  }

  /** 直接拿到缓存数组本体（写入必须改本体，list 返回的是切片副本）。 */
  /** 把当前内存里的看板写盘（手动 compact 等不经过 post 的路径用它） */
  async persist(engagementId) {
    const rows = await this.raw(engagementId)
    await writeJsonAtomic(this.fileOf(engagementId), rows)
    return rows.length
  }

  /** 真实条数（不受显示上限影响） */
  countOf(engagementId) {
    const rows = this.cache.get(engagementId)
    return Array.isArray(rows) ? rows.length : 0
  }

  viewedKey(engagementId, actor) {
    if (actor && actor.kind === 'leader') return `${engagementId}:lead`
    const key = actor && (actor.key || actor.name || actor.role) ? String(actor.key || actor.name || actor.role) : 'lead'
    return `${engagementId}:${key}`
  }

  markViewed(engagementId, actor, id) {
    const key = this.viewedKey(engagementId, actor)
    if (!this.viewed.has(key)) this.viewed.set(key, new Set())
    this.viewed.get(key).add(asText(id))
    if (this.viewed.get(key).size > 2000) {
      const rows = Array.from(this.viewed.get(key))
      this.viewed.set(key, new Set(rows.slice(-1000)))
    }
  }

  viewedIdsOf(engagementId, actor) {
    return this.viewed.get(this.viewedKey(engagementId, actor)) || new Set()
  }

  /** 用户发言全量：永不合并、永不截断，单独按用户条数计算。 */
  directivesForPrompt(engagementId) {
    const rows = this.rawSync(engagementId)
    const mine = Array.isArray(rows) ? rows.filter((row) => this.isUserEntry(row)) : []
    if (mine.length === 0) return ''
    const lines = []
    lines.push('## 【用户看板发言 · 最高优先级】')
    lines.push('下面所有文字都是用户本人写的，必须完整阅读并遵守；用户发言永不压缩、无上限、不参与 agent 看板条数计算。')
    for (const row of mine) {
      const when = new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')
      lines.push(`- （${when}）${safePromptText(asText(row.text))}`)
    }
    return lines.join('\n')
  }

  /**
   * 看板上下文索引：用户发言正文完整注入；agent 条目只注入简短索引，
   * 正文用 `recon_board action=view id=...` 按需查看。图片始终只给路径。
   */
  promptText(engagementId, options = {}) {
    const rows = this.rawSync(engagementId)
    if (!Array.isArray(rows) || rows.length === 0) return ''
    const userRows = rows.filter((row) => this.isUserEntry(row))
    const agentRows = rows.filter((row) => this.isUserEntry(row) === false)
    const viewedIds = options && options.viewedIds instanceof Set
      ? options.viewedIds
      : (options && options.actor ? this.viewedIdsOf(engagementId, options.actor) : new Set())
    const lines = []
    lines.push('## 团队看板概括索引（强制阅读）')
    lines.push(`统计：用户 ${userRows.length} 条（正文全部注入、无上限）· agent ${agentRows.length} 条（只注入概括索引，正文按需查看）。`)
    lines.push('用户发言优先级最高，必须完整阅读。agent 正文不要凭空猜测；需要细节时用 `recon_board action=view id=条目ID` 获取全文。图片只给路径，需要时单独查看。')
    const renderMeta = (row) => {
      const refs = row.refs && typeof row.refs === 'object' ? row.refs : {}
      const refParts = []
      for (const key of ['nodeIds', 'vulnIds', 'commandIds']) {
        if (Array.isArray(refs[key]) && refs[key].length > 0) refParts.push(`${key}=${refs[key].join(',')}`)
      }
      if (refParts.length > 0) lines.push(`引用：${refParts.join('；')}`)
      const shots = Array.isArray(row.shots) ? row.shots : []
      if (shots.length > 0) lines.push(`截图（仅路径，需要时单独查看）：${shots.join(' | ')}`)
      if (refs.merged && refs.merged.count !== undefined) lines.push(`本条为压缩摘要：压缩 ${refs.merged.count} 条（${asText(refs.merged.from)} → ${asText(refs.merged.to)}）`)
    }
    const renderUserRow = (row) => {
      const when = new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')
      const who = row.author && row.author.name ? row.author.name : '?'
      lines.push('')
      lines.push(`### [${asText(row.kind, 'note')}] ${who} · ${when} · ${asText(row.id, '')}`)
      lines.push(safePromptText(asText(row.text)))
      renderMeta(row)
    }
    const renderAgentRow = (row) => {
      const when = new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')
      const who = row.author && row.author.name ? row.author.name : '?'
      lines.push('')
      lines.push(`### [${asText(row.kind, 'note')}] ${who} · ${when} · ${asText(row.id, '')}`)
      if (viewedIds.has(row.id)) {
        lines.push('正文（已查看，已替代原概括）：')
        lines.push(safePromptText(asText(row.text)))
      } else {
        const summary = boardSummaryOf(row)
        lines.push(`概括：${summary === '' ? '⚠️ 未提供有效概括，请按 id 查看正文' : safePromptText(summary)}`)
        lines.push(`查看正文：recon_board action=view id=${asText(row.id, '')}`)
      }
      renderMeta(row)
    }
    if (userRows.length > 0) {
      lines.push('')
      lines.push('### 用户发言正文（永不压缩 / 无上限 / 单独计数）')
      for (const row of userRows) renderUserRow(row)
    }
    lines.push('')
    lines.push('### agent 看板简短索引（全部条目）')
    if (agentRows.length === 0) lines.push('（暂无 agent 看板条目）')
    for (const row of agentRows) renderAgentRow(row)
    return lines.join('\n')
  }

  /** 同步读缓存（提示词每轮实时渲染用；未预热时返回空数组） */
  rawSync(engagementId) {
    if (!this.cache.has(engagementId)) {
      let rows = []
      try {
        const raw = JSON.parse(readFileSync(this.fileOf(engagementId), 'utf8'))
        if (Array.isArray(raw)) rows = raw
      } catch { /* 没有看板 */ }
      this.cache.set(engagementId, rows)
    }
    const rows = this.cache.get(engagementId)
    return Array.isArray(rows) ? rows : []
  }

  async raw(engagementId) {
    if (!this.cache.has(engagementId)) {
      let rows = []
      try {
        const raw = JSON.parse(await readFile(this.fileOf(engagementId), 'utf8'))
        if (Array.isArray(raw)) rows = raw
      } catch { /* 没有看板 */ }
      this.cache.set(engagementId, rows)
    }
    return this.cache.get(engagementId)
  }

  async list(engagementId, limit = 300) {
    const rows = await this.raw(engagementId)
    return rows.slice(-limit)
  }

  /** 按关键词检索看板概括和正文；返回命中的条目，正文仍由 view 读取。 */
  async search(engagementId, query, limit = 50) {
    const needle = asText(query).toLowerCase()
    if (needle === '') return []
    const rows = await this.raw(engagementId)
    return rows
      .filter((row) => `${asText(row.text)} ${boardSummaryOf(row)} ${asText(row.kind)} ${asText(row.author && row.author.name)}`.toLowerCase().includes(needle))
      .slice(-Math.max(1, Math.min(1000, Number(limit) || 50)))
  }

  /** 用户（指挥席本人）的看板发言：无上限、永不压缩、强制进所有 agent 上下文 */
  isUserEntry(row) {
    /* 只有「真人」经 board.post 写入的才算用户发言（role=user）。
       role=lead 是主会话 agent（指挥席）自己发的，不能再冒充用户。 */
    const role = row && row.author ? asText(row.author.role) : ''
    return role === 'user'
  }

  /** 用户条目全文（不截断、不压缩），按时间顺序 */
  async userEntries(engagementId, limit = 0) {
    const rows = await this.raw(engagementId)
    const mine = rows.filter((row) => this.isUserEntry(row))
    return limit > 0 ? mine.slice(-limit) : mine
  }

  /** 除用户之外的条目（受上限与合并影响） */
  agentCountOf(engagementId) {
    const rows = this.cache.get(engagementId)
    if (!Array.isArray(rows)) return 0
    return rows.filter((row) => !this.isUserEntry(row)).length
  }

  async post(engagementId, entry) {
    return this.withLock(engagementId, () => this.postInner(engagementId, entry))
  }

  async postInner(engagementId, entry) {
    const text = asText(entry.text)
    if (text.trim() === '') throw new Error('看板内容不能为空')
    const rows = await this.raw(engagementId)
    this.seq += 1
    const isUser = entry.author && entry.author.role === 'user'
    const record = {
      id: `b${nowMs().toString(36)}${this.seq}`,
      ts: nowMs(),
      author: entry.author || { role: 'system', name: '系统' },
      kind: entry.kind || 'note',
      text,
      summary: isUser ? '' : boardSummaryOf({ author: entry.author, text, summary: entry.summary }),
      refs: entry.refs || {},
      shots: Array.isArray(entry.shots) ? entry.shots : [],
    }
    rows.push(record)
    let merged = null
    /* 达到设定的 agent 条目上限时自动压缩最早一批；手动压缩按钮也走同一条链路。 */
    if (this.isUserEntry(record) === false) {
      const options = boardOptions(this.configStore)
      const agentRows = rows.filter((row) => this.isUserEntry(row) === false)
      if (agentRows.length >= options.limit) merged = await this.compactInner(engagementId, options.mergeCount)
    }
    await writeJsonAtomic(this.fileOf(engagementId), rows)
    try { this.hub.broadcast({ type: 'board.post', engagementId, entry: record }) } catch { /* 广播失败 */ }
    return merged === null ? record : { ...record, merged }
  }

  /** 手动把最早的 N 条 agent 看板压成一条摘要；用户发言永不参与合并。 */
  async compact(engagementId, count) {
    return this.withLock(engagementId, () => this.compactInner(engagementId, count))
  }

  async compactInner(engagementId, count) {
    const rows = await this.raw(engagementId)
    const options = boardOptions(this.configStore)
    const wanted = Number.isFinite(Number(count)) ? Math.max(1, Math.min(100000, Math.floor(Number(count)))) : options.mergeCount
    /* 用户发言永不参与合并：先把它们摘出来，合并完按原时间顺序放回去 */
    const userRows = rows.filter((row) => this.isUserEntry(row))
    const agentRows = rows.filter((row) => this.isUserEntry(row) === false)
    if (agentRows.length === 0) return null
    const head = agentRows.slice(0, Math.min(wanted, agentRows.length))
    if (head.length === 0) return null
    const rest = agentRows.slice(head.length)
    const byKind = {}
    const nodeIds = new Set()
    const vulnIds = new Set()
    const commandIds = new Set()
    const shots = new Set()
    const highlights = []
    /* 按作者留存被压缩条目的计数与少量样本：按队员筛选时仍能看到「他被压缩了多少条」 */
    const authors = new Map()
    const addAuthor = (name, role, count, samples) => {
      const key = `${role}|${name}`
      const rec = authors.get(key) || { name, role, count: 0, samples: [] }
      rec.count += Number(count) || 0
      for (const sample of Array.isArray(samples) ? samples : []) {
        if (asText(sample) === '' || rec.samples.length >= 2) continue
        rec.samples.push(asText(sample))
      }
      authors.set(key, rec)
    }
    for (const row of head) {
      const kind = asText(row.kind, 'note')
      byKind[kind] = (byKind[kind] || 0) + 1
      const refs = row.refs || {}
      for (const id of Array.isArray(refs.nodeIds) ? refs.nodeIds : []) nodeIds.add(id)
      for (const id of Array.isArray(refs.vulnIds) ? refs.vulnIds : []) vulnIds.add(id)
      for (const id of Array.isArray(refs.commandIds) ? refs.commandIds : []) commandIds.add(id)
      for (const shot of Array.isArray(row.shots) ? row.shots : []) shots.add(shot)
      const mergedMeta = refs.merged && Array.isArray(refs.merged.authors) ? refs.merged.authors : null
      if (mergedMeta !== null) {
        /* 压缩摘要被再次压缩：继承里面每个作者的计数，不把「调度台」算成作者 */
        for (const sub of mergedMeta) addAuthor(asText(sub.name, '?'), asText(sub.role, 'system'), sub.count, sub.samples)
      } else {
        addAuthor((row.author && row.author.name) || '?', (row.author && row.author.role) || 'system', 1, [row.text])
      }
      if (kind === 'finding' && highlights.length < 3) {
        highlights.push(`· ${(row.author && row.author.name) || '?'}：${asText(row.text)}`)
      }
    }
    const span = `${new Date(Number(head[0].ts) || nowMs()).toLocaleString('zh-CN')} – ${new Date(Number(head[head.length - 1].ts) || nowMs()).toLocaleString('zh-CN')}`
    const kindText = Object.entries(byKind).map(([kind, count]) => `${kind} ${count}`).join(' / ')
    const authorText = Array.from(authors.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 8)
      .map((row) => `${row.name} ${row.count}`)
      .join(' / ')
    this.seq += 1
    const aiMerged = await this.aiMergeHead(head, options)
    const summaryText = aiMerged !== ''
      ? `${aiMerged}\n\n---\n📦 已合并 ${head.length} 条看板（${span}）；构成：${kindText}；按人：${authorText || '-'}`
      : [
      `📦 **已合并 ${head.length} 条看板**（${span}）`,
      `构成：${kindText}`,
      authorText !== '' ? `按人：${authorText}` : '',
      highlights.length > 0 ? `关键发现：\n${highlights.join('\n')}` : '',
      `引用保留：节点 ${nodeIds.size} / 漏洞 ${vulnIds.size} / 命令 ${commandIds.size}（点下方标签可直接跳）`,
    ].filter((line) => line !== '').join('\n')
    const summary = {
      id: `b${nowMs().toString(36)}${this.seq}`,
      /* 用被合并段的时间起点：按 ts 排序后它落回原位置，用户发言的时间线不会被打乱 */
      ts: Number(head[0].ts) || nowMs(),
      author: { role: 'system', name: '调度台' },
      kind: 'note',
      text: summaryText,
      summary: summaryText,
      refs: {
        nodeIds: Array.from(nodeIds).slice(0, 12),
        vulnIds: Array.from(vulnIds).slice(0, 12),
        commandIds: Array.from(commandIds).slice(0, 6),
        merged: {
          count: head.length,
          from: head[0].id,
          to: head[head.length - 1].id,
          at: nowMs(),
          authors: Array.from(authors.values()),
          entries: head,
        },
      },
      /* 被压缩条目的截图路径不能丢：文字进摘要，图片仍可在页面上单独查看 */
      shots: Array.from(shots),
    }
    const merged = [summary]
    for (const row of rest) merged.push(row)
    for (const row of userRows) merged.push(row)
    merged.sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0))
    rows.length = 0
    for (const row of merged) rows.push(row)
    try { this.hub.broadcast({ type: 'board.update', engagementId, entry: summary }) } catch { /* 忽略 */ }
    return summary
  }

  /** 删除一条看板（用户手动清理）。 */
  async remove(engagementId, id) {
    return this.withLock(engagementId, () => this.removeInner(engagementId, id))
  }

  async removeInner(engagementId, id) {
    const rows = await this.raw(engagementId)
    const index = rows.findIndex((item) => item.id === id)
    if (index < 0) return { ok: false, error: `看板条目不存在：${id}` }
    const [removed] = rows.splice(index, 1)
    await writeJsonAtomic(this.fileOf(engagementId), rows)
    try { this.hub.broadcast({ type: 'board.remove', engagementId, id }) } catch { /* 忽略 */ }
    return { ok: true, removed }
  }

  async update(engagementId, id, patch) {
    return this.withLock(engagementId, () => this.updateInner(engagementId, id, patch))
  }

  /** AI 语义合并：把最早 N 条 agent 看板压成一段真正的语义摘要。 */
  async aiMergeHead(head, options) {
    if (options.mergeMode !== 'ai') return ''
    const llm = this.ctx && typeof this.ctx.get === 'function' ? this.ctx.get('llm') : undefined
    if (llm === undefined || llm === null || typeof llm.stream !== 'function') return ''
    let selection = modelSelectionFor(this.ctx, this.configStore, options.mergeModel === 'deep' ? 'deep' : 'fast')
    if (asText(selection.provider) === '' || asText(selection.model) === '') {
      const fallback = this.ctx.get('agentDefaultModel')
      if (fallback !== undefined && fallback !== null && typeof fallback.currentSelection === 'function') {
        const current = fallback.currentSelection()
        if (current !== undefined && current !== null) selection = { ...current }
      }
    }
    if (asText(selection.provider) === '' || asText(selection.model) === '') return ''
    const payload = head.map((row) => [
      `[${asText(row.id)}] ${asText((row.author && row.author.name) || '?')} / ${asText(row.kind, 'note')}`,
      asText(row.text),
    ].join('\n')).join('\n\n---\n\n')
    let out = ''
    try {
      const stream = llm.stream({
        provider: asText(selection.provider),
        model: asText(selection.model),
        reasoningEffort: 'off',
        system: '你是看板语义合并器。把多条看板合并成一段真正的语义摘要：保留对象、结论、证据 commandId、未闭环事项和下一步；不要逐条复述，不要编造，不要输出前后解释。只输出摘要正文。',
        messages: [{ role: 'user', content: [{ type: 'text', text: `合并以下 ${head.length} 条看板：\n\n${payload}` }] }],
        maxTokens: 1200,
        temperature: 0.1,
      })
      for await (const chunk of stream) {
        if (chunk && chunk.type === 'text-delta' && typeof chunk.text === 'string') out += chunk.text
      }
    } catch {
      return ''
    }
    return asText(out)
  }

  /** 用一次独立 LLM 调用把已有正文提炼成真正的概括；正文永不改。 */
  async summarizeEntry(engagementId, id) {
    const rows = await this.raw(engagementId)
    const row = rows.find((item) => item.id === asText(id))
    if (row === undefined) throw new Error(`看板条目不存在：${id}`)
    if (this.isUserEntry(row)) throw new Error('用户看板条目不需要概括')
    const body = asText(row.text)
    if (body === '') throw new Error('看板正文为空，无法生成概括')
    const llm = this.ctx && typeof this.ctx.get === 'function' ? this.ctx.get('llm') : undefined
    if (llm === undefined || llm === null || typeof llm.stream !== 'function') throw new Error('llm 服务不可用，无法生成概括')
    let selection = modelSelectionFor(this.ctx, this.configStore, 'fast')
    if (asText(selection.provider) === '' || asText(selection.model) === '') {
      const fallback = this.ctx.get('agentDefaultModel')
      if (fallback !== undefined && fallback !== null && typeof fallback.currentSelection === 'function') {
        const current = fallback.currentSelection()
        if (current !== undefined && current !== null) selection = { ...current }
      }
    }
    if (asText(selection.provider) === '' || asText(selection.model) === '') throw new Error('没有可用模型，无法生成概括')
    let summary = ''
    try {
      const stream = llm.stream({
        provider: asText(selection.provider),
        model: asText(selection.model),
        system: '你是严格的看板概括器。只输出 1-3 句真正的语义概括，说明对象、位置、结论和下一步；禁止复制正文、禁止截断正文、禁止输出 Markdown 标题或前后解释。',
        messages: [{ role: 'user', content: [{ type: 'text', text: `请概括以下看板正文：\n\n${body}` }] }],
        maxTokens: 512,
        temperature: 0.1,
      })
      for await (const chunk of stream) {
        if (chunk && chunk.type === 'text-delta' && typeof chunk.text === 'string') summary += chunk.text
      }
    } catch (error) {
      throw new Error(`生成概括失败：${error && error.message ? error.message : String(error)}`)
    }
    summary = summary.trim()
    if (summary === '') throw new Error('模型没有返回概括')
    row.summary = summary
    await writeJsonAtomic(this.fileOf(engagementId), rows)
    try { this.hub.broadcast({ type: 'board.update', engagementId, entry: row }) } catch { /* 忽略 */ }
    return row
  }

  async updateInner(engagementId, id, patch) {
    const rows = await this.raw(engagementId)
    const row = rows.find((item) => item.id === id)
    if (row === undefined) throw new Error(`看板条目不存在：${id}`)
    if (asText(patch.text) !== '') row.text = asText(patch.text)
    if (Object.prototype.hasOwnProperty.call(patch, 'summary')) {
      const isUser = this.isUserEntry(row)
      row.summary = isUser ? '' : boardSummaryOf({ author: row.author, text: row.text, summary: patch.summary })
    }
    if (asText(patch.kind) !== '') row.kind = asText(patch.kind)
    await writeJsonAtomic(this.fileOf(engagementId), rows)
    try { this.hub.broadcast({ type: 'board.update', engagementId, entry: row }) } catch { /* 同上 */ }
    return row
  }

  forget(engagementId) {
    this.cache.delete(engagementId)
    const prefix = `${engagementId}:`
    for (const key of Array.from(this.viewed.keys())) if (key.startsWith(prefix)) this.viewed.delete(key)
  }

  async recentText(engagementId, limit = 12) {
    const rows = await this.list(engagementId, limit)
    if (rows.length === 0) return ''
    return rows
      .map((row) => {
        const summary = row.author && row.author.role === 'user' ? asText(row.text) : boardSummaryOf(row)
        return `- [${row.kind}] ${row.author && row.author.name ? row.author.name : '?'}: ${safePromptText(summary === '' ? '（未提供有效概括）' : summary)}`
      })
      .join('\n')
  }
}


/** 给 agent 的完整看板文本：用户发言全文 + 全部 agent 条目全文。 */
async function boardPromptText(board, engagementId, options = {}) {
  if (board === undefined || board === null) return ''
  try {
    await board.raw(engagementId)
    return board.promptText(engagementId, options)
  } catch {
    return ''
  }
}

/** 轨迹账（Trajectory）：谁在什么时候做了什么——调度、招募、技能、命令、图谱变更全部一条流。 */
class Trace {
  constructor(root, hub) {
    this.root = root
    this.hub = hub
    this.dir = join(root, 'trace')
    this.cache = new Map()
    this.seq = 0
    this.writeQueue = Promise.resolve()
  }

  fileOf(engagementId) {
    return join(this.dir, `${engagementId}.jsonl`)
  }

  async init() {
    await ensureDir(this.dir)
    return this
  }

  async raw(engagementId) {
    if (!this.cache.has(engagementId)) {
      let rows = []
      try {
        const text = await readFile(this.fileOf(engagementId), 'utf8')
        rows = text.split('\n').filter((line) => line.trim() !== '').map((line) => {
          try { return JSON.parse(line) } catch { return null }
        }).filter((row) => row !== null && typeof row === 'object')
      } catch { /* 没有历史 */ }
      this.cache.set(engagementId, rows)
    }
    return this.cache.get(engagementId)
  }

  async push(engagementId, event) {
    const run = this.writeQueue.then(() => this.pushInner(engagementId, event))
    this.writeQueue = run.then(() => undefined, () => undefined)
    return run
  }

  async pushInner(engagementId, event) {
    const rows = await this.raw(engagementId)
    this.seq += 1
    const row = {
      id: `e${Date.now().toString(36)}${this.seq}`,
      ts: nowMs(),
      kind: asText(event.kind, 'event'),
      actor: event.actor || { role: 'system', name: '系统' },
      title: asText(event.title, ''),
      detail: asText(event.detail),
      refs: event.refs || {},
      meta: event.meta || {},
    }
    rows.push(row)
    try {
      await appendFile(this.fileOf(engagementId), `${JSON.stringify(row)}\n`, 'utf8')
    } catch { /* 落盘失败不影响 */ }
    try { this.hub.broadcast({ type: 'trace', engagementId, event: row }) } catch { /* 广播失败 */ }
    return row
  }

  async list(engagementId, limit = 400) {
    const rows = await this.raw(engagementId)
    return rows.slice(-limit)
  }

  forget(engagementId) {
    this.cache.delete(engagementId)
  }
}

/** 任务账本：总指挥拆任务、成员执行、验收判定，一条任务一个状态机。 */
class Tasks {
  constructor(root, hub, trace) {
    this.root = root
    this.hub = hub
    this.trace = trace
    this.dir = join(root, 'tasks')
    this.cache = new Map()
    this.seq = 0
    this.locks = new Map()
  }

  withLock(id, operation) {
    const key = String(id)
    const previous = this.locks.get(key) || Promise.resolve()
    const next = previous.then(operation, operation)
    const tail = next.then(() => undefined, () => undefined)
    this.locks.set(key, tail)
    void tail.finally(() => { if (this.locks.get(key) === tail) this.locks.delete(key) })
    return next
  }

  fileOf(engagementId) {
    return join(this.dir, `${engagementId}.json`)
  }

  async init() {
    await ensureDir(this.dir)
    return this
  }

  rawSync(engagementId) {
    const rows = this.cache.get(engagementId)
    return Array.isArray(rows) ? rows : []
  }

  async raw(engagementId) {
    if (!this.cache.has(engagementId)) {
      let rows = []
      try {
        const raw = JSON.parse(await readFile(this.fileOf(engagementId), 'utf8'))
        if (Array.isArray(raw)) rows = raw
      } catch { /* 没有任务 */ }
      this.cache.set(engagementId, rows)
    }
    return this.cache.get(engagementId)
  }

  async list(engagementId, limit = 200) {
    const rows = await this.raw(engagementId)
    return rows.slice(-limit)
  }

  async save(engagementId, rows) {
    await writeJsonAtomic(this.fileOf(engagementId), rows)
  }

  async create(engagementId, input) {
    return this.withLock(engagementId, () => this.createInner(engagementId, input))
  }

  async createInner(engagementId, input) {
    const rows = await this.raw(engagementId)
    this.seq += 1
    const task = {
      id: `t${Date.now().toString(36).slice(-5)}${this.seq}`,
      title: asText(input.title, '未命名任务'),
      goal: asText(input.goal),
      acceptance: asText(input.acceptance),
      role: asText(input.role, 'web'),
      assignee: asText(input.assignee),
      status: 'open',
      createdBy: input.createdBy || { role: 'commander', name: '总指挥' },
      createdAt: nowMs(),
      evidence: { commandIds: [], vulnIds: [], nodeIds: [], shots: [] },
      note: '',
      followUpOf: asText(input.followUpOf) || null,
      verifiedBy: null,
      verifiedAt: null,
    }
    rows.push(task)
    await this.save(engagementId, rows)
    try { this.hub.broadcast({ type: 'task.created', engagementId, task }) } catch { /* 广播失败 */ }
    if (this.trace !== undefined && this.trace !== null) {
      await this.trace.push(engagementId, {
        kind: 'task',
        actor: task.createdBy,
        title: `拆任务 ${task.id}｜${task.title}`,
        detail: `负责角色：${task.role}\n目标：${task.goal || '-'}\n验收：${task.acceptance || '-'}`,
        refs: { taskId: task.id, role: task.role },
      })
    }
    return task
  }

  async update(engagementId, id, patch, actor) {
    return this.withLock(engagementId, () => this.updateInner(engagementId, id, patch, actor))
  }

  async updateInner(engagementId, id, patch, actor) {
    const rows = await this.raw(engagementId)
    const task = rows.find((row) => row.id === asText(id))
    if (task === undefined) throw new Error(`任务不存在：${id}`)
    if (asText(patch.status) !== '') {
      const status = asText(patch.status)
      if (!TASK_STATUSES.includes(status)) throw new Error(`任务状态非法：${status}`)
      task.status = status
    }
    if (asText(patch.assignee) !== '') task.assignee = asText(patch.assignee)
    if (asText(patch.note) !== '') task.note = asText(patch.note)
    if (asText(patch.role) !== '') task.role = asText(patch.role)
    if (asText(patch.title) !== '') task.title = asText(patch.title)
    if (asText(patch.goal) !== '') task.goal = asText(patch.goal)
    if (asText(patch.acceptance) !== '') task.acceptance = asText(patch.acceptance)
    if (patch.verifiedBy !== null && typeof patch.verifiedBy === 'object' && !Array.isArray(patch.verifiedBy)) {
      task.verifiedBy = { role: asText(patch.verifiedBy.role), name: asText(patch.verifiedBy.name) }
      task.verifiedAt = Number(patch.verifiedAt) || nowMs()
    }
    const evidence = patch.evidence
    if (evidence !== null && typeof evidence === 'object' && !Array.isArray(evidence)) {
      if (task.evidence === null || typeof task.evidence !== 'object') {
        task.evidence = { commandIds: [], vulnIds: [], nodeIds: [], shots: [] }
      }
      for (const key of ['commandIds', 'vulnIds', 'nodeIds', 'shots']) {
        if (!Array.isArray(evidence[key])) continue
        const merged = new Set([...(task.evidence[key] || []), ...evidence[key].map(String)])
        task.evidence[key] = Array.from(merged)
      }
    }
    task.updatedAt = nowMs()
    await this.save(engagementId, rows)
    try { this.hub.broadcast({ type: 'task.updated', engagementId, task }) } catch { /* 广播失败 */ }
    if (this.trace !== undefined && this.trace !== null) {
      const who = actor !== undefined && actor !== null ? actor : { role: 'system', name: '操作台' }
      const verdict = task.status === 'passed' || task.status === 'failed'
      await this.trace.push(engagementId, {
        kind: verdict ? 'verdict' : 'task',
        actor: who,
        title: `任务 ${task.id} → ${task.status}｜${task.title}`,
        detail: task.note || '',
        refs: { taskId: task.id, role: task.role, ...(task.evidence || {}) },
      })
    }
    return task
  }

  /** 驳回 → 生成（或复用）返工任务：标题不嵌套、根任务唯一、已有未闭环返工就合并。 */
  async rework(engagementId, task, reason, createdBy) {
    return this.withLock(engagementId, () => this.reworkInner(engagementId, task, reason, createdBy))
  }

  async reworkInner(engagementId, task, reason, createdBy) {
    const rows = await this.raw(engagementId)
    /* 沿 followUpOf 一路回溯到真正的根任务（历史数据里可能存在 A→B→C 的返工套娃） */
    let rootId = task.id
    const seen = new Set([task.id])
    let cursor = task
    for (let depth = 0; depth < 50; depth += 1) {
      const parentId = asText(cursor.followUpOf)
      if (parentId === '') break
      const parent = rows.find((row) => row.id === parentId)
      if (parent === undefined) { rootId = parentId; break }
      if (seen.has(parent.id)) break
      seen.add(parent.id)
      rootId = parent.id
      cursor = parent
    }
    const rootTitle = String(task.title || '任务').replace(/^(返工[:：])+/, '')
    /* 顺手把被驳回任务的 followUpOf 校正到根，后续查找才一致 */
    if (asText(task.followUpOf) !== rootId) {
      const self = rows.find((row) => row.id === task.id)
      if (self !== undefined) {
        self.followUpOf = rootId
        await this.save(engagementId, rows)
      }
    }
    const existing = rows.find((row) => row.followUpOf === rootId
      && row.status !== 'passed' && row.status !== 'failed')
    if (existing !== undefined) {
      existing.note = `${existing.note ? `${existing.note}；` : ''}再次驳回：${reason}`
      existing.updatedAt = nowMs()
      await this.save(engagementId, rows)
      try { this.hub.broadcast({ type: 'task.updated', engagementId, task: existing }) } catch { /* 广播失败 */ }
      return existing
    }
    return this.createInner(engagementId, {
      title: `返工：${rootTitle}`,
      goal: `原任务 ${task.id} 未通过验收。缺口：${reason}。请重新拆解并派给合适角色。`,
      acceptance: task.acceptance,
      role: 'commander',
      createdBy,
      followUpOf: rootId,
    })
  }

  missionFile(engagementId) {
    return join(this.dir, `${engagementId}.mission.json`)
  }

  async missionOf(engagementId) {
    try {
      const raw = JSON.parse(await readFile(this.missionFile(engagementId), 'utf8'))
      return raw !== null && typeof raw === 'object' ? raw : null
    } catch { return null }
  }

  async setMission(engagementId, input) {
    const prev = await this.missionOf(engagementId)
    const mission = {
      goal: asText(input.goal, prev === null ? '' : asText(prev.goal)),
      done: asText(input.done, prev === null ? '' : asText(prev.done)),
      status: asText(input.status, prev === null ? 'running' : asText(prev.status, 'running')),
      rounds: (() => {
        const prevRounds = prev === null || prev === undefined ? 0 : Number(prev.rounds)
        const fallback = Number.isFinite(prevRounds) ? prevRounds : 0
        /* 显式传 rounds 时以传入为准（返工/重登记会 +1）；没传就保持上一轮的值 */
        const wanted = input.rounds === undefined || input.rounds === null || input.rounds === ''
          ? Number.NaN
          : Number(input.rounds)
        return Number.isFinite(wanted) ? wanted : fallback
      })(),
      createdAt: prev === null ? nowMs() : prev.createdAt,
      updatedAt: nowMs(),
      closedAt: asText(input.status) === 'done' ? nowMs() : (prev === null ? null : prev.closedAt || null),
    }
    await writeJsonAtomic(this.missionFile(engagementId), mission)
    try { this.hub.broadcast({ type: 'mission', engagementId, mission }) } catch { /* 广播失败 */ }
    if (this.trace !== undefined && this.trace !== null) {
      await this.trace.push(engagementId, {
        kind: 'plan',
        actor: { role: 'commander', name: '总指挥' },
        title: mission.status === 'done' ? '宣布任务完成' : `登记作战目标（第 ${mission.rounds + 1} 轮）`,
        detail: [mission.goal ? `目标：${mission.goal}` : '', mission.done ? `完成判据：${mission.done}` : ''].filter((x) => x !== '').join('\n'),
        meta: { op: 'mission', status: mission.status },
      })
    }
    return mission
  }

  async stats(engagementId) {
    const rows = await this.raw(engagementId)
    const out = { total: rows.length, open: 0, doing: 0, blocked: 0, passed: 0, failed: 0 }
    for (const row of rows) {
      if (out[row.status] !== undefined) out[row.status] += 1
    }
    return out
  }

  forget(engagementId) {
    this.cache.delete(engagementId)
  }
}

/** 浏览器操作器：每次动作 = 一个 chromium 会话（storageState 持久化登录态）。 */
class BrowserRunner {
  constructor(root, hub) {
    this.root = root
    this.hub = hub
    this.dir = join(root, 'browser')
    this.script = resolve(fileURLToPath(new URL('.', import.meta.url)), 'browser_runner.py')
    this.seq = 0
  }

  async shot(engagementId) {
    return join(this.dir, engagementId, `shot-${nowMs()}-${Math.random().toString(36).slice(2, 7)}.png`)
  }

  async run(engagementId, request) {
    await ensureDir(join(this.dir, engagementId))
    const statePath = join(this.dir, engagementId, 'state.json')
    const action = asText(request.action, 'goto')
    const payload = {
      action,
      url: asText(request.url),
      selector: asText(request.selector),
      value: asText(request.value),
      text: asText(request.text),
      expression: asText(request.expression),
      x: Number.isFinite(request.x) ? request.x : null,
      y: Number.isFinite(request.y) ? request.y : null,
      steps: Array.isArray(request.steps) ? request.steps : [],
      headless: request.headless !== false,
      statePath,
      outDir: join(this.dir, engagementId),
      shotPath: await this.shot(engagementId),
      timeoutMs: Number.isFinite(request.timeoutMs) ? Math.max(1000, Math.min(30 * 60 * 1000, request.timeoutMs)) : 20000,
      maxChars: Number.isFinite(request.maxChars) ? Math.max(500, Math.min(200000, request.maxChars)) : 6000,
    }
    const outcome = await new Promise((resolvePromise) => {
      const payloadJson = JSON.stringify(payload)
      const candidates = pythonCandidates()
      let index = 0
      let settled = false
      const done = (value) => { if (!settled) { settled = true; resolvePromise(value) } }
      const attempt = () => {
        const python = candidates[index]
        let child
        let superseded = false
        try {
          child = spawn(python, [this.script, payloadJson], {
            /* POSIX 上建独立进程组，超时才能连同 Chromium 子进程一起杀。 */
            cwd: this.root, detached: !IS_WIN, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
          })
        } catch (error) {
          next(error)
          return
        }
        let out = ''
        let err = ''
        const timer = setTimeout(() => { killProcessTree(child) }, payload.timeoutMs + 20000)
        child.stdout.on('data', (chunk) => {
          if (out.length < 8 * 1024 * 1024) out += chunk.toString('utf8')
        })
        child.stderr.on('data', (chunk) => {
          if (err.length < 2 * 1024 * 1024) err += chunk.toString('utf8')
        })
        child.on('error', (error) => {
          clearTimeout(timer)
          if (error && error.code === 'ENOENT') {
            superseded = true
            next(error)
            return
          }
          done({ ok: false, error: `${python} 启动失败：${error.message}` })
        })
        child.on('close', (code) => {
          clearTimeout(timer)
          if (settled || superseded) return
          const line = out.trim().split('\n').filter((l) => l.trim() !== '').pop() || ''
          let parsed
          try { parsed = JSON.parse(line) } catch { parsed = undefined }
          if (parsed === undefined) {
            done({ ok: false, error: `浏览器动作失败（exit ${code}）：${shortText(err || out, 600)}` })
            return
          }
          done(parsed)
        })
      }
      const next = (error) => {
        index += 1
        if (index < candidates.length) { attempt(); return }
        done({
          ok: false,
          error: `无法启动 Python（试过 ${candidates.join(' / ')}）：${error && error.message ? error.message : error}。可设 DSH_RECON_PYTHON 指定解释器路径`,
        })
      }
      attempt()
    })
    if (outcome && outcome.ok) {
      try {
        this.hub.broadcast({
          type: 'browser.shot',
          engagementId,
          shot: outcome.shot || null,
          url: outcome.url || payload.url,
          title: outcome.title || '',
        })
      } catch { /* 广播失败 */ }
    }
    return outcome
  }
}

/** 多智能体队伍：每个成员一个独立会话，共享同一份图谱与看板。 */
/** 角色中文名（离职交接里用）。 */
const HOST_ROLE_LABEL = {
  commander: '总指挥', lead: '总指挥', staff: '参谋', scout: '信息收集', web: 'Web 手',
  hunter: '猎手', browser: '浏览器', reverser: '逆向手', intranet: '内网手', qa: '验收', analyst: '分析',
}
const roleLabelOf = (role) => HOST_ROLE_LABEL[role] || asText(role, '队员')
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** 传给 agent 的文本一律消毒：双花括号会被 prompt 模板当成变量，破坏整个会话。 */
function safePromptText(text) {
  return String(text === undefined || text === null ? '' : text)
    .replace(/\{\{/g, '{ {')
    .replace(/\}\}/g, '} }')
}

/** 常驻核心角色：总指挥与参谋全局各一个，不可召唤、不参与空闲回收，掉了自动补位。 */
const CORE_ROLE_IDS = ['commander', 'staff']
const CORE_ROLES = new Set(CORE_ROLE_IDS)
const DEFAULT_CORE_ROLES = DEFAULT_ROLES.filter((role) => CORE_ROLES.has(role.id))
const DEFAULT_MEMBER_ROLES = DEFAULT_ROLES.filter((role) => !CORE_ROLES.has(role.id))

class Squad {
  constructor({ ctx, store, cfg, configStore, hub, board, tasks, trace, browsers, cockpit }) {
    this.ctx = ctx
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.board = board
    this.tasks = tasks
    this.trace = trace
    this.browsers = browsers
    this.cockpit = cockpit
    this.members = new Map()
    /* 小组：同一任务内多个角色共享上下文，小组整体只算一个并发；成员之间通过 groupAsk 串行协作。 */
    this.groups = new Map()
    this.seq = 0
    this.groupSeq = 0
    this.promptCache = new Map()
    /* 花名册 key→名字，永久保存：历史看板/任务正文里写的 a7 也要能翻成「验收#1」 */
    this.roster = new Map()
    this.rosterLoaded = false
    /* 成员专属 MCP：key → [{ 全局注册名, disposer }]，成员销毁时一并注销 */
    this.memberMcp = new Map()
    this.transcripts = new Map()
    this.saveTimers = new Map()
  }

  chatFile(engagementId, key) {
    return join(this.cfg.root, 'chat', `${engagementId}-${key}.json`)
  }

  async transcriptOf(member) {
    if (!this.transcripts.has(member.key)) {
      let rows = []
      try {
        const raw = JSON.parse(await readFile(this.chatFile(member.engagementId, member.key), 'utf8'))
        if (Array.isArray(raw)) rows = raw
      } catch { /* 没有历史 */ }
      this.transcripts.set(member.key, rows)
    }
    return this.transcripts.get(member.key)
  }

  pushTranscript(member, record) {
    const rows = this.transcripts.get(member.key)
    if (rows === undefined) return
    rows.push(record)
    clearTimeout(this.saveTimers.get(member.key))
    this.saveTimers.set(member.key, setTimeout(() => {
      ensureDir(join(this.cfg.root, 'chat'))
        .then(() => writeFile(this.chatFile(member.engagementId, member.key), `${JSON.stringify(rows, null, 2)}\n`, 'utf8'))
        .catch(() => { /* 落盘失败不影响 */ })
    }, 600))
  }

  /** 用户直接找某个队员说话。 */
  async chat(memberRef, text, options = {}) {
    let member
    try { member = this.resolveMemberRef(memberRef, asText(options.engagement)) } catch { member = undefined }
    if (member === undefined && asText(options.role) !== '') {
      /* 按角色对话：该角色还没有在岗实例 → 现开一个（fast 档，任务=入列待命） */
      const roleId = asText(options.role)
      const coreId = this.coreRoleIdOf(roleId)
      if (coreId !== '') {
        const core = this.coreRoles().find((role) => role.id === coreId)
        throw new Error(`${core !== undefined ? core.name : coreId} 是常设席位，不能按角色召唤；请在「对话」里直接找这个席位，或用 recon_squad task 派活`)
      }
      const engagementId = asText(options.engagement) !== ''
        ? asText(options.engagement)
        : (await this.store.activeEngagement() || {}).id
      if (asText(engagementId) === '') throw new Error('还没有靶标')
      const resolvedRole = this.roleOf(roleId)
      const directRole = this.roles().find((role) => role.id === roleId || role.name === roleId)
      if (directRole === undefined && ROLE_ALIASES[roleId] === undefined && this.coreRoleIdOf(roleId) === '') {
        throw new Error(`未知角色：${roleId}。可用角色：${this.roles().map((role) => `${role.id}(${role.name})`).join(', ')}`)
      }
      const spawned = await this.spawn({
        engagementId,
        roleId: resolvedRole.id,
        tier: asText(options.tier),
        name: asText(options.name),
        task: '入列待命：等指挥官给指令',
        origin: 'chat',
      })
      /* spawn 返回的是视图对象，发消息要拿真正的成员实例（带 agent） */
      member = this.members.get(spawned.key)
    }
    if (member === undefined) throw new Error(`成员不存在：${memberRef}`)
    const message = asText(text)
    if (message === '') throw new Error('消息不能为空')
    await this.transcriptOf(member)
    const record = { id: `u_${nowMs().toString(36)}`, role: 'user', text: message, ts: nowMs(), author: '你' }
    this.pushTranscript(member, record)
    this.hub.broadcast({ type: 'squad.chat', engagementId: member.engagementId, key: member.key, message: record })
    member.status = 'running'
    this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
    await this.refreshPrompt(member)
    member.agent.followup({
      id: record.id,
      role: 'user',
      content: [{ type: 'text', text: message }],
      source: { kind: 'user' },
    })
    return this.view(member)
  }

  /** 可派遣的队员角色：总指挥/参谋已经被移出，只保留普通角色与临时角色。 */
  roles() {
    const configured = this.configStore.get().roles
    const raw = configured && Array.isArray(configured.squad) && configured.squad.length > 0 ? configured.squad : DEFAULT_MEMBER_ROLES
    const list = raw.filter((role) => role !== null && typeof role === 'object' && !CORE_ROLES.has(asText(role.id)))
    return list.length > 0 ? list : DEFAULT_MEMBER_ROLES
  }

  /** 常设席位：总指挥/参谋各一个，配置从 config.core 读，缺省用内置人设。 */
  coreRoles() {
    const saved = this.configStore.get().core
    return CORE_ROLE_IDS.map((id) => {
      const base = DEFAULT_CORE_ROLES.find((role) => role.id === id)
      const custom = saved !== null && typeof saved === 'object' && saved[id] !== null && typeof saved[id] === 'object' ? saved[id] : {}
      const role = mergeDeep(cloneJson(base), custom)
      role.id = id
      role.name = asText(role.name, base.name)
      role.tier = MODEL_CHOICES.includes(asText(role.tier)) ? asText(role.tier) : base.tier
      role.reportsTo = id === 'commander' ? null : 'commander'
      role.skills = asList(role.skills)
      role.mcp = asMcpList(role.mcp)
      role.core = true
      return role
    })
  }

  /** id / 名字 / 别名 → 常设席位 id；不是常设席位返回空串。 */
  coreRoleIdOf(id) {
    const wanted = asText(id)
    if (wanted === '') return ''
    const resolved = ROLE_ALIASES[wanted] || wanted
    if (CORE_ROLES.has(resolved)) return resolved
    const hit = this.coreRoles().find((role) => role.id === wanted || role.name === wanted)
    return hit !== undefined ? hit.id : ''
  }

  roleOf(id) {
    const wanted = asText(id)
    const coreId = this.coreRoleIdOf(wanted)
    if (coreId !== '') return this.coreRoles().find((role) => role.id === coreId)
    const roles = this.roles()
    const direct = roles.find((role) => role.id === wanted || role.name === wanted)
    if (direct !== undefined) return direct
    const alias = ROLE_ALIASES[wanted]
    if (alias !== undefined) {
      const hit = roles.find((role) => role.id === alias)
      if (hit !== undefined) return hit
    }
    return roles.find((role) => role.id === 'web') || roles[0] || DEFAULT_MEMBER_ROLES[0]
  }

  /** 老配置迁移：把 roles.squad 里的总指挥/参谋挪到 core，保留用户改过的人设。 */
  async migrateCoreRoles() {
    const config = this.configStore.get()
    const squad = config.roles && Array.isArray(config.roles.squad) ? config.roles.squad : []
    const legacy = squad.filter((row) => row !== null && typeof row === 'object' && CORE_ROLES.has(asText(row.id)))
    if (legacy.length === 0) return false
    const members = squad.filter((row) => row !== null && typeof row === 'object' && !CORE_ROLES.has(asText(row.id)))
    const core = { ...(config.core !== null && typeof config.core === 'object' ? config.core : {}) }
    for (const row of legacy) {
      const id = asText(row.id)
      core[id] = { ...(core[id] !== null && typeof core[id] === 'object' ? core[id] : {}), ...row, id }
    }
    await this.configStore.patch({
      core,
      roles: { squad: members.length > 0 ? members : DEFAULT_MEMBER_ROLES.map((role) => ({ ...role })) },
    })
    return true
  }

  /** 老配置的 scout 提示词如果没有 Nday 职能，自动补进去（幂等，保留原有自定义内容）。 */
  async upgradeScoutPrompt() {
    const configured = this.configStore.get().roles
    const squad = configured && Array.isArray(configured.squad) ? configured.squad : []
    const index = squad.findIndex((role) => role !== null && typeof role === 'object' && asText(role.id) === 'scout')
    if (index < 0) return false
    const prompt = String(squad[index].prompt || '')
    const legacyWithOldNday = SCOUT_PROMPT_LEGACY.replace(SCOUT_NDAY_PROMPT, SCOUT_NDAY_PROMPT_LEGACY)
    let nextPrompt = prompt
    /* 只升级旧版内置默认文本；用户自己写过的提示词保持原样。 */
    if (prompt === SCOUT_PROMPT_LEGACY || prompt === legacyWithOldNday
      || ((prompt.startsWith('你是信息收集手（Scout）。只做测绘') || prompt.startsWith('你是信息收集手（Scout）。你负责在授权范围内扩大并整理攻击面'))
        && !prompt.includes('全端口扫描'))) {
      nextPrompt = SCOUT_PROMPT
    } else if (nextPrompt.includes(SCOUT_NDAY_PROMPT_LEGACY)) {
      nextPrompt = nextPrompt.replace(SCOUT_NDAY_PROMPT_LEGACY, SCOUT_NDAY_PROMPT)
    } else if (!nextPrompt.includes('recon_nday')) {
      nextPrompt = nextPrompt === '' ? SCOUT_NDAY_PROMPT : `${nextPrompt}\n\n${SCOUT_NDAY_PROMPT}`
    }
    if (nextPrompt === prompt) return false
    const next = squad.slice()
    next[index] = { ...next[index], prompt: nextPrompt }
    await this.configStore.patch({ roles: { squad: next } })
    return true
  }

  /** 升级旧版内置 Web 手提示词；用户自定义内容不覆盖。 */
  async upgradeWebPrompt() {
    const configured = this.configStore.get().roles
    const squad = configured && Array.isArray(configured.squad) ? configured.squad : []
    const index = squad.findIndex((role) => role !== null && typeof role === 'object' && asText(role.id) === 'web')
    if (index < 0) return false
    if (String(squad[index].prompt || '') !== WEB_PROMPT_LEGACY) return false
    const next = squad.slice()
    next[index] = { ...next[index], prompt: WEB_PROMPT }
    await this.configStore.patch({ roles: { squad: next } })
    return true
  }

  /** 升级旧版内置参谋提示词；用户自定义内容不覆盖。 */
  async upgradeStaffPrompt() {
    const core = this.configStore.get().core
    const staff = core && typeof core === 'object' && core.staff && typeof core.staff === 'object' ? core.staff : null
    if (staff === null) return false
    const prompt = String(staff.prompt || '')
    const legacy = prompt === STAFF_PROMPT_LEGACY
      || (prompt.startsWith('你是参谋（Staff）。只出谋划策') && !prompt.includes('## 每次进入项目先做环境检查'))
    if (!legacy) return false
    await this.configStore.patch({ core: { staff: { ...staff, prompt: STAFF_PROMPT } } })
    return true
  }

  /** 临时角色：不在编制里的名字也能开工（写工具、做报告…），并持久化进配置复用。 */
  async ensureRole({ roleId, roleName, rolePrompt, reportsTo, skills, model }) {
    const id = asText(roleId, '').trim()
    if (id === '') return undefined
    const coreId = this.coreRoleIdOf(id)
    if (coreId !== '') {
      const core = this.coreRoles().find((role) => role.id === coreId)
      throw new Error(`${core !== undefined ? core.name : coreId} 是常设席位，不能作为队员角色新增；请在控制台「常设席位」里改`)
    }
    const roles = this.roles()
    const hit = roles.find((role) => role.id === id)
    if (hit !== undefined) return hit
    const temp = {
      id,
      name: asText(roleName, id),
      tier: 'deep',
      reportsTo: asText(reportsTo, 'commander'),
      prompt: asText(rolePrompt, `你是${asText(roleName, id)}，按总指挥下发任务执行；产出结论写进看板，需要复现就留命令证据。`),
      skills: asList(skills),
      model: model && typeof model === 'object' ? model : null,
      temporary: true,
    }
    /* 只保存过滤后的队员角色：老配置里残留的常设席位不能跟着写回去 */
    await this.configStore.patch({ roles: { squad: [...roles.map((role) => ({ ...role })), temp] } })
    return temp
  }

  modelFor(tier) {
    return modelSelectionFor(this.ctx, this.configStore, tier)
  }

  activeCount(engagementId) {
    /* 小组整体算一个并发：组内多个成员同时有活动也只计数一次。 */
    const groups = new Set()
    let ungrouped = 0
    for (const member of this.members.values()) {
      if (member.engagementId !== engagementId) continue
      const active = member.status === 'running' || member.status === 'starting' || member.status === 'waiting'
      if (!active) continue
      const group = member.groupId ? this.groups.get(member.groupId) : undefined
      if (group !== undefined) groups.add(group.id)
      else ungrouped += 1
    }
    return ungrouped + groups.size
  }

  groupView(group) {
    if (group === undefined || group === null) return null
    const members = group.memberKeys.map((key) => {
      const member = this.members.get(key)
      return member === undefined ? null : this.view(member)
    }).filter(Boolean)
    return {
      id: group.id,
      engagementId: group.engagementId,
      lead: group.leadKey,
      status: group.status,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
      members,
      messages: group.messages.map((message) => ({ ...message })),
    }
  }

  listGroups(engagementId) {
    return Array.from(this.groups.values())
      .filter((group) => engagementId === undefined || group.engagementId === engagementId)
      .map((group) => this.groupView(group))
  }

  groupPromptText(member) {
    const group = member && member.groupId ? this.groups.get(member.groupId) : undefined
    if (group === undefined) return ''
    const lines = []
    lines.push('')
    lines.push('## 你的协作小组（组内串行）')
    lines.push(`组 id：${group.id}；组内成员：${group.memberKeys.map((key) => {
      const item = this.members.get(key)
      return item === undefined ? key : `${item.name}(${this.roleOf(item.role).name}/${item.status})`
    }).join('、')}`)
    lines.push('规则：小组整体只算一个并发；同一时间只推进一个成员的步骤；需要别人处理时使用 `recon_group ask`，对方回复后你再继续。')
    for (const message of group.messages) {
      const who = asText(message.from, '成员')
      const to = asText(message.to)
      lines.push(`- [${asText(message.kind, 'note')}] ${who}${to !== '' ? ` → ${to}` : ''}：${safePromptText(asText(message.text))}`)
    }
    return lines.join('\n')
  }

  groupAddMessage(group, message) {
    if (group === undefined || group === null) return null
    group.messages.push({
      id: `gm${nowMs().toString(36)}${Math.random().toString(36).slice(2, 5)}`,
      ts: nowMs(),
      kind: asText(message.kind, 'note'),
      from: asText(message.from, '成员'),
      to: asText(message.to),
      text: asText(message.text),
    })
    /* 小组消息是临时协作上下文，保留足够长的历史，防止单个小组无限膨胀 */
    group.updatedAt = nowMs()
    this.hub.broadcast({ type: 'squad.group', engagementId: group.engagementId, group: this.groupView(group) })
    return group.messages[group.messages.length - 1]
  }

  removeMemberFromGroup(member) {
    if (member === undefined || member === null || member.groupId === undefined || member.groupId === null) return
    const group = this.groups.get(member.groupId)
    member.groupId = null
    if (group === undefined) return
    group.memberKeys = group.memberKeys.filter((key) => key !== member.key)
    group.updatedAt = nowMs()
    if (group.memberKeys.length === 0) this.groups.delete(group.id)
    else this.hub.broadcast({ type: 'squad.group', engagementId: group.engagementId, group: this.groupView(group) })
  }

  /** 等待成员空闲；小组协作是串行的，目标还在跑就等它结束。 */
  async waitMemberIdle(member, timeoutMs = 120000) {
    const deadline = nowMs() + Math.max(1000, Number(timeoutMs) || 120000)
    while (nowMs() < deadline) {
      if (member.status !== 'running' && member.status !== 'starting' && member.status !== 'waiting') return true
      await sleep(120)
    }
    return false
  }

  memberCount(engagementId) {
    let count = 0
    for (const member of this.members.values()) {
      if (engagementId === undefined || member.engagementId === engagementId) count += 1
    }
    return count
  }

  /** 创建/扩展一个协作小组。组内成员共享 groupPromptText，整体只算一个并发。 */
  async createGroup({ engagementId, leadKey, roleId, name, tier, task, promptExtra, skills, mcp }) {
    const lead = this.resolveMemberRef(leadKey, engagementId)
    if (lead === undefined) throw new Error(`组长不存在：${leadKey}`)
    if (CORE_ROLES.has(lead.role)) throw new Error('常设席位不能作为小组的普通成员')
    let group = lead.groupId ? this.groups.get(lead.groupId) : undefined
    if (group === undefined) {
      this.groupSeq += 1
      group = {
        id: `g${nowMs().toString(36)}${this.groupSeq}${Math.random().toString(36).slice(2, 5)}`,
        engagementId,
        leadKey: lead.key,
        memberKeys: [lead.key],
        status: 'active',
        task: asText(task),
        createdAt: nowMs(),
        updatedAt: nowMs(),
        messages: [],
        lock: Promise.resolve(),
      }
      lead.groupId = group.id
      this.groups.set(group.id, group)
      this.groupAddMessage(group, {
        kind: 'task', from: '总指挥', to: lead.name,
        text: `建立小组，组长：${lead.name}。小组任务：${asText(task) || '由组长在需要时提出协作请求。'}`,
      })
    }
    const spawned = await this.spawn({
      engagementId,
      roleId,
      tier,
      task: '',
      origin: 'group',
      name,
      promptExtra: `${asText(promptExtra)}\n\n你当前是协作小组 ${group.id} 的成员；小组内串行协作，只有当前执行者工作。需要组长信息时先看组内消息；收到 recon_group ask 后直接完成并回复，不要把任务转给下一个人。`,
      skills,
      mcp,
    })
    const member = this.members.get(spawned.key)
    if (member === undefined) throw new Error('小组成员创建后未落位')
    member.groupId = group.id
    group.memberKeys.push(member.key)
    group.updatedAt = nowMs()
    this.groupAddMessage(group, {
      kind: 'member', from: '总指挥', to: member.name,
      text: `加入小组 ${group.id}，负责角色：${this.roleOf(member.role).name}。模型：${member.model || member.tier}；技能：${(Array.isArray(member.skills) ? member.skills : []).join(', ') || '无'}；MCP：${asMcpList(member.mcp).map((row) => row.name).join(', ') || '无'}。`,
    })
    await this.refreshPrompt(lead)
    await this.refreshPrompt(member)
    return this.groupView(group)
  }

  /** 组内串行提问：调用者暂停等待，目标成员完成后再返回结果。 */
  async groupAsk(groupId, fromKey, targetKey, question, timeoutMs = 300000) {
    const group = this.groups.get(groupId)
    if (group === undefined) throw new Error(`小组不存在：${groupId}`)
    const from = this.resolveMemberRef(fromKey, group.engagementId)
    const target = this.resolveMemberRef(targetKey, group.engagementId)
    if (from === undefined || target === undefined) throw new Error('小组提问的成员不存在')
    if (from.groupId !== group.id || target.groupId !== group.id) throw new Error('提问双方必须属于同一个小组')
    if (from.key === target.key) throw new Error('不能向自己提问')
    if (target.agent === null || target.agent === undefined) throw new Error(`目标成员不可用：${target.name}`)
    const text = asText(question)
    if (text === '') throw new Error('group ask 需要 question')
    const run = group.lock.then(async () => {
      from.status = 'waiting'
      from.waitingFor = target.name
      this.hub.broadcast({ type: 'squad.status', engagementId: group.engagementId, member: this.view(from) })
      try {
        this.groupAddMessage(group, { kind: 'question', from: from.name, to: target.name, text })
        const idle = await this.waitMemberIdle(target, Math.max(5000, Number(timeoutMs) || 300000))
        if (!idle) throw new Error(`小组成员 ${target.name} 仍在执行上一个任务，暂时不能接收新问题`)
        let answer = ''
        let timedOut = false
        await new Promise((resolve) => {
          let settled = false
          let timer = 0
          const done = (value, timeout) => {
            if (settled) return
            settled = true
            clearTimeout(timer)
            timedOut = timeout
            answer = value
            resolve()
          }
          target.answerWaiters = Array.isArray(target.answerWaiters) ? target.answerWaiters : []
          const waiter = (value) => done(asText(value), false)
          target.answerWaiters.push(waiter)
          timer = setTimeout(() => {
            target.answerWaiters = target.answerWaiters.filter((item) => item !== waiter)
            done('', true)
          }, Math.max(5000, Number(timeoutMs) || 300000))
          this.taskByMember(target, `【小组 ${group.id} · ${from.name} 的协作请求】${text}\n完成后直接回复结果，组长会等待你的答复。`, { groupSerial: false }).catch((error) => {
            target.answerWaiters = target.answerWaiters.filter((item) => item !== waiter)
            done(`执行出错：${error && error.message ? error.message : String(error)}`, false)
          })
        })
        if (timedOut) {
          this.groupAddMessage(group, { kind: 'timeout', from: target.name, to: from.name, text: `等待超过 ${Math.round((Number(timeoutMs) || 300000) / 1000)} 秒，未收到结果。` })
          return { ok: false, timeout: true, error: `等待 ${target.name} 回复超时`, groupId: group.id }
        }
        this.groupAddMessage(group, { kind: 'answer', from: target.name, to: from.name, text: answer })
        try { await this.refreshPrompt(from) } catch { /* 下一轮仍会重新渲染 */ }
        return { ok: true, groupId: group.id, from: from.name, to: target.name, answer }
      } finally {
        from.waitingFor = ''
        if (from.status === 'waiting') from.status = 'running'
        this.hub.broadcast({ type: 'squad.status', engagementId: group.engagementId, member: this.view(from) })
      }
    })
    group.lock = run.then(() => undefined, () => undefined)
    return run
  }

  async groupPost(groupId, fromKey, text) {
    const group = this.groups.get(groupId)
    if (group === undefined) throw new Error(`小组不存在：${groupId}`)
    const from = this.resolveMemberRef(fromKey, group.engagementId)
    if (from === undefined || from.groupId !== group.id) throw new Error('只有小组成员可以发组内消息')
    const body = asText(text)
    if (body === '') throw new Error('组内消息不能为空')
    this.groupAddMessage(group, { kind: 'note', from: from.name, text: body })
    for (const key of group.memberKeys) {
      const item = this.members.get(key)
      if (item !== undefined) { try { await this.refreshPrompt(item) } catch { /* 下一轮再更新 */ } }
    }
    return this.groupView(group)
  }

  /** 结束一个小组：组内每个成员各自产出离职交接后一起回收。 */
  async closeGroup(groupId, engagementId) {
    const group = this.groups.get(groupId)
    if (group === undefined) throw new Error(`小组不存在：${groupId}`)
    if (engagementId !== undefined && group.engagementId !== engagementId) throw new Error('小组不属于当前靶标')
    group.status = 'closing'
    const keys = Array.from(group.memberKeys)
    for (const key of keys) {
      const member = this.members.get(key)
      if (member === undefined) continue
      try { member.agent?.cancel?.({ kind: 'user', reason: 'group-close' }) } catch { /* 已停 */ }
      member.status = 'idle'
    }
    const reclaimed = []
    for (const key of keys) {
      try {
        const result = await this.remove(key, { reason: '小组任务结束', handover: true, engagementId: group.engagementId })
        if (result !== undefined && result.ok !== false) reclaimed.push(result)
      } catch { /* 单个交接失败不阻断其它成员 */ }
    }
    this.groups.delete(group.id)
    return { ok: true, groupId: group.id, reclaimed }
  }

  /** 空闲成员回收：默认 15 分钟没人用就 dispose，避免长会话堆积 agent。 */
  async pruneIdle(ttlMs = 900000, engagementId) {
    const now = nowMs()
    let removed = 0
    for (const member of Array.from(this.members.values())) {
      if (asText(engagementId) !== '' && member.engagementId !== asText(engagementId)) continue
      if (member.status === 'running' || member.status === 'starting' || member.status === 'waiting') continue
      if (CORE_ROLES.has(member.role)) continue /* 总指挥/参谋常驻，不回收 */
      const idleSince = member.idleSince || member.startedAt || now
      if (now - idleSince < ttlMs) continue
      try { await this.handover(member, '空闲回收') } catch { /* 交接失败照常释放 */ }
      try { await member.handle.dispose() } catch { /* 已释放 */ }
      this.uninstallMemberMcp(member.key)
      this.members.delete(member.key)
      this.removeMemberFromGroup(member)
      this.promptCache.delete(member.key)
      this.transcripts.delete(member.key)
      this.browsers?.drop?.(member.engagementId, member.sessionId)
      const timer = this.saveTimers.get(member.key)
      if (timer !== undefined) clearTimeout(timer)
      this.saveTimers.delete(member.key)
      removed += 1
      this.hub.broadcast({ type: 'squad.remove', engagementId: member.engagementId, key: member.key })
    }
    return removed
  }

  /** 保证核心角色（总指挥/参谋）时刻在岗：缺了就补一个待命席位；重复的只留最早那个。 */
  async ensureCore(engagementId) {
    const added = []
    const removed = []
    if (this.corePending === undefined) this.corePending = new Set()
    for (const roleId of CORE_ROLES) {
      const lockKey = `${engagementId}:${roleId}`
      if (this.corePending.has(lockKey)) continue
      const rows = Array.from(this.members.values())
        .filter((m) => m.engagementId === engagementId && m.role === roleId)
        .sort((a, b) => Number(a.startedAt || 0) - Number(b.startedAt || 0))
      if (rows.length > 1) {
        for (const extra of rows.slice(1)) {
          this.uninstallMemberMcp(extra.key)
          try { await extra.handle.dispose() } catch { /* 已释放 */ }
          this.members.delete(extra.key)
          this.removeMemberFromGroup(extra)
          this.promptCache.delete(extra.key)
          this.refreshToolRestrictions()
          this.hub.broadcast({ type: 'squad.remove', engagementId, key: extra.key })
          removed.push(extra.key)
        }
        continue
      }
      if (rows.length === 1) continue
      this.corePending.add(lockKey)
      try {
        const member = await this.spawn({ engagementId, roleId, task: '', origin: 'core', allowCore: true })
        if (member !== undefined && member.key !== undefined) added.push(member.key)
      } catch { /* 建不起来下次再试 */ } finally {
        this.corePending.delete(lockKey)
      }
    }
    return { added, removed }
  }

  /** 整个项目被删除时清场：连常设席位一起释放，不写离职交接 */
  async dropEngagement(engagementId) {
    let removed = 0
    for (const member of Array.from(this.members.values())) {
      if (member.engagementId !== engagementId) continue
      try { await this.remove(member.key, { reason: '项目删除', handover: false, force: true, engagementId }) } catch { /* 已释放 */ }
      removed += 1
    }
    return removed
  }

  async stopAll(engagementId) {
    let stopped = 0
    for (const member of this.members.values()) {
      if (engagementId !== undefined && member.engagementId !== engagementId) continue
      if (member.status !== 'running' && member.status !== 'starting' && member.status !== 'waiting') continue
      try { member.agent.cancel({ kind: 'user' }) } catch { /* 已停 */ }
      member.status = 'idle'
      stopped += 1
      this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
    }
    return stopped
  }

  list(engagementId) {
    const out = []
    for (const member of this.members.values()) {
      if (engagementId !== undefined && member.engagementId !== engagementId) continue
      out.push({
        key: member.key,
        role: member.role,
        name: member.name,
        tier: member.tier,
        status: member.status,
        task: member.task,
        startedAt: member.startedAt,
        promptExtra: asText(member.promptExtra),
        skills: Array.isArray(member.skills) ? member.skills : [],
        mcp: asMcpList(member.mcp),
        mcpError: asText(member.mcpError),
        lastText: member.lastText,
        lastTool: member.lastTool,
        groupId: member.groupId || null,
        waitingFor: asText(member.waitingFor),
        origin: asText(member.origin),
        lastAt: Number(member.lastAt || member.idleSince || member.startedAt || 0),
        core: CORE_ROLES.has(member.role),
        sessionId: member.sessionId,
        station: member.station || null,
      })
    }
    return out.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0))
  }


  /** 成员专属 MCP 的服务名前缀（避免与其他成员/全局 MCP 撞名）。 */
  mcpPrefixOf(key) {
    return `rc_${key}_`
  }

  /** 给一个成员装上它的专属 MCP；返回不可用原因（没有管理器时）。 */
  installMemberMcp(member) {
    const manager = this.ctx.get('mcpManager')
    const rows = asMcpList(member.mcp)
    if (rows.length === 0) return { installed: 0, skipped: 0 }
    if (manager === undefined || manager === null) return { installed: 0, skipped: rows.length, error: 'mcpManager 不可用：profile 未装 MCP 管理器' }
    const prefix = this.mcpPrefixOf(member.key)
    const list = this.memberMcp.get(member.key) || []
    let installed = 0
    let skipped = 0
    for (const row of rows) {
      if (row.enabled === false) { skipped += 1; continue }
      const name = asText(row.name)
      if (name === '') { skipped += 1; continue }
      const globalName = `${prefix}${name}`
      try {
        const entry = normalizeMcpEntry(row)
        const dispose = manager.register(globalName, entry)
        list.push({ name, globalName, dispose })
        installed += 1
      } catch { skipped += 1 }
    }
    this.memberMcp.set(member.key, list)
    return { installed, skipped }
  }

  /** 注销某个成员的全部专属 MCP。 */
  uninstallMemberMcp(key) {
    const list = this.memberMcp.get(key)
    if (list === undefined) return
    for (const row of list) {
      try { row.dispose() } catch { /* 已卸载 */ }
    }
    this.memberMcp.delete(key)
    this.refreshToolRestrictions()
  }

  /**
   * 这个成员「不该看见」的工具名：其他成员的专属 MCP 命名空间。
   * 每个队员只能用自己的 MCP，别去调别人的私有工具。
   */
  mcpDenyFor(key) {
    const deny = []
    for (const row of this.memberMcp.values()) {
      for (const item of row) {
        if (item.globalName.startsWith(this.mcpPrefixOf(key))) continue
        deny.push(item.globalName)
      }
    }
    return deny
  }

  /** 成员 MCP 变更后，重新给所有在岗 agent 计算一次私有工具 deny 列表。 */
  refreshToolRestrictions() {
    for (const member of this.members.values()) {
      const tools = member.tools
      if (tools === undefined || tools === null || typeof tools.restrict !== 'function') continue
      try { tools.restrict({ deny: this.mcpDenyFor(member.key) }) } catch { /* 单个失败不影响其它成员 */ }
    }
  }

  /** 成员专属 MCP 的说明块（写进它的系统提示）。 */
  mcpPromptLines(member) {
    const rows = asMcpList(member.mcp).filter((row) => row.enabled !== false)
    if (rows.length === 0) {
      return [
        hostEnvNote(),
        IS_WIN
          ? '没有给你配置专属 MCP，就用 shell 命令自己干活：Windows 上先 `where` / `--help` 确认工具是否存在；缺工具可用 winget / choco / scoop / pip 现场装。'
          : '没有给你配置专属 MCP，就用 shell 命令自己干活：需要什么先 `which` / `--help` 确认，缺工具可以现场装（apt/pip/go）。',
      ]
    }
    const lines = ['你挂载了专属 MCP 工具（服务名已加你的私人前缀，只有你能用）：']
    for (const row of rows) {
      const name = asText(row.name)
      const desc = asText(row.description) || (row.transport === 'streamable-http' ? asText(row.url) : `${asText(row.command)} ${asList(row.args).join(' ')}`)
      lines.push(`- ${name}：${shortText(desc, 120)}（工具名前缀 ${this.mcpPrefixOf(member.key)}${name}_）`)
    }
    lines.push('这些工具优先于自己手搓脚本；MCP 解决不了的再用 shell。你仍然可以使用本机上的任意命令。')
    return lines
  }

  /**
   * 同步实时渲染成员提示词。
   * 每一轮 agent 组装系统提示时调用，数据直接取内存缓存（configStore / members / board.cache / tasks.cache / store.cache），
   * 所以「总指挥刚在看板点了你的名」→ 你下一次思考就已经看到了，不用等任何刷新。
   */
  renderPromptSync(key) {
    const member = this.members.get(key)
    if (member === undefined) return ''
    const engagementId = member.engagementId
    const role = this.roleOf(member.role)
    const lines = []

    /* —— 我是谁：名字就是身份 —— */
    lines.push(`## 你是谁`)
    lines.push(`你叫 **${member.name}**。这就是你在团队里唯一的称呼。`)
    lines.push(`- 看板里、任务里、别人跟你说话，一律用「${member.name}」叫你；`)
    lines.push(`- 你汇报、写看板、留证据、点别人的名，也一律用人名（例如「Web 手#6」「逆向手#2」）；`)
    lines.push(`- 你是「${role.name}」，汇报对象：${role.reportsTo || '指挥席'}。`)
    lines.push('')
    lines.push(role.prompt)
    if (role.id === 'scout' && !String(role.prompt || '').includes('recon_nday')) {
      lines.push('')
      lines.push('## 指纹 Nday 检索（探测到指纹后立即查，不必等总指挥指派）')
      lines.push('- 你在测绘中确认服务 / 中间件 / 产品 / 版本指纹后，立刻调用 `recon_nday fingerprint="..."` 查 Exploit-DB 与 NVD；')
      lines.push('- 每个指纹至少查一次；候选 CVE / EDB / 受影响版本写看板 kind=hypothesis 并附来源，需要实测的交 Web 手 / QA；')
      lines.push('- 只查历史漏洞库，不对目标发包；不要凭版本猜结论；工具没查到就写「无匹配」，不要编造 CVE。')
    }

    /* —— 技能 / MCP（实时）—— */
    const roleSkills = Array.isArray(role.skills) ? role.skills : []
    const extraSkills = (Array.isArray(member.skills) ? member.skills : []).filter((name) => roleSkills.includes(name) === false)
    if (roleSkills.length > 0) lines.push(`\n已启用技能：${roleSkills.join(', ')}（需要细节时用 recon_skill action=load name=技能名 加载完整正文）。`)
    if (extraSkills.length > 0) lines.push(`总指挥为你点开的技能：${extraSkills.join(', ')}（先用 recon_skill action=load 把它们加载进来再干活）。`)
    lines.push(`模型档位：${role.tier === 'dsh' ? '跟随 DSH' : (role.tier || 'deep')}`)
    if (asText(member.promptExtra) !== '') {
      lines.push('')
      lines.push('## 总指挥给你的专属指令（最高优先级，必须遵守）')
      lines.push(asText(member.promptExtra))
    }
    const mcpLines = this.mcpPromptLines(member)
    if (Array.isArray(mcpLines) && mcpLines.length > 0) { lines.push(''); lines.push(...mcpLines) }
    if (asText(member.station) !== '') {
      lines.push('')
      lines.push('## 你的工位')
      lines.push(`工作目录：${member.station}`)
      lines.push('- 命令默认在这里执行，相对路径写的东西都落在你自己的工位里，不会和别的队员撞车。')
      lines.push('- 要交接给别的队员或 qa 复核的产物，写到同级共享目录 `../shared/`，并在看板条目里写清文件名。')
      lines.push('- 你离职后这个目录不会被删除；不要往别人的工位目录里写。')
    }

    /* —— 点名给我的（实时，置顶）—— */
    const boardRows = this.board === undefined || this.board === null ? [] : this.board.rawSync(engagementId)
    const myNames = [member.name, member.key].filter((v) => asText(v) !== '')
    const calledOn = boardRows.filter((row) => {
      const fromMe = row.author && row.author.name === member.name
      if (fromMe) return false
      const body = asText(row.text)
      return myNames.some((n) => body.includes(n))
    }).slice(-6)
    if (calledOn.length > 0) {
      lines.push('')
      lines.push('## 总指挥点名给你的（最新，优先级高于下面的通用看板）')
      for (const row of calledOn) {
        const who = row.author && row.author.name ? row.author.name : '指挥席'
        lines.push(`- （${new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')}）${who}：${shortText(this.humanize(asText(row.text)).replace(/\s+/g, ' '), 400)}`)
      }
    }

    /* —— 分给我的任务（实时）—— */
    const taskRows = this.tasks === undefined || this.tasks === null ? [] : this.tasks.rawSync(engagementId)
    /* 指派到具体人 + 只写了角色（assignee 为空）的任务都算“分给我”的。 */
    const mine = taskRows.filter((row) => row.assignee === member.name
      || (asText(row.assignee) === '' && row.role === member.role))
    const openMine = mine.filter((row) => row.status !== 'passed' && row.status !== 'failed')
    if (openMine.length > 0) {
      lines.push('')
      lines.push('## 分给你的未完成任务（实时）')
      for (const row of openMine.slice(-8)) {
        const ev = row.evidence || {}
        const evidence = [
          Array.isArray(ev.commandIds) && ev.commandIds.length > 0 ? `命令 ${ev.commandIds.join(',')}` : '',
          Array.isArray(ev.vulnIds) && ev.vulnIds.length > 0 ? `漏洞 ${ev.vulnIds.join(',')}` : '',
          Array.isArray(ev.nodeIds) && ev.nodeIds.length > 0 ? `节点 ${ev.nodeIds.join(',')}` : '',
          Array.isArray(ev.shots) && ev.shots.length > 0 ? `截图 ${ev.shots.length}` : '',
        ].filter((x) => x !== '').join('；')
        lines.push(`- ${row.id} ${this.humanize(row.title)}｜目标：${shortText(this.humanize(row.goal) || '-', 90)}｜验收：${shortText(this.humanize(row.acceptance) || '-', 70)}${evidence !== '' ? `｜已有证据：${evidence}` : ''}`)
      }
      lines.push('做完用 `recon_task update` 改成 doing/passed 并附证据。')
    }
    const rejected = mine.filter((row) => row.status === 'failed')
    if (rejected.length > 0) {
      lines.push(`有 ${rejected.length} 条被验收驳回，优先返工：${rejected.slice(-3).map((r) => `${r.id}（${shortText(r.note || '未达标', 60)}）`).join('；')}`)
    }
    if (role.id === 'qa') {
      lines.push('')
      lines.push('## QA 验收流程（必须按顺序）')
      lines.push('1. 先看 `recon_task list` 的任务目标、验收标准、执行者、commandId/vuln/node/shot 证据。')
      lines.push('2. 用 `recon_audit action=list member=执行者` 核对真实命令、覆盖范围与结果；证据断了或结果不可复现就 reject。')
      lines.push('3. 需要复现时自己 `recon_run` / `recon_browser`；通过才 `recon_task accept`，驳回必须写清缺口并 `recon_task reject`。')
      lines.push('4. 全部任务通过后写最终验收报告到看板（kind=conclusion）；最终只能由总指挥 close，你不要替总指挥宣布结束。')
    }

    /* —— 在岗同事（实时，方便直接喊人）—— */
    const peers = Array.from(this.members.values())
      .filter((m) => m.engagementId === engagementId && m.key !== member.key)
      .map((m) => `${m.name}（${this.roleOf(m.role).name}）`)
    if (peers.length > 0) {
      lines.push('')
      lines.push(`在岗同事：${peers.join('、')}`)
      lines.push('要找别人接手，直接在看板写「@名字 + 要他做什么」，或让总指挥派。')
    }
    const groupText = this.groupPromptText(member)
    if (groupText !== '') lines.push(groupText)

    /* —— 完整看板（强制阅读：用户发言全文 + 全部 agent 条目全文）—— */
    if (this.board !== undefined && this.board !== null) {
      const boardText = this.board.promptText(engagementId, { actor: member })
      if (boardText !== '') { lines.push(''); lines.push(boardText) }
    }

    /* —— 靶标现状 —— */
    const eng = this.store && this.store.cache ? this.store.cache.get(engagementId) : undefined
    if (eng !== undefined) {
      const stats = statsOf(eng)
      lines.push('')
      lines.push(`当前靶标：${eng.name}（${eng.id}）；节点 ${stats.nodes} · 关系 ${stats.edges} · 漏洞 ${stats.vulns} · 命令 ${stats.commands}`)
      const recentNodes = eng.nodes.filter((node) => node.archived !== true).slice(-20).map((node) => `${node.kind}:${node.value}`)
      if (recentNodes.length > 0) lines.push(`最近资产：${recentNodes.join(' , ')}`)
    }

    /* —— 全局长期记忆（所有 agent 强制阅读，仅参谋/总指挥可写）—— */
    const dynamicConfig = this.configStore.get()
    const dynamicMemory = Array.isArray(dynamicConfig.memory) ? dynamicConfig.memory : []
    if (dynamicMemory.length > 0) {
      lines.push('')
      lines.push('## 长期记忆（全局强制阅读，全部条目）')
      for (const item of dynamicMemory) {
        const entry = memoryEntryOf(item)
        if (entry.content !== '') lines.push(`- [${entry.category || 'other'}] ${entry.title}：${entry.content}`)
      }
    }
    const memberPromptGroupText = this.groupPromptText(member)
    if (memberPromptGroupText !== '') {
      lines.push('')
      lines.push(memberPromptGroupText)
    }

    /* —— 常设席位的前情 —— */
    if (CORE_ROLES.has(member.role)) {
      const rows = this.transcripts === undefined ? undefined : this.transcripts.get(member.key)
      const recent = Array.isArray(rows) ? rows.filter((row) => asText(row.text) !== '').slice(-6) : []
      if (recent.length > 0) {
        lines.push('')
        lines.push('## 你的前情（这个席位一直在，下面是你之前说过的，接着做，不要重复已完成的事）')
        for (const row of recent) {
          lines.push(`- （${new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')}）${shortText(asText(row.text).replace(/\s+/g, ' '), 240)}`)
        }
      }
    }

    lines.push('')
    lines.push('## 团队纪律')
    lines.push('- 你和其它 Agent 并行工作，共享同一份图谱、命令日志和看板；不要重复别人刚写进看板的结论。')
    lines.push('- 记忆是全局强制阅读的完整事实库；你没有写入权限，重要结论交给总指挥/参谋写记忆，日常过程只写看板。')
    lines.push('- 每次有发现或猜想，立刻 `recon_board` 记一条（kind=finding/hypothesis/task/conclusion），带上节点/漏洞/命令引用。')
    lines.push('- 你不能派发新 Agent（那是指挥席的事）。遇到非自己职责的卡点，先用 `recon_group action=request role=... task=...` 报给总指挥；编组后用 `recon_group action=ask` 串行求助。')
    lines.push('- 命令一律走 `recon_run`（会留痕并上图）；页面操作走 `recon_browser`。')

    return safePromptText(withCommonPrompt(this.configStore.get(), lines.join('\n')))
  }

  /** 花名册落盘文件 */
  rosterFile() {
    return join(this.store.root, 'roster.json')
  }

  /** 首次使用时把花名册读进内存 */
  async loadRoster() {
    if (this.rosterLoaded) return
    this.rosterLoaded = true
    try {
      const raw = JSON.parse(await readFile(this.rosterFile(), 'utf8'))
      if (raw !== null && typeof raw === 'object') {
        for (const [key, name] of Object.entries(raw)) {
          if (asText(name) !== '') this.roster.set(key, asText(name))
        }
      }
    } catch { /* 第一次还没有花名册 */ }
  }

  /** 记下「这个内部编号曾经是谁」，永久保留（离职也不删） */
  async rememberName(key, name) {
    await this.loadRoster()
    if (asText(name) === '' || asText(key) === '') return
    if (this.roster.get(key) === name) return
    this.roster.set(key, name)
    try {
      const obj = {}
      for (const [k, v] of this.roster) obj[k] = v
      await writeFile(this.rosterFile(), `${JSON.stringify(obj, null, 2)}\n`, 'utf8')
    } catch { /* 写不进去就只在内存里生效 */ }
  }

  /**
   * 把文本里的内部编号翻成人名。
   * 历史看板、历史任务正文里写的「a7」会显示成「验收#1」；查不到的保持原样并标注已离岗。
   */
  humanize(text) {
    const raw = asText(text)
    if (raw === '') return raw
    /* 渲染是同步的：花名册没读进来就先同步读一次（文件很小） */
    if (!this.rosterLoaded) {
      this.rosterLoaded = true
      try {
        const rawRoster = JSON.parse(readFileSync(this.rosterFile(), 'utf8'))
        if (rawRoster !== null && typeof rawRoster === 'object') {
          for (const [k, v] of Object.entries(rawRoster)) {
            if (asText(v) !== '') this.roster.set(k, asText(v))
          }
        }
      } catch { /* 没有就没有 */ }
    }
    return raw.replace(/(?<![A-Za-z0-9_])a(\d{1,4})(?![A-Za-z0-9_])/g, (whole, digits) => {
      const key = `a${digits}`
      const name = this.roster.get(key)
      if (name !== undefined) return name
      const live = this.members.get(key)
      if (live !== undefined && asText(live.name) !== '') return live.name
      return whole
    })
  }

  /** 用户在看板发了新指令：把在岗成员的系统提示全部重建，下一轮就吃到 */
  async refreshPrompts(engagementId) {
    const rows = this.list(engagementId)
    let count = 0
    for (const member of rows) {
      try {
        const role = this.roleOf(member.role)
        this.promptCache.set(member.key, await this.memberPrompt(engagementId, role, member))
        count += 1
      } catch { /* 单个失败不影响其它成员 */ }
    }
    return count
  }

  async memberPrompt(engagementId, role, member) {
    const config = this.configStore.get()
    const eng = await this.store.load(engagementId)
    const lines = []
    lines.push(`## 你是「狩猎 · 协同团队」里的${role.name}（role=${role.id}）`)
    lines.push(role.prompt)
    if (role.id === 'scout' && !String(role.prompt || '').includes('recon_nday')) {
      lines.push('')
      lines.push('## 指纹 Nday 检索（探测到指纹后立即查，不必等总指挥指派）')
      lines.push('- 你在测绘中确认服务 / 中间件 / 产品 / 版本指纹后，立刻调用 `recon_nday fingerprint="..."` 查 Exploit-DB 与 NVD；')
      lines.push('- 每个指纹至少查一次；候选 CVE / EDB / 受影响版本写看板 kind=hypothesis 并附来源，需要实测的交 Web 手 / QA；')
      lines.push('- 只查历史漏洞库，不对目标发包；不要凭版本猜结论；工具没查到就写「无匹配」，不要编造 CVE。')
    }
    lines.push('')
    lines.push(`你的汇报对象：${role.reportsTo || '无（最高指挥）'}。`)
    const roleSkills = Array.isArray(role.skills) ? role.skills : []
    if (roleSkills.length > 0) lines.push(`你已启用的技能：${roleSkills.join(', ')}（需要细节时用 recon_skill action=load name=技能名 加载完整正文）。`)
    lines.push(`模型档位：${role.tier === 'dsh' ? '跟随 DSH' : (role.tier || 'deep')}`)
    if (member !== undefined && member !== null) {
      lines.push(`你的代号：${member.name}（key=${member.key}）；总指挥点名派的活，汇报时自报这个代号。`)
      if (asText(member.station) !== '') {
        lines.push('')
        lines.push('## 你的工位')
        lines.push(`工作目录：${member.station}`)
        lines.push('- 所有命令默认在这里执行，临时文件、脚本、扫描输出的**相对路径**都落在你自己的工位里，不会和别的队员撞车。')
        lines.push('- 要交接给别的队员或 qa 复核的产物，写到同级共享目录 `../shared/`（不存在就先 mkdir -p ../shared），并在看板条目里写清文件名。')
        lines.push('- 你离职后这个目录不会被删除，东西都留着；不要往别人的工位目录里写。')
      }
      const extraSkills = (Array.isArray(member.skills) ? member.skills : []).filter((name) => roleSkills.includes(name) === false)
      if (extraSkills.length > 0) lines.push(`总指挥为你点开的技能：${extraSkills.join(', ')}（先用 recon_skill action=load 把它们加载进来再干活）。`)
      if (asText(member.promptExtra) !== '') {
        lines.push('')
        lines.push('总指挥给你的专属指令（最高优先级，必须遵守）：')
        lines.push(member.promptExtra)
      }
      lines.push('')
      lines.push(...this.mcpPromptLines(member))
    }
    try {
      const rows = this.tasks === undefined || this.tasks === null ? [] : await this.tasks.list(engagementId, 120)
      const mine = rows.filter((row) => row.role === role.id && row.status !== 'passed')
      if (mine.length > 0) {
        lines.push('分给你（或你的角色）的未完成任务：')
        for (const row of mine.slice(-8)) {
          lines.push(`- ${row.id} ${row.title}｜目标：${shortText(row.goal || '-', 80)}｜验收：${shortText(row.acceptance || '-', 60)}`)
        }
        lines.push('完成后用 `recon_task update` 把状态改成 doing/passed 并附证据。')
      }
    } catch { /* 忽略 */ }
    lines.push('团队纪律：')
    lines.push('- 你和其它 Agent 并行工作，共享同一份图谱、命令日志和看板；不要重复别人刚写进看板的结论。')
    lines.push('- 记忆是全局强制阅读的完整事实库；你没有写入权限，重要结论交给总指挥/参谋写记忆，日常过程只写看板。')
    lines.push('- 每次有发现或猜想，立刻 `recon_board` 记一条（kind=finding/hypothesis/task/conclusion），带上节点/漏洞/命令引用。')
    lines.push('- 你不能派发新 Agent（那是指挥席的事）。遇到非自己职责的卡点（例如 Web 需要逆向、需要内网隧道），先用 `recon_group action=request role=... task=...` 报给总指挥；等总指挥把你和专业人员编成小组后，用 `recon_group action=ask member=对方 question=...` 串行提问并等待结果，再继续自己的工作。')
    lines.push('- 命令一律走 `recon_run`（会留痕并上图）；页面操作走 `recon_browser`。')
    if (eng !== undefined) {
      const stats = statsOf(eng)
      lines.push('')
      lines.push(`当前靶标：${eng.name}（${eng.id}）；节点 ${stats.nodes} · 关系 ${stats.edges} · 漏洞 ${stats.vulns} · 命令 ${stats.commands}`)
      const recentNodes = eng.nodes.filter((node) => node.archived !== true).slice(-20).map((node) => `${node.kind}:${node.value}`)
      if (recentNodes.length > 0) lines.push(`最近资产：${recentNodes.join(' , ')}`)
    }
    /* 完整看板置顶注入：用户发言全文 + 所有 agent 条目全文 */
    const boardText = await boardPromptText(this.board, engagementId, { actor: member })
    if (boardText !== '') {
      lines.push('')
      lines.push(boardText)
      lines.push('')
    }
    /* 常设席位（总指挥/参谋）跨重启保持对话记忆：把最近几轮自己的发言带回来 */
    if (member !== undefined && member !== null && CORE_ROLES.has(member.role)) {
      try {
        const rows = await this.transcriptOf(member)
        const recent = Array.isArray(rows) ? rows.filter((row) => asText(row.text) !== '').slice(-6) : []
        if (recent.length > 0) {
          lines.push('')
          lines.push('## 你的前情（这个席位一直在，下面的对话是你之前说过的，接着做，不要重复已完成的事）')
          for (const row of recent) {
            lines.push(`- （${new Date(Number(row.ts) || Date.now()).toLocaleString('zh-CN')}）${shortText(asText(row.text).replace(/\s+/g, ' '), 240)}`)
          }
        }
      } catch { /* 读不到就不带 */ }
    }
    try {
      const taskRows = this.tasks === undefined || this.tasks === null ? [] : await this.tasks.list(engagementId, 80)
      const open = taskRows.filter((row) => row.status !== 'passed' && row.status !== 'failed')
      if (open.length > 0) {
        lines.push('')
        lines.push('未闭环任务：')
        for (const row of open.slice(-12)) {
          lines.push(`- ${row.id} [${row.role}/${row.status}] ${row.title}｜验收：${shortText(row.acceptance || '-', 60)}`)
        }
      }
      const failed = taskRows.filter((row) => row.status === 'failed')
      if (failed.length > 0) {
        lines.push(`有 ${failed.length} 条任务被验收驳回，优先处理返工。`)
      }
    } catch { /* 任务读取失败不影响对话 */ }
    const memory = Array.isArray(config.memory) ? config.memory : []
    if (memory.length > 0) {
      lines.push('')
      lines.push('## 长期记忆（全局强制阅读，全部条目）')
      for (const item of memory) {
        const entry = memoryEntryOf(item)
        if (entry.content !== '') lines.push(`- [${entry.category || 'other'}] ${entry.title}：${entry.content}`)
      }
    }
    return safePromptText(withCommonPrompt(config, lines.join('\n')))
  }

  /** 工位目录名：用队员名，去掉文件系统不允许的字符 */
  stationName(name, key) {
    const raw = asText(name).trim() || key
    const safe = raw.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/\.+$/, '').slice(0, 60)
    return safe === '' ? key : safe
  }

  /** 队员的独立工位（招募时创建，离职不删除） */
  async stationOf(engagementId, name, key) {
    const base = this.stationName(name, key)
    const workRoot = this.store && this.store.workDir ? this.store.workDir : join(this.cfg.root, 'work')
    let dir = join(workRoot, engagementId, base)
    /* 在岗重名才加序号；离职留下的目录直接复用（同一岗位） */
    const taken = new Set()
    for (const member of this.members.values()) {
      if (member.engagementId === engagementId && member.key !== key && member.station !== undefined) taken.add(member.station)
    }
    if (taken.has(dir)) {
      let n = 2
      while (taken.has(`${dir}-${n}`)) n += 1
      dir = `${dir}-${n}`
    }
    await mkdir(dir, { recursive: true })
    return dir
  }

  async spawn({ engagementId, roleId, tier, task, origin = 'manual', name: nameWanted, promptExtra, skills, mcp, allowCore = false }) {
    const agents = this.ctx.get('agents')
    if (agents === undefined || agents === null) throw new Error('agents 服务不可用')
    const engagement = await this.store.load(engagementId)
    if (engagement === undefined) throw new Error(`靶标不存在：${engagementId}`)
    const requestedRole = asText(roleId)
    if (requestedRole !== '') {
      const directRole = this.roles().find((role) => role.id === requestedRole || role.name === requestedRole)
      const coreRole = this.coreRoleIdOf(requestedRole)
      if (directRole === undefined && coreRole === '' && ROLE_ALIASES[requestedRole] === undefined) {
        throw new Error(`未知角色：${requestedRole}。可用角色：${this.roles().map((role) => `${role.id}(${role.name})`).join(', ')}`)
      }
    }
    const role = this.roleOf(roleId)
    if (CORE_ROLES.has(role.id) && allowCore !== true) {
      throw new Error(`${role.name}是常设席位（每靶标各一个、自动在岗），不能召唤为队员；请用 recon_squad task / recon_org brief 给席位派活`)
    }
    /* 常设席位全局唯一：总指挥 / 参谋已在岗时不再新建，任务直接追加给原席位。
       （全员会议、事件触发、断点续跑都会走 spawn，这里是最后一道闸。） */
    if (CORE_ROLES.has(role.id)) {
      const findSeat = () => Array.from(this.members.values())
        .filter((m) => m.engagementId === engagementId && m.role === role.id)
        .sort((a, b) => Number(a.startedAt || 0) - Number(b.startedAt || 0))[0]
      const lockKey = `${engagementId}:${role.id}`
      if (this.coreCreating === undefined) this.coreCreating = new Set()
      let seated = findSeat()
      /* 并发窗口：另一个 spawn 正在建这个席位 → 等它落位，避免出现两个总指挥 */
      if (seated === undefined && this.coreCreating.has(lockKey)) {
        for (let i = 0; i < 30 && seated === undefined; i += 1) {
          await sleep(100)
          seated = findSeat()
        }
      }
      if (seated !== undefined) {
        const text = asText(task)
        if (text !== '') await this.taskByMember(seated, text)
        return this.view(seated)
      }
      /* 先占位：后到的并发 spawn 会走上面的等待分支 */
      this.coreCreating.add(lockKey)
      setTimeout(() => { try { this.coreCreating.delete(lockKey) } catch { /* 已释放 */ } }, 15000)
    }
    const automationConfig = mergeDeep(DEFAULT_AUTOMATION, this.configStore.get().automation || {})
    const maxAgents = Number.isFinite(Number(automationConfig.maxAgents))
      ? Math.max(1, Math.min(50, Math.floor(Number(automationConfig.maxAgents))))
      : 8
    const configuredMembers = Number.isFinite(Number(automationConfig.maxMembers))
      ? Math.max(1, Math.min(50, Math.floor(Number(automationConfig.maxMembers))))
      : 6
    /* 最大并发数调大时，成员上限跟随，避免被隐藏的 6 人上限拦住 */
    const maxMembers = Math.max(maxAgents, configuredMembers)
    const coreCount = () => Array.from(this.members.values())
      .filter((m) => m.engagementId === engagementId && CORE_ROLES.has(m.role)).length
    if (this.memberCount(engagementId) - coreCount() >= maxMembers) {
      const before = this.memberCount(engagementId)
      await this.pruneIdle(60000)
      if (this.memberCount(engagementId) - coreCount() >= maxMembers) {
        throw new Error(`队员已满（${maxMembers}）：先停掉/移除空闲成员，或在控制台调大「最大并发数」`)
      }
      if (before === this.memberCount(engagementId)) {
        /* 没有可回收的，继续走失败分支 */
      }
    }
    /* 角色只选档位（deep / fast / vision / dsh），实际 provider/model 由模型页决定 */
    const wantedTier = MODEL_CHOICES.includes(asText(tier))
      ? asText(tier)
      : (MODEL_CHOICES.includes(asText(role.tier)) ? asText(role.tier) : 'dsh')
    const selection = this.modelFor(wantedTier)
    const workDir = await ensureDir(join(this.store.workDir, engagementId))
    this.seq += 1
    const key = `a${this.seq}`
    const customName = asText(nameWanted).trim()
    /* 常设席位直接用角色名（总指挥 / 参谋），不带序号，避免看起来像「第 1 个总指挥」 */
    const name = customName !== ''
      ? customName
      : (CORE_ROLES.has(role.id) ? role.name : `${role.name}#${this.seq}`)
    const roleSkills = Array.isArray(role.skills) ? role.skills.map((x) => asText(x)).filter((x) => x !== '') : []
    const extraSkills = asList(skills).map((x) => asText(x)).filter((x) => x !== '')
    const memberSkills = Array.from(new Set([...roleSkills, ...extraSkills]))
    const extraPrompt = asText(promptExtra).trim()
    const duplicateName = Array.from(this.members.values()).find((m) => m.engagementId === engagementId
      && m.name.toLowerCase() === name.toLowerCase())
    if (duplicateName !== undefined) throw new Error(`成员代号重复：${name}；请换一个代号`)
    const sessionId = `recon-squad-${key}-${nowMs().toString(36)}`
    const member = {
      key,
      role: role.id,
      name,
      skills: memberSkills,
      promptExtra: extraPrompt,
      mcp: asMcpList(mcp).length > 0 ? asMcpList(mcp) : asMcpList(role.mcp),
      tier: wantedTier,
      engagementId,
      sessionId,
      agent: null,
      handle: null,
      status: 'starting',
      task: asText(task),
      startedAt: nowMs(),
      lastText: '',
      lastAssistantText: '',
      lastTool: '',
      boardPosts: 0,
      origin,
      groupId: null,
      answerWaiters: [],
      waitingFor: '',
      taskNotified: false,
    }
    const squad = this
    /* 先装专属 MCP：工具注册要在 agent 建立之前完成，restrict 才能看到它们 */
    const mcpState = squad.installMemberMcp(member)
    if (mcpState.error !== undefined) member.mcpError = mcpState.error
    const setup = (agentCtx) => {
      try {
        const prompt = typeof agentCtx.get === 'function' ? agentCtx.get('systemPrompt') : undefined
        if (prompt !== undefined && prompt !== null && typeof prompt.section === 'function') {
          prompt.section({
            name: `recon-squad-${key}`,
            order: 4902,
            /* 每轮实时渲染：看板/任务/名字/MCP 变更立刻进上下文，不等任何刷新 */
            text: () => squad.renderPromptSync(key) || safePromptText(withCommonPrompt(squad.configStore.get(), `## 你是${role.name}\n${role.prompt}`)),
          })
        }
        /* 工具隔离：别人挂的私有 MCP 不给这个成员用 */
        const tools = typeof agentCtx.get === 'function' ? agentCtx.get('tools') : undefined
        member.tools = tools
        const deny = squad.mcpDenyFor(key)
        if (deny.length > 0 && tools !== undefined && tools !== null && typeof tools.restrict === 'function') {
          tools.restrict({ deny })
        }
      } catch { /* 注入失败不影响任务 */ }
    }
    /* 每个队员一个独立工位：目录名 = 队员名，离职不删，留在原地 */
    try {
      member.station = await this.stationOf(engagementId, name, key)
    } catch {
      member.station = undefined
    }
    void this.rememberName(key, name)
    try {
      this.promptCache.set(key, await this.memberPrompt(engagementId, role, member))
      const handle = await agents.create({
        sessionId,
        meta: { cwd: member.station || workDir, origin: 'subagent' },
        agentOptions: selection,
        setup,
      })
      member.agent = handle.agent
      member.handle = handle
      member.status = 'idle'
      member.model = asText(selection.provider) !== '' ? `${selection.provider}/${selection.model}` : 'follow-dsh'
      this.members.set(key, member)
    } catch (error) {
      /* agent 没建起来时，把已注册的私有 MCP 和占位状态一并回滚。 */
      this.uninstallMemberMcp(key)
      this.promptCache.delete(key)
      if (CORE_ROLES.has(role.id) && this.coreCreating !== undefined) {
        this.coreCreating.delete(`${engagementId}:${role.id}`)
      }
      throw error
    }
    /* 席位已落位：放开占位，让并发等待者直接复用这个成员 */
    if (CORE_ROLES.has(role.id) && this.coreCreating !== undefined) {
      this.coreCreating.delete(`${engagementId}:${role.id}`)
    }
    void this.trace?.push?.(engagementId, {
      kind: 'member',
      actor: { role: 'commander', name: '总指挥' },
      title: `启用队员 ${member.name}（${role.name}／${member.model || ('tier:' + wantedTier)}）`,
      detail: asText(task),
      refs: { memberName: asText(name), role: role.id },
      meta: { origin: asText(origin, 'manual') },
    })
    this.hub.broadcast({ type: 'squad.spawn', engagementId, member: this.view(member) })
        if (asText(task) !== '') {
  await this.board.post(engagementId, {
        author: { role: 'system', name: '调度台' },
        kind: 'task',
        text: `${name}（${role.name} · ${wantedTier} · ${origin === 'trigger' ? '事件触发' : '手动派发'}）开工：${asText(task)}`,
      })
    }
    if (asText(task) !== '') await this.taskByMember(member, task)
    return this.view(member)
  }

  view(member) {
    return {
      key: member.key,
      role: member.role,
      name: member.name,
      tier: member.tier,
      model: member.model || null,
      skills: Array.isArray(member.skills) ? member.skills : [],
      promptExtra: asText(member.promptExtra),
      mcp: asMcpList(member.mcp),
      mcpError: asText(member.mcpError),
      status: member.status,
      task: member.task,
      startedAt: member.startedAt,
      idleSince: member.idleSince || null,
      lastText: member.lastText,
      lastTool: member.lastTool,
      core: CORE_ROLES.has(member.role),
      sessionId: member.sessionId,
      engagementId: member.engagementId,
      station: member.station || null,
      groupId: member.groupId || null,
      waitingFor: asText(member.waitingFor),
      origin: asText(member.origin),
    }
  }

  /**
   * 成员寻址：只认名字。
   * 「Web 手#6」「web手6」「#6」「6」都算名字写法；内部 ID（a6）不再接受 —— 逼所有调用方说人名。
   */
  resolveMemberRef(ref, engagementId) {
    const wanted = asText(ref).trim()
    if (wanted === '') return undefined
    const all = Array.from(this.members.values())
      .filter((m) => asText(engagementId) === '' || m.engagementId === asText(engagementId))
    /* 内部调用经常直接传 member.key；必须支持，否则 remove/drop 会静默失败。 */
    const byKey = all.find((m) => m.key === wanted)
    if (byKey !== undefined) return byKey
    const norm = (v) => asText(v).toLowerCase().replace(/[\s#＃_\-·]/g, '')
    const target = norm(wanted)
    const hits = all.filter((m) => norm(m.name) === target)
    if (hits.length === 1) return hits[0]
    if (hits.length > 1) {
      throw new Error(`「${wanted}」对应 ${hits.length} 个成员，名字重复了：${hits.map((m) => m.name).join('、')}`)
    }
    /* 允许只写序号：#6 / 6 */
    const seqHit = /^(?:#|＃)?(\d+)$/.exec(wanted)
    if (seqHit !== null) {
      const bySeq = all.filter((m) => asText(m.name).endsWith(`#${seqHit[1]}`))
      if (bySeq.length === 1) return bySeq[0]
    }
    /* 允许不带 # 的写法：Web 手6 */
    const loose = all.filter((m) => {
      const nameAsSeq = asText(m.name).replace('#', '').toLowerCase()
      return nameAsSeq === target
    })
    if (loose.length === 1) return loose[0]
    const roster = all.map((m) => m.name).join('、') || '（目前没有在岗成员）'
    throw new Error(`找不到成员「${wanted}」。在岗成员：${roster}`)
  }

  async task(key, text, engagementId) {
    const member = this.resolveMemberRef(key, engagementId)
    if (member === undefined) throw new Error('没指定成员')
    return this.taskByMember(member, text)
  }

  /** 直接按成员对象派活：内部调用方拿的是 key/对象，不能再去走「只认名字」的 resolveMemberRef。 */
  async taskByMember(member, text, options = {}) {
    if (member === undefined || member === null) throw new Error('没指定成员')
    /* 小组内默认串行：已有其他成员在跑时，不允许再并发派活；组内应使用 recon_group ask。 */
    if (options.groupSerial !== false && member.groupId) {
      const group = this.groups.get(member.groupId)
      const otherActive = group === undefined ? undefined : group.memberKeys
        .filter((key) => key !== member.key)
        .map((key) => this.members.get(key))
        .find((item) => item !== undefined && (item.status === 'running' || item.status === 'starting' || item.status === 'waiting'))
      if (otherActive !== undefined) {
        throw new Error(`小组 ${member.groupId} 正在串行执行 ${otherActive.name}；等它完成后再派，或让成员用 recon_group ask 协作`)
      }
    }
    /* 双花括号会被 prompt 模板当变量解析，直接把整个会话变成 malformed，这里统一消毒 */
    const message = safePromptText(asText(text))
    if (message === '') throw new Error('任务内容不能为空')
    member.task = message
    member.taskNotified = false
    member.lastText = ''
    member.lastAssistantText = ''
    member.status = 'running'
    member.startedAt = nowMs()
    void this.trace?.push?.(member.engagementId, {
      kind: 'dispatch',
      actor: { role: 'commander', name: '总指挥' },
      title: `派活 → ${member.name}`,
      detail: message,
      refs: { memberName: member.name, role: member.role },
    })
    await this.refreshPrompt(member)
    member.agent.followup({
      id: `msg_${nowMs().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
      role: 'user',
      content: [{ type: 'text', text: message }],
      source: { kind: 'user' },
    })
    this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
    return this.view(member)
  }

  async refreshPrompt(member) {
    try {
      const role = this.roleOf(member.role)
      this.promptCache.set(member.key, await this.memberPrompt(member.engagementId, role, member))
    } catch { /* 用旧提示 */ }
  }

  async stop(key, engagementId) {
    let member
    try { member = this.resolveMemberRef(key, engagementId) } catch { member = undefined }
    if (member === undefined) return { ok: true, stopped: false }
    if (CORE_ROLES.has(member.role)) {
      return { ok: false, stopped: false, error: `${member.name} 是常设席位；请派空任务或使用「暂停/继续」，不要直接停止` }
    }
    try { member.agent.cancel({ kind: 'user' }) } catch { /* 已停 */ }
    member.status = 'done'
    void this.trace?.push?.(member.engagementId, {
      kind: 'member',
      actor: { role: 'commander', name: '总指挥' },
      title: `叫停 ${member.name}`,
      refs: { memberName: member.name, role: member.role },
    })
    this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
    return { ok: true, stopped: true }
  }

  /** 收队：停掉并移除所有空闲成员，返回回收名单（有活的不动）。 */
  async reclaimIdle(engagementId) {
    const reclaimed = []
    for (const member of Array.from(this.members.values())) {
      if (member.engagementId !== engagementId) continue
      if (member.status === 'running' || member.status === 'starting' || member.status === 'waiting') continue
      if (CORE_ROLES.has(member.role)) continue
      try { await this.handover(member, '收队') } catch { /* 交接失败照常释放 */ }
      this.uninstallMemberMcp(member.key)
      try { await member.handle.dispose() } catch { /* 已释放 */ }
      this.members.delete(member.key)
      this.removeMemberFromGroup(member)
      this.promptCache.delete(member.key)
      this.transcripts.delete(member.key)
      this.browsers?.drop?.(member.engagementId, member.sessionId)
      const timer = this.saveTimers.get(member.key)
      if (timer !== undefined) clearTimeout(timer)
      this.saveTimers.delete(member.key)
      reclaimed.push({ key: member.key, name: member.name, role: member.role })
      try { this.hub.broadcast({ type: 'squad.remove', engagementId, key: member.key }) } catch { /* 广播失败 */ }
    }
    if (reclaimed.length > 0) {
      void this.trace?.push?.(engagementId, {
        kind: 'member',
        actor: { role: 'commander', name: '总指挥' },
        title: `收队：回收 ${reclaimed.length} 名空闲队员`,
        detail: reclaimed.map((m) => `${m.name}(${m.role})`).join(', '),
      })
    }
    return reclaimed
  }

  /** 离职交接：释放前让成员把「发现 / 踩的坑 / 解决办法 / 给接手人的建议」写出来，落看板 + 记忆。 */
  async handover(member, reason = '释放') {
    if (member === undefined || member === null) return null
    const config = (this.configStore && this.configStore.get ? this.configStore.get().handover : null) || {}
    const enabled = config.enabled === undefined ? true : config.enabled !== false
    const timeoutMs = Number.isFinite(Number(config.timeoutMs)) ? Number(config.timeoutMs) : 90000
    if (!enabled) return null
    let tasks = []
    try { tasks = await this.tasks.list(member.engagementId, 200) } catch { tasks = [] }
    const mine = tasks.filter((row) => row.assignee === member.name).slice(-8)
    const done = mine.filter((row) => row.status === 'passed').length
    const failed = mine.filter((row) => row.status === 'failed').length
    const prompt = [
      `【离职交接】你（${member.name}）即将被${reason}。离职前把这一段的工作经验交出来，写清楚，别客套。`,
      '',
      `你的任务：共 ${mine.length} 条，通过 ${done}，驳回 ${failed}。`,
      mine.length > 0 ? mine.map((row) => `· [${row.status}] ${row.title}`).join('\n') : '· （没领到账本任务，按你实际做的事写）',
      '',
      '严格按下面四段输出（Markdown，每段 1-5 条，写具体：主机/路径/参数/命令，不要写“加强测试”这种空话）：',
      '## 发现',
      '已经确认的事实：哪些资产/接口/漏洞是真的，证据（commandId / 节点 value）。',
      '## 踩过的坑',
      '试过但失败的路：为什么失败（WAF/权限/超时/思路错），下次别重复。',
      '## 有用的小技巧',
      '这段工作里总结出来、换个人也能直接用的技巧：命令、payload、参数组合、判断依据。',
      '## 给接手人的建议',
      '下一步该打哪里、优先级、注意事项。',
      '',
      '直接输出交接正文。不要调用任何工具（包括 recon_board），不要写开场白——系统会把你的这段输出原样落到看板。',
    ].join('\n')

    let text = ''
    try {
      const beforeAnswer = asText(member.lastAnswer)
      const beforeStream = asText(member.lastText)
      await this.taskByMember(member, prompt)
      const deadline = nowMs() + timeoutMs
      while (nowMs() < deadline) {
        await sleep(1500)
        const fresh = this.members.get(member.key)
        if (fresh === undefined) break
        const answer = asText(fresh.lastAnswer)
        if (answer !== '' && answer !== beforeAnswer) { text = answer; break }
        const stream = asText(fresh.lastText)
        if (fresh.status !== 'running' && stream !== '' && stream !== beforeStream) { text = stream; break }
      }
      if (text === '' && asText(member.lastAnswer) !== beforeAnswer) text = asText(member.lastAnswer)
    } catch { /* 交接失败不阻塞释放 */ }

    const body = asText(text)
    if (body === '') {
      try {
        await this.board.post(member.engagementId, {
          author: { role: 'system', name: '调度台' },
          kind: 'note',
          text: `📤 ${member.name}（${roleLabelOf(member.role)}）已${reason}，但没来得及产出交接。`,
        })
      } catch { /* 忽略 */ }
      return null
    }

    try {
      await this.board.post(member.engagementId, {
        author: { role: member.role, name: member.name },
        kind: 'conclusion',
        text: `📤 **离职交接 · ${member.name}（${roleLabelOf(member.role)}）**\n\n${body}`,
        refs: { memberName: member.name, role: member.role, handover: true },
      })
    } catch { /* 忽略 */ }
    void this.trace?.push?.(member.engagementId, {
      kind: 'member',
      actor: { role: member.role, name: member.name },
      title: `${member.name} 离职交接`,
      detail: body,
      refs: { memberName: member.name, role: member.role },
    })
    return body
  }

  async remove(key, { reason = '回收', handover = true, force = false, engagementId } = {}) {
    let member
    try { member = this.resolveMemberRef(key, engagementId) } catch (error) { if (asText(key) !== '') throw error }
    if (member === undefined && asText(key) === '') return { ok: false, removed: false, error: '没有指定成员' }
    if (member !== undefined) key = member.key
    /* 总指挥与参谋是常设席位：每场固定各一个，任何常规回收都不动它们；
       只有整个项目被删除（force）时才随项目一起清掉 */
    if (member !== undefined && CORE_ROLES.has(member.role) && force !== true) {
      return {
        ok: false,
        removed: false,
        error: `${member.name} 是常设席位（${member.role}），不能释放；要清掉请删除整个项目`,
      }
    }
    if (handover) { try { await this.handover(member, reason) } catch { /* 交接失败照常释放 */ } }
    this.uninstallMemberMcp(key)
    try { await member.handle.dispose() } catch { /* 已释放 */ }
    this.members.delete(key)
    this.removeMemberFromGroup(member)
    this.promptCache.delete(key)
    this.transcripts.delete(key)
    this.browsers?.drop?.(member.engagementId, member.sessionId)
    const timer = this.saveTimers.get(key)
    if (timer !== undefined) clearTimeout(timer)
    this.saveTimers.delete(key)
    void this.trace?.push?.(member.engagementId, {
      kind: 'member',
      actor: { role: 'commander', name: '总指挥' },
      title: `回收 ${member.name}`,
      refs: { memberName: member.name, role: member.role },
    })
    this.hub.broadcast({ type: 'squad.remove', engagementId: member.engagementId, key })
    return { ok: true, removed: true }
  }

  memberByAgent(agent) {
    for (const member of this.members.values()) if (member.agent === agent) return member
    return undefined
  }

  memberBySessionId(sessionId) {
    for (const member of this.members.values()) if (member.sessionId === sessionId) return member
    return undefined
  }

  install() {
    const ctx = this.ctx
    const offStream = ctx.on('agent/assistant-stream', (payload) => {
      try {
        const member = this.memberByAgent(payload.agent)
        if (member === undefined) return
        const frame = payload.frame
        if (frame.type !== 'chunk') return
        const chunk = frame.chunk
        if (chunk.type === 'text-delta') {
          member.lastText = (member.lastText || '') + chunk.text
          this.hub.broadcast({ type: 'squad.delta', engagementId: member.engagementId, key: member.key, text: chunk.text })
        } else if (chunk.type === 'reasoning-delta') {
          this.hub.broadcast({ type: 'squad.reasoning', engagementId: member.engagementId, key: member.key, text: chunk.text })
        }
      } catch { /* 观察者不外溢 */ }
    })
    const offEvent = ctx.on('session/event', (session, event) => {
      try {
        const header = session && session.header ? session.header : {}
        const member = this.memberBySessionId(header.id)
        if (member === undefined) return
        if (event.type === 'tool/result') {
          const rt = blocksText(event.data.message && event.data.message.content)
          const okr = event.data.error === undefined
          void this.trace?.push?.(member.engagementId, {
            kind: 'result',
            actor: { role: member.role, name: member.name },
            title: `${okr ? '✓' : '✗'} ${event.data.name || 'tool'} 结果`,
            detail: rt,
            refs: { memberName: member.name, role: member.role, tool: event.data.name },
            meta: { ok: okr, out: rt },
          })
        } else if (event.type === 'tool/call') {
          member.lastTool = event.data.name
          member.lastAt = nowMs()
          this.hub.broadcast({
            type: 'squad.tool',
            engagementId: member.engagementId,
            key: member.key,
            name: event.data.name,
            args: event.data.arguments,
          })
          if (event.data.name === 'recon_board') {
            try {
              const parsed = typeof event.data.arguments === 'string' ? JSON.parse(event.data.arguments) : event.data.arguments
              if (asText(parsed && parsed.action ? parsed.action : 'post') === 'post') member.boardPosts += 1
            } catch { member.boardPosts += 1 }
          }
          const isSkill = event.data.name === 'skill'
          let skillName = ''
          if (isSkill) {
            try {
              const parsed = typeof event.data.arguments === 'string' ? JSON.parse(event.data.arguments) : event.data.arguments
              skillName = asText(parsed && parsed.name)
            } catch { /* 参数解析失败 */ }
          }
          void this.trace?.push?.(member.engagementId, {
            kind: isSkill ? 'skill' : 'tool',
            actor: { role: member.role, name: member.name },
            title: isSkill ? `加载技能 ${skillName || '(未命名)'}` : `调用 ${event.data.name}`,
            detail: event.data.arguments,
            refs: { memberName: member.name, role: member.role },
          })
        } else if (event.type === 'assistant/message') {
          const blocks = Array.isArray(event.data.message.content) ? event.data.message.content : []
          const text = blocks.filter((b) => b && b.type === 'text').map((b) => b.text).join('').trim()
          const reasoning = blocks.filter((b) => b && b.type === 'reasoning').map((b) => b.text).join('').trim()
          if (text !== '' || reasoning !== '') {
            if (text !== '') member.lastAssistantText = text
            const record = {
              id: `a_${event.seq}_${nowMs().toString(36)}`,
              role: 'assistant',
              text,
              reasoning,
              ts: nowMs(),
              author: member.name,
            }
            void this.trace?.push?.(member.engagementId, {
              kind: 'chat',
              actor: { role: member.role, name: member.name },
              title: `${member.name} 汇报`,
              detail: text || reasoning,
              refs: { memberName: member.name, role: member.role },
            })
            void this.transcriptOf(member).then(() => {
              this.pushTranscript(member, record)
              try { this.hub.broadcast({ type: 'squad.message', engagementId: member.engagementId, key: member.key, message: record }) } catch { /* 广播失败 */ }
            })
          }
        } else if (event.type === 'turn/end') {
          member.status = 'idle'
          member.idleSince = nowMs()
          member.lastAt = nowMs()
          this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
          const finished = asText(member.lastText) || asText(member.lastAssistantText)
          const finishedTask = asText(member.task)
          if (asText(finished) !== '') member.lastAnswer = finished
          member.lastText = ''
          member.lastAssistantText = ''
          /* 组内 ask 的调用者正在等这一轮结果；turn/end 立即唤醒。 */
          const answerText = asText(member.lastAnswer) || asText(finished)
          const waiters = Array.isArray(member.answerWaiters) ? member.answerWaiters.splice(0) : []
          for (const waiter of waiters) {
            try { waiter(answerText) } catch { /* 单个等待者失败不影响其它 */ }
          }
          if (member.boardPosts === 0 && asText(finished) !== '') {
            void this.board.post(member.engagementId, {
              author: { role: member.role, name: member.name },
              kind: 'finding',
              text: finished,
            })
          }
          member.boardPosts = 0
          /* 成员完成一轮后主动回报总指挥；否则总指挥常常以为还在跑而卡住。
             常设总指挥自己不是队员会话；普通成员每次派活只通知一次。 */
          if (finishedTask !== '' && member.role !== 'commander' && member.taskNotified !== true) {
            member.taskNotified = true
            const report = asText(finished) || asText(member.lastAnswer)
            void this.cockpit?.nudge?.(member.engagementId,
              `${member.name}（${member.role}）完成了派发任务：${finishedTask}${report !== '' ? `\n成员汇报：${report}` : ''}`,
              { always: true }).catch(() => {})
          }
          void this.refreshPrompt(member)
        }
      } catch { /* 同上 */ }
    })
    const offStatus = ctx.on('agent/status', (payload) => {
      try {
        const member = this.memberByAgent(payload.agent)
        if (member === undefined) return
        member.status = payload.status === 'running' ? 'running' : (member.status === 'running' ? 'idle' : member.status)
        /* 常设席位：idle 就代表「在岗待命」，别让它看起来像掉线 */
        if (CORE_ROLES.has(member.role) && member.status !== 'running') member.status = 'idle'
        member.lastAt = nowMs()
        this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
      } catch { /* 同上 */ }
    })
    const offError = ctx.on('agent/error', (payload) => {
      try {
        const member = this.memberByAgent(payload.agent)
        if (member === undefined) return
        const error = payload.error
        member.status = 'idle'
        member.lastAt = nowMs()
        const waiters = Array.isArray(member.answerWaiters) ? member.answerWaiters.splice(0) : []
        for (const waiter of waiters) {
          try { waiter(`执行出错：${error && error.message ? error.message : String(error)}`) } catch { /* 忽略 */ }
        }
        this.hub.broadcast({
          type: 'squad.error',
          engagementId: member.engagementId,
          key: member.key,
          text: error && error.message ? error.message : String(error),
        })
        this.hub.broadcast({ type: 'squad.status', engagementId: member.engagementId, member: this.view(member) })
        void this.board.post(member.engagementId, {
          author: { role: 'system', name: '调度台' },
          kind: 'note',
          text: `${member.name} 执行出错：${shortText(error && error.message ? error.message : String(error), 300)}`,
        })
      } catch { /* 同上 */ }
    })
    return () => {
      offStream()
      offEvent()
      offStatus()
      offError()
    }
  }

  forgetSession(sessionId) {
    if (typeof sessionId === 'string') COMMANDER_SESSIONS.delete(sessionId)
  }

  async disposeAll() {
    for (const timer of this.saveTimers.values()) clearTimeout(timer)
    this.transcripts.clear()
    for (const member of Array.from(this.members.values())) {
      this.uninstallMemberMcp(member.key)
      try { await member.handle.dispose() } catch { /* 已释放 */ }
    }
    for (const key of Array.from(this.memberMcp.keys())) this.uninstallMemberMcp(key)
    this.members.clear()
  }
}

/** 事件触发引擎：图谱变化 → 按规则派人。 */

/* ═══════════════ 全员会议：停滞检测 + 协同出新方案 ═══════════════ */


/* ═══════════ 命令审计：验收员回看某个队员执行过的命令，不合格就返工 ═══════════ */
/** 扫描类命令的覆盖度规则：命中即说明「这次扫描不够全面」，给出具体改法。 */
const AUDIT_RULES = [
  {
    id: 'port-no-full',
    label: '端口扫描没打全端口',
    severity: 'high',
    /* 只在「这名队员从来没做过全端口扫描」时才判为缺口，避免逐条误报 */
    match: (cmd, _row, ctx) => /\bnmap\b/.test(cmd) && ctx.hasFullPortScan !== true
      && !/\b-p\s*-|--top-ports|-p\s*1-65535/.test(cmd),
    advice: '换全端口扫描：nmap -p- --min-rate 1500 -T4 TARGET，再对开放端口做 nmap -sV -sC -p PORT1,PORT2',
  },
  {
    id: 'port-no-service',
    label: '端口扫描缺服务/版本识别',
    severity: 'medium',
    match: (cmd, _row, ctx) => /\bnmap\b/.test(cmd) && ctx.hasServiceScan !== true
      && !/-sV/.test(cmd) && !/redis-cli|mysql\s+-h|psql|curl|wget|nc\s+-z/.test(cmd),
    advice: '加 -sV 识别服务版本，必要时 -sC 跑默认脚本；版本信息决定后续 CVE 匹配',
  },
  {
    id: 'port-top-only',
    label: '只扫了 top 端口',
    severity: 'medium',
    match: (cmd) => /nmap/.test(cmd) && /--top-ports\s*(100|200|500|1000)?\b/.test(cmd) && !/-p\s*-/.test(cmd),
    advice: 'top 端口只是起点；补一轮 -p- 全端口，很多后台/内网服务落在高位端口',
  },
  {
    id: 'dir-small-wordlist',
    label: '目录爆破字典太小',
    severity: 'high',
    match: (cmd) => /(ffuf|gobuster|dirsearch|feroxbuster|dirb)\b/.test(cmd)
      && /(common\.txt|directory-list-2\.3-small|small\.txt|quickhits|raft-small)/i.test(cmd),
    advice: '换中等以上字典：/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 或 directory-list-2.3-medium.txt（≥2 万行）',
  },
  {
    id: 'dir-no-ext',
    label: '目录爆破没带扩展名',
    severity: 'medium',
    match: (cmd) => /(ffuf|gobuster|feroxbuster|dirsearch)\b/.test(cmd) && !/(-e\s|-x\s|\.php|\.jsp|\.asp|extensions?=)/i.test(cmd),
    advice: '补扩展名：-e .php,.asp,.aspx,.jsp,.html,.js,.zip,.bak,.old,.json,.xml',
  },
  {
    id: 'dir-low-threads',
    label: '目录爆破并发过低',
    severity: 'low',
    match: (cmd) => /ffuf/.test(cmd) && !/-t\s*(\d+)/.test(cmd),
    advice: '显式给并发：ffuf -t 60 -rate 200，避免默认值把大字典跑成几小时',
  },
  {
    id: 'subdomain-no-all',
    label: '子域枚举没开全源',
    severity: 'medium',
    match: (cmd) => /subfinder\b/.test(cmd) && !/-all/.test(cmd),
    advice: 'subfinder -d DOMAIN -all -recursive；再补一轮 assetfinder/amass 或多源对比，单源会漏大量子域',
  },
  {
    id: 'nuclei-no-filter',
    label: 'nuclei 没加模板/等级过滤',
    severity: 'low',
    match: (cmd) => /nuclei\b/.test(cmd) && !/(-severity|-tags|-t\s)/.test(cmd),
    advice: '明确扫描面：nuclei -severity critical,high,medium -tags cve,exposure,misconfig',
  },
  {
    id: 'no-purpose',
    label: '命令没写目的（留痕不全）',
    severity: 'low',
    match: (_cmd, row) => asText(row.purpose) === '',
    advice: '每条命令都要写 purpose：这次要回答什么问题、预期产出什么',
  },
]

class Audit {
  constructor({ store, board, tasks, squad, trace, configStore }) {
    this.store = store
    this.board = board
    this.tasks = tasks
    this.squad = squad
    this.trace = trace
    this.configStore = configStore
  }

  /** 从 sessionId 里取执行者代号（recon-squad-<key>-xxxx → <key>）。 */
  keyOf(row) {
    const hit = /^recon-squad-(a\d+)-/.exec(asText(row.sessionId))
    return hit === null ? '' : hit[1]
  }

  /** 汇总每个代号的命令数（含已回收成员，名字尽量从任务账本补）。 */
  async members(eng) {
    const byKey = new Map()
    for (const row of eng.commands || []) {
      const key = this.keyOf(row)
      if (key === '') continue
      if (!byKey.has(key)) byKey.set(key, { count: 0, lastAt: 0, role: '', name: '' })
      const slot = byKey.get(key)
      slot.count += 1
      const at = Number(row.startedAt ? Date.parse(row.startedAt) : 0) || 0
      if (at > slot.lastAt) slot.lastAt = at
    }
    const live = this.squad.list(eng.id)
    for (const member of live) {
      if (!byKey.has(member.key)) byKey.set(member.key, { count: 0, lastAt: 0, role: '', name: '' })
      const slot = byKey.get(member.key)
      slot.role = member.role
      slot.name = member.name
      slot.status = member.status
    }
    const tasks = await this.tasks.list(eng.id, 300)
    for (const row of tasks) {
      const who = asText(row.assignee)
      if (who === '') continue
      /* assignee 存的是名字；按名字补角色，assignee 是旧代号的行直接跳过 */
      const slot = Array.from(byKey.values()).find((item) => item.name === who)
      if (slot !== undefined && slot.role === '') slot.role = asText(row.role)
    }
    return Array.from(byKey.values()).sort((a, b) => b.count - a.count)
  }

  /** 取某成员（或整个角色）的命令列表。 */
  commandsOf(eng, { member, role, limit = 200 }) {
    const wanted = asText(member)
    let wantedKey = ''
    if (wanted !== '') {
      /* 传进来的是名字；内部再从在岗名单换成 sessionId 里的代号 */
      const hit = this.squad.list(eng.id).find((m) => m.name === wanted)
      if (hit === undefined) return []
      wantedKey = hit.key
    }
    const rows = (eng.commands || []).filter((row) => {
      const key = this.keyOf(row)
      if (wantedKey !== '') return key === wantedKey
      if (asText(role) !== '') {
        const live = this.squad.list(eng.id).find((m) => m.key === key)
        return live !== undefined && live.role === asText(role)
      }
      return true
    })
    return rows.slice(-limit)
  }

  /** 逐条跑规则，产出问题清单。 */
  inspect(eng, options = {}) {
    const rows = this.commandsOf(eng, options)
    const findings = []
    const seen = new Map()
    /* 集合级事实：这名队员/角色整体做过全端口与服务识别没有 */
    const allText = rows.map((row) => asText(row.command)).join('\n')
    const ctx = {
      hasFullPortScan: /nmap[^\n]*(-p\s*-|-p\s*1-65535|--top-ports)/.test(allText),
      hasServiceScan: /nmap[^\n]*-sV/.test(allText),
    }
    for (const row of rows) {
      const cmd = asText(row.command)
      for (const rule of AUDIT_RULES) {
        let hit = false
        try { hit = rule.match(cmd, row, ctx) === true } catch { hit = false }
        if (!hit) continue
        findings.push({
          rule: rule.id,
          label: rule.label,
          severity: rule.severity,
          advice: rule.advice,
          commandId: asText(row.id),
          command: shortText(cmd, 160),
          purpose: shortText(asText(row.purpose), 80),
          at: asText(row.startedAt),
        })
      }
      const dupKey = cmd.replace(/\s+/g, ' ').trim()
      if (dupKey !== '') seen.set(dupKey, (seen.get(dupKey) || 0) + 1)
    }
    for (const [cmd, count] of seen) {
      if (count < 2) continue
      findings.push({
        rule: 'duplicate-command',
        label: `同一条命令跑了 ${count} 次`,
        severity: 'low',
        advice: '重复跑同一条命令不产生新信息；换成不同字典/不同端口段/不同参数再跑',
        commandId: '',
        command: shortText(cmd, 160),
        purpose: '',
        at: '',
      })
    }
    const failed = rows.filter((row) => Number(row.exitCode) !== 0 && row.exitCode !== null && row.exitCode !== undefined).length
    const timedOut = rows.filter((row) => row.timedOut === true).length
    if (rows.length > 0 && (failed + timedOut) / rows.length > 0.3) {
      findings.push({
        rule: 'high-failure-rate',
        label: `失败/超时占比 ${Math.round(((failed + timedOut) / rows.length) * 100)}%`,
        severity: 'medium',
        advice: '先排查失败原因（目标不通/WAF/超时太短/依赖缺失），再重跑；不要带着失败率继续堆任务',
        commandId: '', command: '', purpose: '', at: '',
      })
    }
    const order = { high: 0, medium: 1, low: 2 }
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
    const highCount = findings.filter((f) => f.severity === 'high').length
    const verdict = highCount > 0 ? 'rework' : (findings.length > 0 ? 'improve' : 'pass')
    return {
      scope: asText(options.member) !== '' ? `成员 ${options.member}` : (asText(options.role) !== '' ? `角色 ${options.role}` : '全部'),
      commands: rows.length,
      findings: findings.slice(0, 40),
      total: findings.length,
      highCount,
      verdict,
      verdictText: verdict === 'rework' ? '有高风险覆盖缺口，必须返工重做'
        : (verdict === 'improve' ? '能用但不全面，建议补一轮' : '没发现覆盖缺口'),
    }
  }

  /** 建返工任务并派回原成员（或原角色）。 */
  async rework(eng, options = {}) {
    const member = asText(options.member)
    /* 没显式给角色时，按该成员自己的角色派返工，别一律塞给 web 手 */
    let role = asText(options.role)
    if (role === '' && member !== '') {
      const rows = await this.members(eng)
      const hit = rows.find((row) => row.name === member)
      role = hit !== undefined && asText(hit.role) !== '' ? asText(hit.role) : 'web'
    }
    if (role === '') role = 'web'
    const report = this.inspect(eng, { member, role })
    if (report.total === 0) return { ok: true, created: null, report, skipped: '没发现需要返工的问题' }
    const top = report.findings.slice(0, 6)
    const title = `返工：${member !== '' ? member : role} 的扫描覆盖不足（${top[0].label}）`
    const goal = [
      `针对 ${member !== '' ? `队员 ${member}` : `角色 ${role}`} 的执行过程重做覆盖不足的部分：`,
      ...top.map((f, i) => `${i + 1}) ${f.label}${f.command !== '' ? ` —— 原命令：${f.command}` : ''}\n   改法：${f.advice}`),
    ].join('\n')
    const acceptance = [
      '重跑的命令要能在命令日志里看到改进后的参数（如 -p-、-sV、更大字典、-e 扩展名、-all 等）',
      '新产出至少 1 条资产节点或漏洞证据，commandId 写进任务证据',
      '在看板写一条结论：这轮补到了什么、还有什么没覆盖',
    ].join('；')
    const task = await this.tasks.create(eng.id, {
      title,
      goal,
      acceptance,
      role,
      assignee: member && member.name ? member.name : asText(member),
      createdBy: { role: 'qa', name: '验收' },
      followUpOf: asText(options.followUpOf) || null,
    })
    await this.board.post(eng.id, {
      author: { role: 'qa', name: '验收' },
      kind: 'task',
      text: [
        `🔍 **命令审计 · ${report.scope}**（${report.commands} 条命令，问题 ${report.total} 项，高危 ${report.highCount} 项）`,
        `结论：${report.verdictText}`,
        ...top.map((f) => `· [${f.severity}] ${f.label}${f.commandId !== '' ? `（${f.commandId}）` : ''} → ${f.advice}`),
        `已建返工任务：**${title}**`,
      ].join('\n'),
      refs: { nodeIds: [], vulnIds: [], commandIds: top.map((f) => f.commandId).filter((id) => id !== '') },
      status: 'open',
    })
    if (member !== '') {
      try {
        await this.squad.task(member, [
          '【返工通知】验收员审计了你执行过的命令，覆盖不够全面，按下面重做：',
          goal,
          `验收标准：${acceptance}`,
          '做完把新命令的 commandId 写进任务证据，并在看板留一条结论。',
        ].join('\n'), eng.id)
      } catch { /* 成员不在岗就只留任务 */ }
    }
    await this.trace?.push?.(eng.id, {
      kind: 'verdict',
      actor: { role: 'qa', name: '验收' },
      title: `审计 ${report.scope}：${report.verdictText}`,
      detail: goal,
      refs: { taskId: task.id },
    })
    return { ok: true, task, report }
  }
}

/* ═══════════ 断点续跑：暂停 / 启动 / 崩溃后恢复 ═══════════ */
class Runner {
  constructor({ store, cfg, configStore, hub, board, tasks, squad, cockpit, trace }) {
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.board = board
    this.tasks = tasks
    this.squad = squad
    this.cockpit = cockpit
    this.trace = trace
    this.dir = join(cfg.root, 'checkpoints')
    this.cache = new Map()
    this.stallMs = 15 * 60 * 1000
    this.writeQueue = Promise.resolve()
  }

  fileOf(engagementId) {
    return join(this.dir, `${String(engagementId).replace(/[^a-zA-Z0-9_-]/g, '_')}.json`)
  }

  async load(engagementId) {
    if (this.cache.has(engagementId)) return this.cache.get(engagementId)
    try {
      const raw = JSON.parse(await readFile(this.fileOf(engagementId), 'utf8'))
      this.cache.set(engagementId, raw)
      return raw
    } catch {
      return undefined
    }
  }

  async save(engagementId, patch) {
    const run = this.writeQueue.then(() => this.saveInner(engagementId, patch))
    this.writeQueue = run.then(() => undefined, () => undefined)
    return run
  }

  async saveInner(engagementId, patch) {
    const previous = (await this.load(engagementId)) || {}
    const next = { ...previous, ...patch, engagementId, updatedAt: nowMs() }
    this.cache.set(engagementId, next)
    try { await ensureDir(this.dir) } catch { /* 忽略 */ }
    await writeJsonAtomic(this.fileOf(engagementId), next)
    try { this.hub.broadcast({ type: 'checkpoint', engagementId, checkpoint: next }) } catch { /* 忽略 */ }
    return next
  }

  /* 快照：任务账本 + 在岗成员 + 最近命令 + 当前阶段，够 resume 用 */
  async snapshot(eng, phase, reason) {
    const tasks = await this.tasks.list(eng.id, 300)
    const stats = await this.tasks.stats(eng.id)
    const members = this.squad.list(eng.id)
    const mission = await this.tasks.missionOf(eng.id)
    const lastCommand = (eng.commands || []).slice(-1)[0]
    return {
      phase,
      reason: asText(reason),
      mission: mission || null,
      stats,
      tasks: tasks.filter((row) => row.status === 'open' || row.status === 'doing' || row.status === 'failed' || row.status === 'blocked')
        .slice(-40)
        .map((row) => ({ id: row.id, title: row.title, goal: row.goal, acceptance: row.acceptance, role: row.role, status: row.status, assignee: row.assignee || null })),
      done: tasks.filter((row) => row.status === 'passed').length,
      members: members.map((m) => ({ key: m.key, role: m.role, name: m.name, task: m.task || '', status: m.status })),
      cursor: lastCommand ? { commandId: lastCommand.id, command: lastCommand.command, at: lastCommand.startedAt } : null,
      counts: { nodes: (eng.nodes || []).length, edges: (eng.edges || []).length, vulns: (eng.vulns || []).length, commands: (eng.commands || []).length },
      savedAt: nowMs(),
    }
  }

  /* 中断：停掉所有人 + 记断点（manual 手动，stall 断网/卡死，shutdown 关机） */
  async pause(eng, reason = 'manual') {
    const checkpoint = await this.snapshot(eng, 'paused', reason)
    await this.save(eng.id, checkpoint)
    let stopped = 0
    try { stopped = (await this.squad.stopAll(eng.id)) || 0 } catch { /* 没有在跑的 */ }
    try { await this.cockpit?.stop?.(eng.id) } catch { /* 忽略 */ }
    await this.board.post(eng.id, {
      author: { role: 'system', name: '调度' },
      kind: 'note',
      text: `⏸ 已中断（${reason === 'manual' ? '手动' : reason}）。断点已存：任务 ${checkpoint.stats.open + checkpoint.stats.doing} 待办 / ${checkpoint.done} 已通过，成员 ${checkpoint.members.length} 人，最后命令 ${checkpoint.cursor ? checkpoint.cursor.commandId : '无'}。恢复时点「继续」即可从这里接着跑。`,
      status: 'open',
    })
    return { ok: true, checkpoint, stopped }
  }

  /* 启动：按断点把人和活重新拉起来 */
  async resume(eng, note = '') {
    const checkpoint = await this.load(eng.id)
    if (checkpoint === undefined) {
      return { ok: false, error: '这个项目还没有断点：先让它跑起来再中断，或直接给总指挥下指令' }
    }
    const pending = (checkpoint.tasks || []).filter((row) => row.status !== 'passed')
    const pendingText = pending.slice(0, 12)
      .map((row) => `· [${row.status}] ${row.title}${row.role ? `（${row.role}）` : ''}${row.acceptance ? ` —— 验收：${row.acceptance}` : ''}`)
      .join('\n')
    const membersText = (checkpoint.members || []).map((m) => `· ${m.name}（${m.role}）${m.task ? ` 上次任务：${shortText(m.task, 80)}` : ''}`).join('\n')
    const brief = [
      '【从断点继续】',
      note !== '' ? `说明：${note}` : '',
      `上次中断原因：${checkpoint.reason || '未知'}；保存时间 ${new Date(Number(checkpoint.savedAt) || nowMs()).toLocaleString('zh-CN')}`,
      `进度：资产 ${(checkpoint.counts || {}).nodes || 0} · 漏洞 ${(checkpoint.counts || {}).vulns || 0} · 命令 ${(checkpoint.counts || {}).commands || 0} · 任务 ${checkpoint.stats ? checkpoint.stats.total : 0}（通过 ${checkpoint.done || 0}）`,
      checkpoint.cursor ? `最后一条命令：${checkpoint.cursor.commandId} ${shortText(checkpoint.cursor.command || '', 100)}` : '',
      pendingText !== '' ? `未完成的任务：\n${pendingText}` : '没有未完成任务',
      membersText !== '' ? `上次在岗：\n${membersText}` : '',
      '',
      '请：1) 先 recon_view 复核图谱现状，确认断点之后有没有人补过活；2) 把未完成任务按优先级重新派给对应角色；3) 继续推进，不要从头重跑已经完成的扫描。',
    ].filter((line) => line !== '').join('\n')

    await this.board.post(eng.id, {
      author: { role: 'system', name: '调度' },
      kind: 'note',
      text: `▶ 从断点继续（上次中断：${checkpoint.reason || '未知'}）。未完成任务 ${pending.length} 条；总指挥已收到交接单。`,
      status: 'open',
    })

    let spawned = 0
    for (const row of pending.slice(0, 4)) {
      const roleId = asText(row.role) || 'scout'
      const taskText = `【继续未完成任务】${row.title}\n目标：${row.goal || row.title}\n验收标准：${row.acceptance || '按任务标题判定'}${note !== '' ? `\n补充说明：${note}` : ''}\n做完把证据（commandId/节点/漏洞）附到任务上。`
      try {
        /* 优先复用同角色在岗成员，避免每次 resume 都新建一个重复队员。 */
        const existing = this.squad.list(eng.id).find((m) => m.role === roleId)
        let member
        if (existing !== undefined) {
          member = await this.squad.task(existing.name, taskText, eng.id)
        } else {
          member = await this.squad.spawn({
            engagementId: eng.id,
            roleId,
            task: taskText,
            origin: 'resume',
            allowCore: true,
          })
        }
        spawned += 1
        try {
          await this.tasks.update(eng.id, row.id, {
            status: 'doing',
            assignee: member && member.name ? member.name : '',
          }, { role: 'system', name: '断点续跑' })
        } catch { /* 任务可能已被删除 */ }
      } catch { /* 成员满了就继续下一条 */ }
    }

    let handoff = null
    try {
      handoff = await this.cockpit?.send?.({ engagement: eng.id, text: brief, tier: 'deep' })
    } catch { /* 驾驶舱不可用就只依赖看板 */ }

    const next = await this.save(eng.id, { ...checkpoint, phase: 'running', reason: '', resumedAt: nowMs(), spawned })
    return { ok: true, checkpoint: next, spawned, pending: pending.length, handoff: handoff ? 'sent' : 'skipped' }
  }

  /* 自动巡检：正在跑但长时间没有任何新动静（断网/额度耗尽/进程被杀）→ 自动存断点并标 interrupted */
  async tick() {
    const eng = await this.store.activeEngagement()
    if (eng === undefined) return
    const checkpoint = await this.load(eng.id)
    const members = this.squad.list(eng.id)
    const running = members.filter((m) => m.status === 'running' || m.status === 'starting')
    const phase = checkpoint ? checkpoint.phase : 'idle'
    if (phase === 'paused') return
    if (running.length === 0) {
      if (phase === 'running') {
        /* 之前被标记在跑，但已经没人在跑：可能全崩了 */
        const lastAt = Number((checkpoint && checkpoint.savedAt) || 0)
        if (nowMs() - lastAt > this.stallMs) {
          await this.save(eng.id, { ...(await this.snapshot(eng, 'interrupted', '成员全部消失（断网/关机/额度）')), phase: 'interrupted' })
        }
      }
      return
    }
    const lastCommandAt = (eng.commands || []).slice(-1).map((c) => toEpoch(c.startedAt))[0] || 0
    const lastTraceAt = toEpoch(checkpoint && checkpoint.lastBeat)
    const memberLastAt = members.reduce((max, m) => Math.max(max, Number(m.lastAt) || 0), 0)
    const beat = Math.max(lastCommandAt, lastTraceAt, memberLastAt)
    if (beat !== 0 && nowMs() - beat > this.stallMs) {
      const fresh = await this.snapshot(eng, 'interrupted', '心跳超时（断网/额度耗尽/卡死）')
      await this.save(eng.id, { ...fresh, lastBeat: beat })
      await this.board.post(eng.id, {
        author: { role: 'system', name: '调度' },
        kind: 'note',
        text: `⚠ 检测到心跳超时（${Math.round(this.stallMs / 60000)} 分钟没有新命令或新产出），已存断点并标记「已中断」。恢复网络或开机后点「继续」即可续跑。`,
        status: 'open',
      })
      return
    }
    /* 只在首次进入 running 或仍有真实活动时落一次基线；不能每轮刷新 lastBeat，
       否则卡死的 agent 永远看起来“刚刚有活动”。 */
    if (checkpoint === undefined || checkpoint.phase !== 'running' || toEpoch(checkpoint.lastBeat) === 0) {
      await this.save(eng.id, { ...(checkpoint || {}), phase: 'running', lastBeat: beat || nowMs() })
    }
  }

  async status(eng) {
    const checkpoint = eng === undefined ? undefined : await this.load(eng.id)
    const members = eng === undefined ? [] : this.squad.list(eng.id)
    const running = members.filter((m) => m.status === 'running' || m.status === 'starting').length
    return {
      phase: checkpoint ? checkpoint.phase : 'idle',
      running,
      checkpoint: checkpoint
        ? {
          phase: checkpoint.phase, reason: checkpoint.reason || '', savedAt: checkpoint.savedAt || 0,
          resumedAt: checkpoint.resumedAt || 0, pending: (checkpoint.tasks || []).length,
          done: checkpoint.done || 0, counts: checkpoint.counts || {}, members: (checkpoint.members || []).length,
          cursor: checkpoint.cursor || null,
        }
        : null,
    }
  }

  forget(engagementId) {
    this.cache.delete(engagementId)
  }
}

class Meeting {
  constructor({ store, cfg, configStore, hub, board, squad, tasks, cockpit, trace }) {
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.board = board
    this.squad = squad
    this.tasks = tasks
    this.cockpit = cockpit
    this.trace = trace
    this.lastAt = new Map()
    this.counts = new Map()
    this.busy = new Set()
    this.loaded = new Set()
  }

  meetingFile(engagementId) {
    return join(this.store.root, 'meeting', `${String(engagementId).replace(/[^a-zA-Z0-9_-]/g, '_')}.json`)
  }

  async load(engagementId) {
    if (this.loaded.has(engagementId)) return
    this.loaded.add(engagementId)
    try {
      const raw = JSON.parse(await readFile(this.meetingFile(engagementId), 'utf8'))
      if (raw !== null && typeof raw === 'object') {
        if (Number.isFinite(Number(raw.rounds))) this.counts.set(engagementId, Number(raw.rounds))
        if (Number.isFinite(Number(raw.lastAt))) this.lastAt.set(engagementId, Number(raw.lastAt))
      }
    } catch { /* 第一次没有会议状态 */ }
  }

  async persist(engagementId) {
    try {
      await ensureDir(join(this.store.root, 'meeting'))
      await writeJsonAtomic(this.meetingFile(engagementId), {
        rounds: this.counts.get(engagementId) || 0,
        lastAt: this.lastAt.get(engagementId) || 0,
        updatedAt: nowMs(),
      })
    } catch { /* 会议状态落盘失败不阻断会议 */ }
  }

  /** 会议参数全部来自控制台配置（没设就按默认 20/20/3）。 */
  options() {
    const raw = (this.configStore && this.configStore.get ? this.configStore.get().meeting : null) || {}
    const clamp = (value, min, max, fallback) => {
      const num = Number(value)
      return Number.isFinite(num) ? Math.min(max, Math.max(min, Math.round(num))) : fallback
    }
    return {
      stallMinutes: clamp(raw.stallMinutes, 5, 240, 20),
      gapMinutes: clamp(raw.gapMinutes, 5, 240, 20),
      maxRounds: clamp(raw.maxRounds, 1, 20, 3),
    }
  }

  /* 停滞判定：任务全派完 + 没有人在跑 + 一段时间内没有新进展 */
  async verdict(eng) {
    if (eng === undefined || eng === null) return { stalled: false, reasons: [] }
    await this.load(eng.id)
    const reasons = []
    const stats = await this.tasks.stats(eng.id)
    const members = this.squad.list(eng.id)
    const running = members.filter((m) => m.status === 'running' || m.status === 'starting').length
    const pending = stats.open + stats.doing + stats.blocked
    if (running > 0) return { stalled: false, reasons: ['有成员在跑'] }
    if (pending > 0) return { stalled: false, reasons: [`还有 ${pending} 个任务没完成`] }
    if (stats.total === 0) {
      const nodeCount = (eng.nodes || []).length
      return { stalled: nodeCount > 0, reasons: [nodeCount > 0 ? '有资产但一个任务都没拆' : '还没有任何资产'] }
    }
    if (stats.failed === 0 && stats.passed > 0 && stats.open === 0 && stats.doing === 0 && stats.blocked === 0) {
      /* 全部通过：那是完成态，不需要开会 */
      return { stalled: false, reasons: ['所有任务已通过验收'] }
    }
    if (stats.failed > 0) reasons.push(`${stats.failed} 个任务被驳回未返工`)

    /* 时间窗：最近一段时间有没有实质进展（新命令 / 新资产 / 新漏洞 / 验收通过） */
    const options = this.options()
    const windowMs = options.stallMinutes * 60 * 1000
    const since = nowMs() - windowMs
    const freshCommands = (eng.commands || []).filter((c) => toEpoch(c.startedAt) >= since).length
    const freshNodes = (eng.nodes || []).filter((n) => toEpoch(n.ts || n.createdAt) >= since).length
    const freshVulns = (eng.vulns || []).filter((v) => toEpoch(v.ts || v.createdAt) >= since).length
    if (freshCommands === 0 && freshNodes === 0 && freshVulns === 0) {
      reasons.push(`最近 ${Math.round(windowMs / 60000)} 分钟没有新命令/资产/漏洞`)
    } else {
      return { stalled: false, reasons: ['仍在产生新信息'] }
    }

    const last = this.lastAt.get(eng.id) || 0
    const wait = last + options.gapMinutes * 60 * 1000 - nowMs()
    if (wait > 0) return { stalled: false, reasons: [`距离上次会议还有 ${Math.ceil(wait / 60000)} 分钟`] }
    return { stalled: true, reasons, stats, members }
  }

  /* 召集全员：每个在编角色各出一份新方案，总指挥汇总成新一轮计划 */
  async convene(eng, { reason = '自动检测到停滞', manual = false } = {}) {
    if (eng === undefined || eng === null) throw new Error('还没有项目')
    if (this.busy.has(eng.id)) return { ok: false, error: '这个项目正在开会' }
    await this.load(eng.id)
    this.busy.add(eng.id)
    const round = (this.counts.get(eng.id) || 0) + 1
    this.counts.set(eng.id, round)
    this.lastAt.set(eng.id, nowMs())
    await this.persist(eng.id)
    try {
      const stats = await this.tasks.stats(eng.id)
      const verified = (eng.vulns || []).filter((v) => v.status === 'verified').length
      const failed = await this.tasks.list(eng.id, 200)
      const blocked = failed.filter((row) => row.status === 'failed' || row.status === 'blocked')
        .slice(-6)
        .map((row) => `· ${row.title}${row.note ? ` —— ${shortText(row.note, 120)}` : ''}`)
        .join('\n')
      const recentBoard = await this.board.recentText(eng.id, 8)
      const brief = [
        `第 ${round} 轮全员会议`,
        `触发原因：${reason}`,
        `现状：资产 ${(eng.nodes || []).length} · 关系 ${(eng.edges || []).length} · 漏洞 ${(eng.vulns || []).length}（已验证 ${verified}）· 命令 ${(eng.commands || []).length}`,
        `任务：共 ${stats.total}，通过 ${stats.passed}，驳回 ${stats.failed}，待办 ${stats.open + stats.doing}`,
        blocked !== '' ? `卡住的：\n${blocked}` : '',
        recentBoard !== '' ? `最近看板：\n${recentBoard}` : '',
      ].filter((line) => line !== '').join('\n')

      const roles = this.squad.roles()
        .filter((role) => role !== null && typeof role === 'object' && asText(role.id) !== '')
        .slice(0, 7)
      const meetingTask = (role, roleId) => [
        `【全员会议 · 第 ${round} 轮】你是「${asText(role.name, roleId)}」。`,
        '目标：在不重复已失败路径的前提下，给出能推进的新方案。',
        brief,
        '产出要求（写进看板，kind=hypothesis 或 conclusion）：',
        '1) 一句话诊断：为什么现在卡住了；',
        '2) 新方案 1-3 条：每条写清 打什么/怎么打/预期产出；',
        '3) 建议任务：标题 + 目标 + 验收标准（谁看都能判）；',
        '4) 明确说出你需要谁配合（角色即可）。',
        '禁止：重复已被驳回的做法；禁止只说「继续深挖」这种空话。',
      ].join('\n')

      const seats = this.squad.list(eng.id)
      const seatFor = (roleId) => seats.find((row) => row.role === roleId) || null
      const seated = []

      /* 常设席位（总指挥 / 参谋）不通过 spawn 重开：直接在原座上下发会议任务，
         保证全局永远只有一个总指挥、一个参谋。 */
      const staffSeat = seatFor('staff')
      if (staffSeat !== null) {
        try {
          await this.squad.task(staffSeat.name, meetingTask({ name: staffSeat.name, id: 'staff' }, 'staff'), eng.id)
          seated.push({ role: 'staff', name: staffSeat.name })
        } catch { /* 参谋不可用就跳过 */ }
      }

      for (const role of roles) {
        const roleId = asText(role.id)
        if (CORE_ROLES.has(roleId)) continue
        try {
          /* 同角色已有在岗成员时复用，避免每轮会议都新建一批队员。 */
          const existing = seatFor(roleId)
          if (existing !== null) {
            await this.squad.task(existing.name, meetingTask(role, roleId), eng.id)
            seated.push({ role: roleId, name: existing.name })
          } else {
            const member = await this.squad.spawn({ engagementId: eng.id, roleId, tier: asText(role.tier, 'deep'), task: meetingTask(role, roleId), origin: 'meeting' })
            seated.push({ role: roleId, name: member.name })
          }
        } catch { /* 成员满了或角色不可用就跳过 */ }
      }

      await this.board.post(eng.id, {
        author: { role: 'system', name: '会议主持' },
        kind: 'note',
        text: [
          `🗣 全员会议 #${round}（${manual ? '手动召开' : '自动触发'}）`,
          `原因：${reason}`,
          `参会：${seated.map((row) => row.name).join('、') || '无（成员已满或角色不可用）'}`,
          '议题：诊断停滞原因 → 每角色出 1-3 条新方案 → 总指挥汇总成新一轮任务。',
        ].join('\n'),
        status: 'open',
      })

      /* 让总指挥汇总：等各角色交方案后，把结论收成新一轮任务。
         总指挥常设席位一直在，直接追加任务；没有席位才退回驾驶舱主 agent。 */
      const commanderTask = [
        `【全员会议 · 第 ${round} 轮 · 主持】`,
        brief,
        '本轮已请每个角色各出一份方案（他们会把方案写到看板）。',
        '你要做的是：',
        '1) 等他们的方案落到看板后，逐条判断可行性（可先用 recon_board list 读）；',
        '2) 合成一份「新一轮计划」：按优先级列出 3-6 条任务，每条带目标与验收标准；',
        '3) 用 recon_task 创建这些任务并派给对应角色，然后开始推进；',
        '4) 如果判断目标已不可达，明确写出结论与建议（降级范围 / 换攻击面 / 收工），写进看板。',
        '不要重复上一轮已经失败的做法。',
      ].join('\n')
      const commanderSeat = seatFor('commander')
      if (commanderSeat !== null) {
        try {
          await this.squad.task(commanderSeat.name, commanderTask, eng.id)
          seated.push({ role: 'commander', name: commanderSeat.name })
        } catch {
          try { await this.cockpit?.send?.({ engagement: eng.id, text: commanderTask, tier: 'deep' }) } catch { /* 只留看板记录 */ }
        }
      } else {
        try { await this.cockpit?.send?.({ engagement: eng.id, text: commanderTask, tier: 'deep' }) } catch { /* 只留看板记录 */ }
      }

      this.hub.broadcast({ type: 'meeting', engagementId: eng.id, round, seated })
      return { ok: true, round, seated, reason }
    } finally {
      this.busy.delete(eng.id)
    }
  }

  /* 定时巡检：只对当前项目、且只在停滞时开会 */
  async tick() {
    const eng = await this.store.activeEngagement()
    if (eng === undefined) return
    const verdict = await this.verdict(eng)
    if (!verdict.stalled) return
    await this.load(eng.id)
    const round = this.counts.get(eng.id) || 0
    const cap = this.options().maxRounds
    if (round >= cap) {
      if (round === cap) {
        this.counts.set(eng.id, round + 1)
        await this.persist(eng.id)
        await this.board.post(eng.id, {
          author: { role: 'system', name: '会议主持' },
          kind: 'note',
          text: `❗ 已连续 ${cap} 轮全员会议仍无进展，自动开会暂停。需要人工介入：改目标 / 缩范围 / 换攻击面。`,
          status: 'open',
        })
      }
      return
    }
    await this.convene(eng, { reason: verdict.reasons.join('；') })
  }

  status(eng) {
    const options = this.options()
    return {
      round: this.counts.get(eng.id) || 0,
      lastAt: this.lastAt.get(eng.id) || 0,
      maxRounds: options.maxRounds,
      stallMinutes: options.stallMinutes,
      gapMinutes: options.gapMinutes,
      busy: this.busy.has(eng.id),
    }
  }

  forget(engagementId) {
    this.lastAt.delete(engagementId)
    this.counts.delete(engagementId)
    this.busy.delete(engagementId)
    this.loaded.delete(engagementId)
  }
}

class Automation {
  constructor({ ctx, store, cfg, configStore, hub, board, squad }) {
    this.ctx = ctx
    this.store = store
    this.cfg = cfg
    this.configStore = configStore
    this.hub = hub
    this.board = board
    this.squad = squad
    this.lastFired = new Map()
    this.seen = new Set()
    this.queue = []
    this.draining = null
    this.drainAgain = false
  }

  config() {
    const raw = this.configStore.get().automation
    const merged = mergeDeep(cloneJson(DEFAULT_AUTOMATION), raw && typeof raw === 'object' ? raw : {})
    merged.maxAgents = Number.isFinite(Number(merged.maxAgents))
      ? Math.max(1, Math.min(50, Math.floor(Number(merged.maxAgents))))
      : 8
    merged.maxAutomationAgents = Number.isFinite(Number(merged.maxAutomationAgents))
      ? Math.max(1, Math.min(50, Math.floor(Number(merged.maxAutomationAgents))))
      : 3
    const configuredMembers = Number.isFinite(Number(merged.maxMembers))
      ? Math.max(1, Math.min(50, Math.floor(Number(merged.maxMembers))))
      : 6
    /* 控制台只暴露一个「最大并发数」；成员上限不能低于它，否则调大并发也不会生效 */
    merged.maxMembers = Math.max(merged.maxAgents, configuredMembers)
    merged.rules = Array.isArray(merged.rules) ? merged.rules : []
    return merged
  }

  render(template, context) {
    return String(template || '').replace(/\{\{(\w+)\}\}/g, (_, key) => {
      const value = context[key]
      return value === undefined || value === null ? '' : String(value)
    })
  }

  /** 自动化自己的并发：只统计 origin=trigger 的成员；小组整体算一个。 */
  activeAutomationCount(engagementId) {
    const groups = new Set()
    let ungrouped = 0
    for (const member of this.squad.list(engagementId)) {
      if (asText(member.origin) !== 'trigger') continue
      if (member.status !== 'running' && member.status !== 'starting' && member.status !== 'waiting') continue
      if (asText(member.groupId) !== '') groups.add(member.groupId)
      else ungrouped += 1
    }
    return ungrouped + groups.size
  }

  /** 自动化队列：同一候选/规则只保留一个，避免事件风暴重复排队。 */
  enqueue(job) {
    const key = asText(job.dedupeKey) || `${job.engagementId}:${job.ruleId}:${job.task}`
    if (this.queue.some((item) => item.dedupeKey === key)) return false
    this.queue.push({ ...job, dedupeKey: key, queuedAt: nowMs() })
    if (this.queue.length > 1000) this.queue.splice(0, this.queue.length - 1000)
    this.hub.broadcast({ type: 'automation.queue', queued: this.queue.length })
    void this.drain()
    return true
  }

  /** 有空位就按入队顺序派发；超过 maxAutomationAgents 的任务留在队列里。 */
  async drain() {
    if (this.draining !== null) {
      this.drainAgain = true
      return this.draining
    }
    const run = Promise.resolve().then(async () => {
      do {
        this.drainAgain = false
        const config = this.config()
        if (!config.enabled) return
        let progressed = true
        while (progressed) {
          progressed = false
          let index = -1
          for (let i = 0; i < this.queue.length; i += 1) {
            if (this.activeAutomationCount(this.queue[i].engagementId) < config.maxAutomationAgents) {
              index = i
              break
            }
          }
          if (index < 0) break
          const [job] = this.queue.splice(index, 1)
          this.hub.broadcast({ type: 'automation.queue', queued: this.queue.length })
          try {
            await this.squad.spawn({
              engagementId: job.engagementId,
              roleId: job.roleId,
              tier: job.tier,
              task: job.task,
              origin: 'trigger',
            })
            this.lastFired.set(`${job.engagementId}:${job.ruleId}`, nowMs())
            progressed = true
          } catch (error) {
            await this.board.post(job.engagementId, {
              author: { role: 'system', name: '调度台' },
              kind: 'note',
              text: `自动化规则「${job.ruleId}」排队派发失败：${shortText(error && error.message ? error.message : error, 300)}`,
            })
          }
        }
      } while (this.drainAgain === true)
    })
    this.draining = run
    try {
      return await run
    } finally {
      if (this.draining === run) this.draining = null
      if (this.drainAgain === true) {
        this.drainAgain = false
        void this.drain()
      }
    }
  }

  status(engagementId) {
    const config = this.config()
    return {
      queued: engagementId === undefined
        ? this.queue.length
        : this.queue.filter((job) => job.engagementId === engagementId).length,
      runningAutomation: engagementId === undefined ? 0 : this.activeAutomationCount(engagementId),
      maxAutomationAgents: config.maxAutomationAgents,
    }
  }

  /** 周期巡检规则（on=interval）：到点入队，由 drain 按自动化并发上限派发。 */
  async tick() {
    const config = this.config()
    if (!config.enabled) return
    const eng = await this.store.activeEngagement()
    if (eng === undefined) return
    const now = nowMs()
    for (const rule of config.rules) {
      if (rule === null || typeof rule !== 'object' || rule.enabled === false) continue
      if (asText(rule.on) !== 'interval') continue
      const every = Number.isFinite(rule.everyMs) ? Math.max(60000, rule.everyMs) : 900000
      const key = `${eng.id}:interval:${rule.id}`
      const last = this.lastFired.get(key) || 0
      if (now - last < every) continue
      const job = {
        engagementId: eng.id,
        ruleId: asText(rule.id, 'interval'),
        roleId: asText(rule.role, 'scout'),
        tier: asText(rule.tier),
        task: this.render(rule.task || '做一次巡检：读图谱与看板，指出下一步 3 条高价值任务，写进看板。', {}),
        dedupeKey: `${key}:${Math.floor(now / every)}`,
      }
      if (this.enqueue(job)) {
        this.lastFired.set(key, now)
        if (this.activeAutomationCount(eng.id) >= config.maxAutomationAgents) {
          await this.board.post(eng.id, {
            author: { role: 'system', name: '调度台' },
            kind: 'note',
            text: `自动化并发已达 ${config.maxAutomationAgents}，巡检规则「${rule.id}」已进入队列（当前队列 ${this.queue.length}）。`,
          })
        }
      }
    }
    await this.drain()
  }

  async onDelta(eng, delta) {
    const config = this.config()
    if (!config.enabled) return
    const now = nowMs()
    const candidates = []
    for (const command of delta.newCommands) {
      candidates.push({
        ruleType: 'command.finished',
        nodeId: command.nodeIds && command.nodeIds.length > 0 ? command.nodeIds[0] : '',
        kind: 'command',
        value: shortText(command.command, 120),
        title: shortText(command.command, 120),
        severity: '',
        endpoint: '',
        commandId: command.id,
        command: command.command,
        exitCode: command.exitCode,
        purpose: command.purpose || '',
      })
    }
    for (const node of delta.newNodes) {
      candidates.push({
        ruleType: 'node.created',
        nodeId: node.id,
        kind: node.kind,
        value: node.value,
        title: node.label || node.value,
        severity: '',
        endpoint: node.value,
      })
    }
    for (const vuln of delta.newVulns) {
      const node = eng.nodes.find((n) => n.id === vuln.nodeId)
      candidates.push({
        ruleType: 'vuln.created',
        nodeId: vuln.nodeId,
        kind: node ? node.kind : '',
        value: node ? node.value : vuln.nodeId,
        title: vuln.title,
        severity: vuln.severity,
        endpoint: vuln.endpoint || (node ? node.value : ''),
      })
    }
    if (candidates.length === 0) return
    for (const rule of config.rules) {
      if (rule === null || typeof rule !== 'object' || rule.enabled === false) continue
      if (asText(rule.on) === 'interval') continue
      for (const candidate of candidates) {
        if (asText(rule.on) !== candidate.ruleType) continue
        const kinds = asList(rule.whenKinds)
        if (kinds.length > 0 && !kinds.includes(candidate.kind)) continue
        const severities = asList(rule.whenSeverity)
        if (severities.length > 0 && !severities.includes(candidate.severity)) continue
        const dedupeKey = `${eng.id}:${rule.id}:${candidate.nodeId}:${candidate.title}`
        if (this.seen.has(dedupeKey)) continue
        const last = this.lastFired.get(`${eng.id}:${rule.id}`) || 0
        const cooldown = Number.isFinite(rule.cooldownMs) ? rule.cooldownMs : 30000
        if (now - last < cooldown) continue
        this.seen.add(dedupeKey)
        if (this.seen.size > 2000) this.seen = new Set(Array.from(this.seen).slice(-1000))
        const job = {
          engagementId: eng.id,
          ruleId: asText(rule.id, 'auto'),
          roleId: asText(rule.role, 'hunter'),
          tier: asText(rule.tier),
          task: this.render(rule.task, candidate),
          dedupeKey,
        }
        if (this.enqueue(job)) {
          this.lastFired.set(`${eng.id}:${rule.id}`, now)
          if (this.activeAutomationCount(eng.id) >= config.maxAutomationAgents) {
            await this.board.post(eng.id, {
              author: { role: 'system', name: '调度台' },
              kind: 'note',
              text: `规则「${rule.id}」命中 ${candidate.kind || candidate.ruleType} ${candidate.value}，自动化并发已达 ${config.maxAutomationAgents}，已进入队列（当前队列 ${this.queue.length}）。`,
            })
          }
        }
      }
    }
    await this.drain()
  }
}

/* ────────────────────────── HTTP 桥 ────────────────────────── */

function sendJson(res, status, value) {
  const body = `${JSON.stringify(value)}\n`
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  })
  res.end(body)
}

async function readBody(req, limit = 36 * 1024 * 1024) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > limit) throw new Error('请求体过大')
    chunks.push(chunk)
  }
  if (chunks.length === 0) return {}
  const text = Buffer.concat(chunks).toString('utf8')
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    throw new Error('请求体不是合法 JSON')
  }
}

function sameOrigin(req) {
  const host = typeof req.headers.host === 'string' ? req.headers.host : ''
  const origin = req.headers.origin
  /* 缺少 Origin 的命令行/同源图片请求允许通过；浏览器跨站请求会带
     Sec-Fetch-Site: cross-site，必须拒绝。不能因为请求来自本机回环就放行
     就放行，否则反向代理场景下所有外部请求都会被当成同源。 */
  if (origin === undefined || origin === '') {
    const site = typeof req.headers['sec-fetch-site'] === 'string' ? req.headers['sec-fetch-site'] : ''
    return site === '' || site === 'same-origin' || site === 'none'
  }
  if (origin === 'null') return false
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

function makeHandler(deps) {
  const { store, cfg, configStore, hub, cockpit, mcp, board, tasks, trace, squad, browser, automation, meeting, runner, audit, ctx, browsers, brief, customModels } = deps

  const pick = async (engagementArg) => {
    if (asText(engagementArg) !== '') {
      const eng = await store.load(engagementArg)
      if (eng === undefined) throw new Error(`靶标不存在：${engagementArg}`)
      return eng
    }
    return store.activeEngagement()
  }

  /** 删除靶标前统一清理它的内存态和附属对象，避免后台 agent/定时器继续写入已删项目。 */
  const forgetDerived = async (engagementId) => {
    browsers.clear(engagementId)
    board.forget?.(engagementId)
    tasks.forget?.(engagementId)
    trace.forget?.(engagementId)
    runner.forget?.(engagementId)
    meeting.forget?.(engagementId)
    try { await squad.dropEngagement(engagementId) } catch { /* 已释放 */ }
    try { await cockpit.forget?.(engagementId) } catch { /* 已释放 */ }
    try { await brief.forget?.(engagementId) } catch { /* 已释放 */ }
  }

  return async (req, res) => {
    try {
      if (req.method !== 'POST') {
        sendJson(res, 405, { ok: false, error: 'POST only' })
        return
      }
      if (!sameOrigin(req)) {
        sendJson(res, 403, { ok: false, error: 'cross-origin 被拒绝' })
        return
      }
      const body = await readBody(req)
      const op = asText(body.op, 'overview')
      const engagementArg = asText(body.engagement)

      if (op === 'browsers.list') {
        const eng = await pick(engagementArg)
        if (eng !== undefined) await browsers.restore(eng.id)
        sendJson(res, 200, { ok: true, browsers: eng === undefined ? [] : browsers.list(eng.id) })
        return
      }

      if (op === 'overview' || op === 'graph') {
        const listed = await store.list()
        const eng = await pick(engagementArg)
        const config = configStore.get()
        if (eng === undefined) {
          sendJson(res, 200, {
            ok: true,
            root: store.root,
            activeId: null,
            engagements: listed,
            engagement: null,
            chat: null,
            config: { models: config.models, keys: configStore.keyPresence(), ui: config.ui, chat: config.chat, role: config.role, trace: config.trace },
          })
          return
        }
        await browsers.restore(eng.id)
        const transcript = await cockpit.loadTranscript(eng.id)
        const boardAll = await board.list(eng.id, 1000000)
        sendJson(res, 200, {
          ok: true,
          root: store.root,
          activeId: eng.id,
          engagements: listed,
          chat: {
            ...cockpit.stateOf(eng.id),
            /* 老数据里可能存过只有工具调用的空回复，读出来时滤掉，别让空气泡一直挂在界面上 */
            messages: transcript
              .filter((row) => row !== null && row !== undefined
                && ((row.text || '') !== '' || (row.reasoning || '') !== '')),
          },
          /* 全量读出来算真实条数，再按显示上限切片：计数永远是真实值，不会在某个数上卡住 */
          /* agent 条目按上限切片；用户发言永不截断，和 agent 条目按时间合并回显。 */
          board: (() => {
            const limit = boardOptions(configStore).limit
            const userRows = boardAll.filter((row) => board.isUserEntry(row))
            const agentRows = boardAll.filter((row) => board.isUserEntry(row) === false)
            return [...userRows, ...agentRows]
              .sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0))
              .map((row) => ({
                id: row.id, ts: row.ts, kind: row.kind,
                author: row.author, text: row.text, summary: row.summary || boardSummaryOf(row), refs: row.refs, shots: row.shots,
              }))
          })(),
          boardLimit: boardOptions(configStore).limit,
          traceLimit: traceLimitOf(configStore),
          boardTotal: boardAll.length,
          boardAgentCount: boardAll.filter((row) => board.isUserEntry(row) === false).length,
          boardUserCount: boardAll.filter((row) => board.isUserEntry(row)).length,
          squad: { running: squad.activeCount(eng.id), members: squad.list(eng.id) },
          browsers: browsers.list(eng.id),
          tasks: { stats: await tasks.stats(eng.id), items: await tasks.list(eng.id, 120) },
          trace: await trace.list(eng.id, traceLimitOf(configStore)),
          delegation: await (async () => {
            const rows = await trace.list(eng.id, 2000)
            let own = 0
            let delegated = 0
            for (const row of rows) {
              if (row.kind !== 'command') continue
              const role = (row.actor || {}).role || ''
              if (role === 'lead' || role === 'commander' || role === 'user') own += 1
              else delegated += 1
            }
            const total = own + delegated
            return { own, delegated, total, rate: total === 0 ? 0 : Math.round((delegated / total) * 100) }
          })(),
          roles: [...squad.coreRoles(), ...squad.roles()].map((role) => ({
            id: role.id, name: role.name, tier: role.tier, reportsTo: role.reportsTo || null,
            temporary: role.temporary === true, core: role.core === true || CORE_ROLES.has(role.id),
            skills: Array.isArray(role.skills) ? role.skills : [],
          })),
          automation: (() => {
            const conf = automation.config()
            const status = automation.status(eng.id)
            return { enabled: conf.enabled, maxAgents: conf.maxAgents, maxAutomationAgents: conf.maxAutomationAgents, queued: status.queued, runningAutomation: status.runningAutomation, rules: conf.rules.length }
          })(),
          config: { models: config.models, keys: configStore.keyPresence(), ui: config.ui, chat: config.chat, role: config.role, trace: config.trace },
          engagement: {
            id: eng.id,
            name: eng.name,
            scope: eng.scope,
            version: eng.version,
            createdAt: eng.createdAt,
            updatedAt: eng.updatedAt,
            stats: statsOf(eng),
            kinds: (() => {
              const map = new Map()
              for (const node of eng.nodes) {
                const key = node.kind || 'note'
                map.set(key, (map.get(key) || 0) + 1)
              }
              return Array.from(map.entries())
                .map(([kind, count]) => ({ kind, count }))
                .sort((a, b) => b.count - a.count)
            })(),
            nodes: eng.nodes,
            edges: eng.edges,
            vulns: eng.vulns,
            commands: eng.commands.slice(-400).map((c) => ({
              id: c.id, command: c.command, purpose: c.purpose, source: c.source, cwd: c.cwd, startedAt: c.startedAt,
              exitCode: c.exitCode, durationMs: c.durationMs, timedOut: c.timedOut, envKeys: c.envKeys,
              stdoutBytes: c.stdoutBytes, stderrBytes: c.stderrBytes, truncated: c.truncated,
              outputPath: c.outputPath, nodeIds: c.nodeIds || [], stderrTail: c.stderrTail,
            })),
            commandTotal: eng.commands.length,
          },
        })
        return
      }

      if (op === 'command') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const id = asText(body.commandId)
        const record = eng.commands.find((c) => c.id === id)
        if (record === undefined) throw new Error(`命令不存在：${id}`)
        let text = ''
        try {
          const info = await stat(record.outputPath)
          if (info.size > 4 * 1024 * 1024) {
            const content = await readFile(record.outputPath, 'utf8')
            text = `${content.slice(0, 4 * 1024 * 1024)}\n\n… 文件 ${info.size} 字节，仅显示前 4MB …`
          } else {
            text = await readFile(record.outputPath, 'utf8')
          }
        } catch {
          text = `[输出文件读不到：${record.outputPath}]\n\nstdout tail:\n${record.tail || ''}\n\nstderr tail:\n${record.stderrTail || ''}`
        }
        sendJson(res, 200, { ok: true, command: record, text })
        return
      }

      if (op === 'provenance') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const nodeId = asText(body.nodeId)
        const node = eng.nodes.find((n) => n.id === nodeId)
        if (node === undefined) throw new Error(`节点不存在：${nodeId}`)
        const direct = node.commandId ? eng.commands.filter((c) => c.id === node.commandId) : []
        const linked = eng.commands.filter((c) => (c.nodeIds || []).includes(nodeId))
        const edgeEvidence = eng.edges
          .filter((e) => (e.from === nodeId || e.to === nodeId) && asText(e.commandId) !== '')
          .map((e) => ({ id: e.id, type: e.type, from: e.from, to: e.to, commandId: e.commandId }))
        const seen = new Set()
        const commands = []
        for (const command of [...direct, ...linked]) {
          if (seen.has(command.id)) continue
          seen.add(command.id)
          commands.push({
            id: command.id, command: command.command, purpose: command.purpose, source: command.source,
            exitCode: command.exitCode, startedAt: command.startedAt, durationMs: command.durationMs,
            outputPath: command.outputPath, envKeys: command.envKeys,
          })
        }
        const extraIds = edgeEvidence.map((e) => e.commandId).filter((id) => !seen.has(id))
        for (const id of extraIds) {
          if (seen.has(id)) continue
          const command = eng.commands.find((c) => c.id === id)
          if (command === undefined) continue
          seen.add(id)
          commands.push({
            id: command.id, command: command.command, purpose: command.purpose, source: command.source,
            exitCode: command.exitCode, startedAt: command.startedAt, durationMs: command.durationMs,
            outputPath: command.outputPath, envKeys: command.envKeys,
          })
        }
        sendJson(res, 200, { ok: true, node: { id: node.id, value: node.value, kind: node.kind }, commands, edges: edgeEvidence })
        return
      }

      if (op === 'select') {
        const eng = await store.setActive(asText(body.engagement))
        void squad.ensureCore(eng.id).catch(() => {})
        sendJson(res, 200, { ok: true, activeId: eng.id })
        return
      }

      if (op === 'create') {
        const opened = await store.openOrCreate(asText(body.name, '新靶标'), body.scope)
        void squad.ensureCore(opened.engagement.id).catch(() => {})
        sendJson(res, 200, { ok: true, activeId: opened.engagement.id, engagement: { id: opened.engagement.id, name: opened.engagement.name } })
        return
      }

      if (op === 'delete') {
        const id = asText(body.engagement, asText(body.id, engagementArg))
        if (id === '') throw new Error('缺少项目 id')
        const existed = await store.load(id)
        if (existed === undefined) { sendJson(res, 200, { ok: false, error: `项目不存在：${id}` }); return }
        await forgetDerived(id)
        await store.remove(id)
        const rest = await store.list()
        sendJson(res, 200, {
          ok: true,
          removed: { id, name: existed.name },
          activeId: (await store.activeEngagement() || {}).id || null,
          engagements: rest,
        })
        return
      }

      if (op === 'deleteAll') {
        if (body.confirm !== true) { sendJson(res, 200, { ok: false, error: '需要 confirm:true 才执行清空' }); return }
        const before = await store.list()
        for (const row of before) {
          try { await forgetDerived(row.id) } catch { /* 单个清理失败不影响继续 */ }
        }
        const result = await store.removeAll()
        sendJson(res, 200, { ok: true, ...result, engagements: [] })
        return
      }

      if (op === 'setVulnStatus') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const status = lower(asText(body.status))
        if (!VULN_STATUSES.includes(status)) throw new Error(`状态非法：${status}`)
        const updated = await store.mutate(eng.id, (draft) => {
          const vuln = draft.vulns.find((v) => v.id === body.vulnId)
          if (vuln === undefined) throw new Error(`漏洞不存在：${body.vulnId}`)
          vuln.status = status
          vuln.updatedAt = nowIso()
          return vuln
        })
        sendJson(res, 200, { ok: true, vuln: { id: updated.id, status: updated.status } })
        return
      }

      if (op === 'archiveNode') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const mode = asText(body.mode, 'archive')
        const result = await store.mutate(eng.id, (draft) => {
          const node = draft.nodes.find((n) => n.id === asText(body.nodeId))
          if (node === undefined) throw new Error(`节点不存在：${body.nodeId}`)
          if (mode === 'restore') { node.archived = false; return { node, archived: false } }
          node.archived = true
          node.archivedAt = nowIso()
          if (asText(body.reason) !== '') node.archiveReason = asText(body.reason)
          return { node, archived: true }
        })
        await board.post(eng.id, {
          author: { role: 'system', name: '操作台' },
          kind: 'note',
          text: `${mode === 'restore' ? '恢复' : '归档'}节点 ${result.node.kind}:${result.node.value}`
            + (asText(body.reason) !== '' ? `；原因：${body.reason}` : ''),
          refs: { nodeIds: [result.node.id], nodeValue: result.node.value },
        })
        sendJson(res, 200, { ok: true, archived: result.archived, nodeId: result.node.id })
        return
      }

      if (op === 'deleteNode') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const removed = await store.mutate(eng.id, (draft) => {
          const id = asText(body.nodeId)
          const before = draft.nodes.length
          draft.nodes = draft.nodes.filter((n) => n.id !== id)
          draft.edges = draft.edges.filter((e) => e.from !== id && e.to !== id)
          draft.vulns = draft.vulns.filter((v) => v.nodeId !== id)
          draft.commands = draft.commands.map((c) => ({ ...c, nodeIds: (c.nodeIds || []).filter((n) => n !== id) }))
          return before - draft.nodes.length
        })
        sendJson(res, 200, { ok: true, removed })
        return
      }

      if (op === 'deleteVuln') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const removed = await store.mutate(eng.id, (draft) => {
          const before = draft.vulns.length
          draft.vulns = draft.vulns.filter((v) => v.id !== body.vulnId)
          return before - draft.vulns.length
        })
        if (removed === 0) { sendJson(res, 200, { ok: false, error: `漏洞不存在：${asText(body.vulnId)}` }); return }
        sendJson(res, 200, { ok: true, removed })
        return
      }

      if (op === 'saveLayout') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const positions = Array.isArray(body.positions) ? body.positions : []
        await store.mutate(eng.id, (draft) => {
          const index = new Map(draft.nodes.map((n) => [n.id, n]))
          for (const row of positions) {
            const node = index.get(row.id)
            if (node === undefined) continue
            if (Number.isFinite(row.x) && Number.isFinite(row.y)) {
              node.x = Math.round(row.x)
              node.y = Math.round(row.y)
            }
          }
        })
        sendJson(res, 200, { ok: true, saved: positions.length })
        return
      }

      if (op === 'rename') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const nameText = asText(body.name)
        if (nameText === '') throw new Error('名称不能为空')
        await store.mutate(eng.id, (draft) => { draft.name = nameText })
        sendJson(res, 200, { ok: true })
        return
      }

      if (op === 'deleteEngagement') {
        const id = asText(body.engagement)
        if (id === '') throw new Error('缺少 engagement')
        const eng = await store.load(id)
        if (eng === undefined) throw new Error(`靶标不存在：${id}`)
        await forgetDerived(id)
        await store.remove(id)
        sendJson(res, 200, { ok: true, removed: id })
        return
      }

      /* ── 配置中心 ── */

      if (op === 'config.get') {
        const config = configStore.redacted()
        config.models = { ...(config.models || {}), custom: await customModels.list() }
        sendJson(res, 200, {
          ok: true,
          config,
          keys: configStore.keyPresence(),
          mcp: mcp.last,
        })
        return
      }

      if (op === 'config.set') {
        const patch = body.patch && typeof body.patch === 'object' ? { ...body.patch } : {}
        /* 看板阈值统一夹取：合并条数不超过上限的一半，避免一次合并清空看板 */
        if (patch.board !== undefined && patch.board !== null && typeof patch.board === 'object') {
          const currentBoard = configStore.get().board || {}
          const limit = [50, 100, 200].includes(Number(patch.board.limit)) ? Number(patch.board.limit) : (Number(currentBoard.limit) || 100)
          const wanted = [25, 50, 100].includes(Number(patch.board.mergeCount)) ? Number(patch.board.mergeCount) : (Number(currentBoard.mergeCount) || 50)
          const mergeMode = patch.board.mergeMode === 'ai'
            ? 'ai'
            : (patch.board.mergeMode === 'deterministic' ? 'deterministic' : (currentBoard.mergeMode === 'ai' ? 'ai' : 'deterministic'))
          const mergeModel = ['deep', 'fast'].includes(asText(patch.board.mergeModel))
            ? asText(patch.board.mergeModel)
            : (currentBoard.mergeModel === 'deep' ? 'deep' : 'fast')
          patch.board = { limit, mergeCount: Math.min(wanted, Math.max(10, Math.floor(limit / 2))), mergeMode, mergeModel }
        }
        if (patch.models !== undefined && patch.models !== null && typeof patch.models === 'object' && Array.isArray(patch.models.custom)) {
          const prepared = await customModels.prepare(patch.models.custom)
          await customModels.apply(prepared.next, prepared.removed, prepared.keyUpdates)
          patch.models = { ...patch.models, custom: prepared.next }
        }
        const next = await configStore.patch(patch)
        const mcpState = mcp.sync(next)
        hub.broadcast({ type: 'config', keys: configStore.keyPresence(), models: next.models })
        const config = configStore.redacted()
        config.models = { ...(config.models || {}), custom: await customModels.list() }
        sendJson(res, 200, { ok: true, config, keys: configStore.keyPresence(), mcp: mcpState })
        return
      }

      if (op === 'providers') {
        const llm = ctx.get('llm')
        if (llm === undefined || llm === null) {
          sendJson(res, 200, { ok: true, providers: [], models: {} })
          return
        }
        const providers = await llm.listProviders()
        const models = {}
        for (const provider of providers) {
          try {
            const list = await llm.listModels(provider.id)
            models[provider.id] = list.map((m) => ({ id: m.id, name: m.name, modalities: m.inputModalities }))
          } catch {
            models[provider.id] = []
          }
        }
        for (const row of customModels.current()) {
          const provider = asText(row.provider)
          if (provider === '') continue
          if (!providers.some((item) => item.id === provider)) {
            providers.push({ id: provider, name: asText(row.name, provider), custom: true })
          }
          models[provider] = [{ id: asText(row.model), name: asText(row.name, asText(row.model)), modalities: ['text'] }]
        }
        let configurable = []
        try { configurable = await llm.listConfigurableProviders() } catch { configurable = [] }
        sendJson(res, 200, { ok: true, providers, models, configurable })
        return
      }

      if (op === 'skills') {
        const skills = ctx.get('skills')
        if (skills === undefined || skills === null) {
          sendJson(res, 200, { ok: true, items: [], error: 'skills 服务不可用' })
          return
        }
        let items = []
        try { items = await skills.list() } catch (error) { items = [] }
        sendJson(res, 200, {
          ok: true,
          items: items.map((item) => ({
            name: item.name,
            description: shortText(item.description || '', 240),
            modelInvocable: item.modelInvocable !== false,
            userInvocable: item.userInvocable !== false,
            source: item.source || item.provider,
          })),
        })
        return
      }

      if (op === 'squad.mcp') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: false, error: '还没有靶标' }); return }
        let member = squad.members.get(asText(body.member))
        let key = asText(body.member)
        if (member === undefined) {
          try { member = squad.resolveMemberRef(key, eng.id) } catch { member = undefined }
        }
        if (member === undefined) { sendJson(res, 200, { ok: false, error: `成员不存在：${key}` }); return }
        key = member.key
        squad.uninstallMemberMcp(key)
        member.mcp = asMcpList(body.mcp)
        const state = squad.installMemberMcp(member)
        member.mcpError = state.error === undefined ? '' : state.error
        squad.refreshToolRestrictions()
        try { squad.promptCache.set(key, await squad.memberPrompt(eng.id, squad.roleOf(member.role), member)) } catch { /* 提示词重建失败 */ }
        const view = squad.view(member)
        hub.broadcast({ type: 'squad.status', engagementId: eng.id, member: view })
        sendJson(res, 200, { ok: true, member: view, installed: state.installed || 0, skipped: state.skipped || 0, error: state.error || '' })
        return
      }
      if (op === 'mcp.list') {
        const manager = ctx.get('mcpManager')
        let servers = []
        if (manager !== undefined && manager !== null) {
          try {
            const listed = manager.list()
            servers = Array.isArray(listed) ? listed.map((row) => redactMcpSecrets(row)) : listed
          } catch { servers = [] }
        }
        sendJson(res, 200, { ok: true, available: manager !== undefined && manager !== null, servers, bindings: mcp.last })
        return
      }

      if (op === 'mcp.sync') {
        const state = mcp.sync(configStore.get())
        sendJson(res, 200, { ok: true, ...state })
        return
      }

      /* ── 驾驶舱对话 ── */

      if (op === 'chat.state') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, chat: null }); return }
        await browsers.restore(eng.id)
        const transcript = await cockpit.loadTranscript(eng.id)
        sendJson(res, 200, { ok: true, chat: { ...cockpit.stateOf(eng.id), messages: transcript } })
        return
      }

      /* 汇报席：fork 出来的独立只读对话，不写 cockpit transcript */
      if (op === 'prompt.cockpit') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        sendJson(res, 200, { ok: true, prompt: await cockpit.cockpitPrompt(eng.id) })
        return
      }

      if (op === 'squad.prompt') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        const ref = asText(body.member)
        const members = squad.list(eng.id)
        let member
        try {
          member = ref === '' ? members[0] : squad.resolveMemberRef(ref)
        } catch (error) {
          sendJson(res, 200, { ok: false, error: error.message })
          return
        }
        if (member === undefined) { sendJson(res, 200, { ok: false, error: '没有这个队员' }); return }
        /* 这里返回的就是 agent 每轮真实拿到的系统提示（同步实时渲染版） */
        const text = squad.renderPromptSync(member.key)
        sendJson(res, 200, { ok: true, member: member.key, name: member.name, prompt: text })
        return
      }

      if (op === 'brief.chat') {
        sendJson(res, 200, await brief.send(engagementArg, body.question))
        return
      }

      if (op === 'brief.clear') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        sendJson(res, 200, await brief.clear(eng.id))
        return
      }

      if (op === 'brief.status') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, ready: false }); return }
        const state = brief.sessions.get(eng.id)
        sendJson(res, 200, {
          ok: true,
          ready: state !== undefined,
          sessionId: state === undefined ? null : state.sessionId,
          busy: state === undefined ? false : state.busy,
        })
        return
      }

      if (op === 'brief.history') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, messages: [] }); return }
        sendJson(res, 200, { ok: true, messages: await brief.readHistory(eng.id) })
        return
      }

      if (op === 'chat.send') {
        const result = await cockpit.send({
          engagement: engagementArg,
          text: body.text,
          tier: body.tier,
          images: body.images,
          attachments: body.attachments,
          interrupt: body.interrupt === true,
        })
        sendJson(res, 200, { ok: true, ...result })
        return
      }

      if (op === 'chat.stop') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        sendJson(res, 200, await cockpit.stop(eng.id))
        return
      }

      if (op === 'chat.clear') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        sendJson(res, 200, await cockpit.clear(eng.id))
        return
      }

      /* ── 看板 ── */

      if (op === 'board.list') {
        const eng = await pick(engagementArg)
        const boardCfg = boardOptions(configStore)
        if (eng === undefined) { sendJson(res, 200, { ok: true, entries: [], limit: boardCfg.limit, mergeCount: boardCfg.mergeCount }); return }
        const rows = await board.list(eng.id, Number.isFinite(body.limit) ? body.limit : 120)
        sendJson(res, 200, { ok: true, entries: rows, limit: boardCfg.limit, mergeCount: boardCfg.mergeCount })
        return
      }

      if (op === 'board.post') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const entry = await board.post(eng.id, {
          author: { role: 'user', name: asText(body.authorName, '你') },
          kind: asText(body.kind, 'note'),
          text: asText(body.text),
          summary: asText(body.summary),
          refs: body.refs && typeof body.refs === 'object' ? body.refs : {},
          shots: asList(body.shots),
        })
        /* 用户在看板发言 = 指挥席下指令：立刻重建所有 agent 的系统提示，下一轮就生效 */
        if (board.isUserEntry(entry) === true) {
          void (async () => {
            try { await cockpit.refreshPrompt(eng.id) } catch { /* 忽略 */ }
            try { await squad.refreshPrompts(eng.id) } catch { /* 忽略 */ }
          })()
        }
        void trace.push(eng.id, {
          kind: entry.kind === 'hypothesis' || entry.kind === 'task' ? 'plan' : 'chat',
          actor: entry.author,
          title: `看板 +1（${entry.kind}）｜${shortText(entry.text, 90)}`,
          detail: entry.text,
          refs: entry.refs || {},
          meta: { op: 'board', boardKind: entry.kind, input: entry.text },
        })
        sendJson(res, 200, { ok: true, entry })
        return
      }

      if (op === 'board.update' || op === 'board.edit') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const entry = await board.update(eng.id, asText(body.id), body)
        sendJson(res, 200, { ok: true, entry })
        return
      }

      if (op === 'board.remove' || op === 'board.delete') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        sendJson(res, 200, await board.remove(eng.id, asText(body.id)))
        return
      }
      if (op === 'board.summarize') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        sendJson(res, 200, { ok: true, entry: await board.summarizeEntry(eng.id, asText(body.id)) })
        return
      }

      if (op === 'board.compact') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const merged = await board.compact(eng.id, Number(body.count))
        if (merged === null) {
          sendJson(res, 200, { ok: true, merged: null, note: '没有可压缩的 agent 看板条目' })
          return
        }
        await board.persist(eng.id)
        sendJson(res, 200, { ok: true, merged })
        return
      }


      /* ── 编队 ── */

      if (op === 'squad.list') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, members: [], roles: squad.roles() }); return }
        sendJson(res, 200, {
          ok: true,
          running: squad.activeCount(eng.id),
          members: squad.list(eng.id),
          roles: squad.roles().map((role) => ({ id: role.id, name: role.name, tier: role.tier })),
          core: squad.coreRoles().map((role) => ({ id: role.id, name: role.name, tier: role.tier })),
        })
        return
      }

      if (op === 'squad.spawn') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const member = await squad.spawn({
          engagementId: eng.id,
          roleId: asText(body.role, 'hunter'),
          tier: asText(body.tier),
          task: asText(body.task),
          origin: 'manual',
          name: asText(body.name),
          promptExtra: asText(body.prompt),
          skills: asList(body.skills),
          mcp: asMcpList(body.mcp),
        })
        sendJson(res, 200, { ok: true, member })
        return
      }

      if (op === 'squad.task') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const member = await squad.task(asText(body.member), asText(body.task), eng.id)
        sendJson(res, 200, { ok: true, member })
        return
      }

      if (op === 'squad.stop') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        sendJson(res, 200, await squad.stop(asText(body.member), eng.id))
        return
      }

      if (op === 'squad.remove') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        /* 释放前先做离职交接（body.handover === false 可跳过，用于强制清理） */
        sendJson(res, 200, await squad.remove(asText(body.member), {
          reason: asText(body.reason, '回收'),
          handover: body.handover !== false,
          engagementId: eng.id,
        }))
        return
      }

      /* ── 自动化规则 ── */

      if (op === 'automation.get') {
        const eng = await pick(engagementArg)
        sendJson(res, 200, { ok: true, config: automation.config(), roles: squad.roles(), status: automation.status(eng === undefined ? undefined : eng.id) })
        return
      }

      if (op === 'automation.set') {
        const patch = body.patch && typeof body.patch === 'object' ? body.patch : {}
        const next = await configStore.patch({ automation: patch })
        const eng = await pick(engagementArg)
        sendJson(res, 200, { ok: true, config: automation.config(), status: automation.status(eng === undefined ? undefined : eng.id) })
        return
      }

      /* ── 附件上传 / 导出 / 重跑 ── */

      if (op === 'chat.upload') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const raw = typeof body.base64 === 'string' ? body.base64 : ''
        if (raw === '') throw new Error('缺少 base64 内容')
        const data = Buffer.from(raw, 'base64')
        if (data.length > 24 * 1024 * 1024) throw new Error('单文件上限 24MB')
        const safeName = asText(body.name, 'upload.bin').replace(/[^\w.\-\u4e00-\u9fa5]+/g, '_').slice(0, 120)
        const dir = await ensureDir(join(cfg.root, 'uploads', eng.id))
        const path = join(dir, `${Date.now().toString(36)}-${safeName}`)
        await writeFile(path, data, { mode: 0o600 })
        sendJson(res, 200, {
          ok: true,
          file: { name: safeName, bytes: data.length, path, url: `/recon/asset?p=${encodeURIComponent(path)}` },
        })
        return
      }

      if (op === 'command.rerun') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const record = eng.commands.find((c) => c.id === asText(body.commandId))
        if (record === undefined) throw new Error(`命令不存在：${body.commandId}`)
        const workRoot = await ensureDir(join(store.workDir, eng.id))
        const keyEnv = configStore.keyEnv()
        const cmdId = `r${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
        const outcome = await runShell(record.command, {
          cwd: asText(record.cwd) || workRoot,
          timeoutMs: cfg.defaultTimeoutMs,
          signal: undefined,
          env: { ...process.env, ...keyEnv },
        })
        const outputPath = join(store.cmdDir, eng.id, `${cmdId}.log`)
        await ensureDir(join(store.cmdDir, eng.id))
        await writeFile(outputPath, [
          `# command : ${record.command}`,
          `# rerun-of: ${record.id}`,
          `# cwd     : ${asText(record.cwd) || workRoot}`,
          `# exit    : ${outcome.exitCode}`,
          '',
          '## stdout',
          outcome.stdout,
          '',
          '## stderr',
          outcome.stderr,
          '',
        ].join('\n'), 'utf8')
        const created = await store.mutate(eng.id, (draft) => {
          const row = {
            id: cmdId,
            command: record.command,
            purpose: `重跑 ${record.id}`,
            cwd: asText(record.cwd) || workRoot,
            startedAt: nowIso(),
            exitCode: outcome.exitCode,
            durationMs: outcome.durationMs,
            timedOut: outcome.timedOut,
            aborted: false,
            stdoutBytes: outcome.outBytes,
            stderrBytes: outcome.errBytes,
            truncated: outcome.truncated,
            outputPath,
            source: 'rerun',
            envKeys: Object.keys(keyEnv),
            sessionId: undefined,
            nodeIds: Array.isArray(record.nodeIds) ? [...record.nodeIds] : [],
            tail: outcome.stdout.slice(-4000),
            stderrTail: outcome.stderr.slice(-2000),
          }
          draft.commands.push(row)
          return row
        })
        sendJson(res, 200, { ok: true, commandId: created.id, exitCode: outcome.exitCode })
        return
      }

      if (op === 'chat.export') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const rows = await cockpit.loadTranscript(eng.id)
        const lines = [`# ${eng.name} · 驾驶舱对话`, '']
        for (const row of rows) {
          const who = row.role === 'user' ? '你' : '驾驶舱'
          lines.push(`## ${who} · ${new Date(row.ts || Date.now()).toLocaleString()}`)
          lines.push(row.text || '')
          if (row.attachments && row.attachments.length > 0) {
            lines.push('', `附件：${row.attachments.map((f) => `${f.name} (${f.bytes}B) ${f.path}`).join(' ; ')}`)
          }
          if (row.reasoning) lines.push('', '<details><summary>思维</summary>', '', row.reasoning, '', '</details>')
          lines.push('')
        }
        sendJson(res, 200, { ok: true, markdown: lines.join('\n') })
        return
      }

      if (op === 'board.export') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const rows = await board.list(eng.id, 5000)
        const lines = [`# ${eng.name} · 团队看板`, '']
        for (const row of rows) {
          lines.push(`- **${row.author && row.author.name ? row.author.name : '?'}** [${row.kind}] ${new Date(row.ts).toLocaleString()}`)
          lines.push(`  ${String(row.text || '').replace(/\n/g, '\n  ')}`)
          const refs = row.refs || {}
          const refText = [
            ...(refs.nodeIds || []).map((id) => `node:${id}`),
            ...(refs.vulnIds || []).map((id) => `vuln:${id}`),
            ...(refs.commandIds || []).map((id) => `cmd:${id}`),
          ]
          if (refText.length > 0) lines.push(`  引用：${refText.join(', ')}`)
          if (row.shots && row.shots.length > 0) lines.push(`  截图：${row.shots.join(', ')}`)
        }
        sendJson(res, 200, { ok: true, markdown: lines.join('\n') })
        return
      }

      if (op === 'trace.list') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, events: [] }); return }
        const limit = Number.isFinite(Number(body.limit)) ? Math.max(20, Math.min(5000, Number(body.limit))) : traceLimitOf(configStore)
        sendJson(res, 200, { ok: true, events: await trace.list(eng.id, limit) })
        return
      }

      if (op === 'task.list') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, stats: {}, items: [] }); return }
        sendJson(res, 200, { ok: true, stats: await tasks.stats(eng.id), items: await tasks.list(eng.id, 200) })
        return
      }

      if (op === 'task.create') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const mission = await tasks.missionOf(eng.id)
        if (mission === null || mission.status !== 'running') {
          sendJson(res, 200, {
            ok: false,
            error: '还没有进行中的作战目标，不能拆任务',
            hint: '先让参谋出整体方案并写看板，再由总指挥登记目标。',
          })
          return
        }
        const task = await tasks.create(eng.id, {
          title: asText(body.title, 'UI 任务'),
          goal: asText(body.goal),
          acceptance: asText(body.acceptance),
          role: canonicalRoleId(squad, body.role),
          assignee: (() => {
            const ref = asText(body.assignee)
            if (ref === '') return ''
            const hit = squad.resolveMemberRef(ref, eng.id)
            if (hit === undefined) throw new Error(`指定成员不存在：${ref}`)
            return hit.name
          })(),
          createdBy: { role: 'user', name: '你' },
        })
        await board.post(eng.id, {
          author: { role: 'system', name: '操作台' },
          kind: 'task',
          text: `[${task.id}] ${task.title}\n目标：${task.goal || '-'}\n验收：${task.acceptance || '-'}\n负责：${task.role}`,
        })
        sendJson(res, 200, { ok: true, task })
        return
      }

      if (op === 'task.assign') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const ref = asText(body.member)
        let who = ''
        if (ref !== '') {
          const hit = squad.resolveMemberRef(ref)
          who = hit === undefined ? '' : hit.name
        }
        const task = await tasks.update(eng.id, asText(body.id), { assignee: who, status: 'doing' }, { role: 'user', name: '你' })
        sendJson(res, 200, { ok: true, task: { id: task.id, assignee: task.assignee, status: task.status } })
        return
      }

      if (op === 'runner.status') {
        const eng = await pick(engagementArg)
        sendJson(res, 200, { ok: true, ...(await runner.status(eng)) })
        return
      }

      if (op === 'runner.pause') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        const reason = asText(body.reason) || 'manual'
        sendJson(res, 200, await runner.pause(eng, reason))
        return
      }

      if (op === 'runner.resume') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        sendJson(res, 200, await runner.resume(eng, asText(body.note)))
        return
      }

      if (op === 'meeting.status') {
        const eng = await pick(engagementArg)
        if (eng === undefined) sendJson(res, 200, { ok: true, meeting: null, verdict: { stalled: false, reasons: [] } })
        else {
          await meeting.load(eng.id)
          sendJson(res, 200, { ok: true, meeting: meeting.status(eng), verdict: await meeting.verdict(eng) })
        }
        return
      }

      if (op === 'meeting.convene') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有项目')
        const verdict = await meeting.verdict(eng)
        const result = await meeting.convene(eng, {
          reason: asText(body.reason) || (verdict.stalled ? verdict.reasons.join('；') : '手动召开'),
          manual: true,
        })
        sendJson(res, 200, { ok: true, ...result })
        return
      }

      if (op === 'mission.get') {
        const eng = await pick(engagementArg)
        if (eng === undefined) { sendJson(res, 200, { ok: true, mission: null, progress: null }); return }
        const rows = await tasks.list(eng.id, 400)
        sendJson(res, 200, {
          ok: true,
          mission: await tasks.missionOf(eng.id),
          progress: {
            total: rows.length,
            passed: rows.filter((r) => r.status === 'passed').length,
            open: rows.filter((r) => r.status !== 'passed' && r.status !== 'failed').length,
            failed: rows.filter((r) => r.status === 'failed').length,
          },
        })
        return
      }

      if (op === 'mission.set') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const prev = await tasks.missionOf(eng.id)
        const plan = await latestStaffPlan(board, eng.id, prev === null ? 0 : prev.updatedAt)
        if (plan === undefined) {
          sendJson(res, 200, {
            ok: false,
            error: '还没有本轮参谋方案，不能登记作战目标',
            hint: '先让参谋把整体方案写进看板（kind=hypothesis），总指挥读方案后再拆任务。',
          })
          return
        }
        const mission = await tasks.setMission(eng.id, {
          goal: asText(body.goal),
          done: asText(body.done),
          status: 'running',
          rounds: (prev === null ? 0 : Number(prev.rounds) || 0) + 1,
        })
        sendJson(res, 200, { ok: true, mission })
        return
      }

      if (op === 'mission.close') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const rows = await tasks.list(eng.id, 400)
        const pending = rows.filter((r) => r.status !== 'passed')
        const unverified = rows.filter((r) => r.status === 'passed'
          && (!r.verifiedBy || r.verifiedBy.role !== 'qa'))
        if ((pending.length > 0 || unverified.length > 0) && body.force !== true) {
          sendJson(res, 200, {
            ok: false,
            error: pending.length > 0 ? `还有 ${pending.length} 条任务未通过验收` : `还有 ${unverified.length} 条任务没有 QA 验收记录`,
            pending: (pending.length > 0 ? pending : unverified).slice(-8).map((r) => `${r.id} ${r.title}`),
            hint: '先让 QA 对每条任务执行 accept/reject；全部通过后再由总指挥 close。',
          })
          return
        }
        const prev = await tasks.missionOf(eng.id)
        const mission = await tasks.setMission(eng.id, {
          goal: prev === null ? '' : asText(prev.goal),
          done: prev === null ? '' : asText(prev.done),
          status: 'done',
        })
        cockpit.pendingNudges?.delete?.(eng.id)
        const stopped = await squad.stopAll(eng.id)
        await board.post(eng.id, {
          author: { role: 'commander', name: '总指挥' },
          kind: 'conclusion',
          text: `【任务完成】${mission.goal !== '' ? mission.goal : '本轮作战目标'} 已由 QA 全部验收通过（${rows.filter((r) => r.status === 'passed').length} 条任务），总指挥宣布结束，收队。`,
        })
        const reclaimed = await squad.reclaimIdle(eng.id)
        sendJson(res, 200, { ok: true, mission, stopped, reclaimed })
        return
      }

      if (op === 'task.accept' || op === 'task.reject') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const id = asText(body.id)
        const note = asText(body.note)
        const task = await tasks.update(eng.id, id, {
          status: op === 'task.accept' ? 'passed' : 'failed', note,
          verifiedBy: { role: 'qa', name: '验收' }, verifiedAt: nowMs(),
        }, { role: 'qa', name: '验收' })
        if (op === 'task.reject') {
          const followUp = await tasks.rework(eng.id, task, note || '未达到验收标准', { role: 'qa', name: '验收' })
          await board.post(eng.id, {
            author: { role: 'qa', name: '验收' },
            kind: 'task',
            text: `任务 ${id} 验收驳回：${note || '未达到验收标准'}（返工任务 ${followUp.id} @总指挥）`,
          })
          let staffCall = null
          const staffMember = squad.list(eng.id).find((m) => m.role === 'staff' && m.status !== 'running')
          const ask = `验收驳回 ${id}（${note || '未达到验收标准'}）。请给出 3 条改进方案（怎么做 / 派给谁 / 验收标准），写进看板 kind=hypothesis。`
          if (staffMember !== undefined) {
            await squad.task(staffMember.name, ask, eng.id)
            staffCall = { member: staffMember.key, name: staffMember.name, mode: 'task' }
          } else {
            const invited = await squad.spawn({
              engagementId: eng.id, roleId: 'staff', name: '参谋（返工）',
              promptExtra: '你只出方案不执行；针对验收缺口给可执行、可验收的改进方案。', task: ask, origin: 'rework',
              allowCore: true,
            })
            staffCall = { member: invited.key, name: invited.name, mode: 'spawn' }
          }
          try {
            const prevMission = await tasks.missionOf(eng.id)
            if (prevMission !== null) {
              await tasks.setMission(eng.id, { goal: prevMission.goal, done: prevMission.done, status: 'running', rounds: (Number(prevMission.rounds) || 0) + 1 })
            }
          } catch { /* 忽略 */ }
          const nudged = await cockpit.nudge(eng.id, `任务 ${id} 被验收驳回，已请参谋出方案`)
          sendJson(res, 200, { ok: true, followUp: followUp.id, staff: staffCall, nudged })
          return
        }
        await board.post(eng.id, {
          author: { role: 'qa', name: '验收' },
          kind: 'conclusion',
          text: `任务 ${id} 验收通过${note ? `：${note}` : ''}`,
        })
        let settle = null
        const rows = await tasks.list(eng.id, 400)
        const pending = rows.filter((r) => r.status !== 'passed' && r.status !== 'failed')
        const failed = rows.filter((r) => r.status === 'failed')
        const unverified = rows.filter((r) => r.status === 'passed'
          && (!r.verifiedBy || r.verifiedBy.role !== 'qa'))
        if (pending.length === 0 && failed.length === 0) {
          const mission = await tasks.missionOf(eng.id)
          if (mission === null || mission.status !== 'done') {
            await board.post(eng.id, {
              author: { role: 'qa', name: '验收' },
              kind: 'conclusion',
              text: unverified.length === 0
                ? `【QA 终验报告】${eng.name} 共 ${rows.length} 条任务全部通过 QA 核查，交总指挥做最终收尾决定。`
                : `【QA 终验报告】仍有 ${unverified.length} 条已通过任务缺少 QA 验收记录，暂不能收尾。`,
            })
            settle = unverified.length === 0
              ? await cockpit.nudge(eng.id, 'QA 已对全部任务完成最终验收，请立即复核并宣布作战结束', { force: true, final: true, always: true })
              : await cockpit.nudge(eng.id, `仍有 ${unverified.length} 条已通过任务缺少 QA 验收记录，请安排 QA 重新核查`, { force: true, always: true })
          }
        }
        sendJson(res, 200, { ok: true, settle })
        return
      }

      if (op === 'squad.chat') {
        const member = await squad.chat(asText(body.member), asText(body.text), {
          role: asText(body.role),
          engagement: (await pick(engagementArg) || {}).id,
          tier: asText(body.tier),
          name: asText(body.name),
        })
        sendJson(res, 200, { ok: true, member })
        return
      }

      if (op === 'squad.transcript') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const key = asText(body.member)
        const member = squad.members.get(key)
        if (member === undefined) throw new Error(`成员不存在：${key}`)
        const rows = await squad.transcriptOf(member)
        sendJson(res, 200, { ok: true, messages: rows, member: squad.view(member) })
        return
      }

      if (op === 'roles.get') {
        const coreView = (role) => ({
          id: role.id, name: role.name, tier: role.tier, reportsTo: role.reportsTo || null,
          prompt: role.prompt || '', skills: Array.isArray(role.skills) ? role.skills : [],
          mcp: asMcpList(role.mcp), core: true,
        })
        sendJson(res, 200, {
          ok: true,
          roles: squad.roles().map((role) => ({
            id: role.id, name: role.name, tier: role.tier, reportsTo: role.reportsTo || null,
            prompt: role.prompt || '', skills: Array.isArray(role.skills) ? role.skills : [],
            mcp: asMcpList(role.mcp),
            temporary: role.temporary === true,
          })),
          core: squad.coreRoles().map(coreView),
        })
        return
      }

      if (op === 'roles.set') {
        const rows = Array.isArray(body.roles) ? body.roles : null
        if (rows === null) throw new Error('roles 需要数组')
        const cleaned = rows
          .filter((row) => row !== null && typeof row === 'object' && asText(row.id) !== '' && !CORE_ROLES.has(asText(row.id)))
          .map((row) => ({
            id: asText(row.id),
            name: asText(row.name, asText(row.id)),
            tier: MODEL_CHOICES.includes(asText(row.tier)) ? asText(row.tier) : 'dsh',
            reportsTo: asText(row.reportsTo) === '' ? null : asText(row.reportsTo),
            prompt: asText(row.prompt),
            skills: asList(row.skills),
            /* 角色级专属 MCP 也要保留：控制台里填了却在保存时丢掉，等于这个功能一直没生效 */
            mcp: asMcpList(row.mcp),
            temporary: row.temporary === true,
          }))
        if (cleaned.length === 0) throw new Error('至少保留一个队员角色（总指挥/参谋在「常设席位」里配置）')
        const roleIds = new Set()
        for (const role of cleaned) {
          if (roleIds.has(role.id)) throw new Error(`角色 id 重复：${role.id}`)
          roleIds.add(role.id)
        }
        const patch = { roles: { squad: cleaned } }
        if (Array.isArray(body.core)) {
          const core = {}
          for (const id of CORE_ROLE_IDS) {
            const row = body.core.find((item) => item !== null && typeof item === 'object' && asText(item.id) === id)
            if (row === undefined) continue
            core[id] = {
              id,
              name: asText(row.name, id === 'commander' ? '总指挥' : '参谋'),
              tier: MODEL_CHOICES.includes(asText(row.tier)) ? asText(row.tier) : 'dsh',
              reportsTo: id === 'commander' ? null : 'commander',
              prompt: asText(row.prompt),
              skills: asList(row.skills),
              mcp: asMcpList(row.mcp),
              core: true,
            }
          }
          if (Object.keys(core).length > 0) patch.core = core
        }
        await configStore.patch(patch)
        const coreView = squad.coreRoles().map((role) => ({
          id: role.id, name: role.name, tier: role.tier, reportsTo: role.reportsTo || null,
          prompt: role.prompt || '', skills: Array.isArray(role.skills) ? role.skills : [],
          mcp: asMcpList(role.mcp), core: true,
        }))
        sendJson(res, 200, { ok: true, roles: cleaned, core: coreView })
        return
      }

      if (op === 'squad.stopAll') {
        const eng = await pick(engagementArg)
        const stopped = await squad.stopAll(eng ? eng.id : undefined)
        sendJson(res, 200, { ok: true, stopped })
        return
      }

      if (op === 'squad.prune') {
        const eng = await pick(engagementArg)
        if (eng === undefined) throw new Error('还没有靶标')
        const removed = await squad.pruneIdle(Number.isFinite(body.ttlMs) ? body.ttlMs : 900000, eng.id)
        sendJson(res, 200, { ok: true, removed })
        return
      }

      sendJson(res, 400, { ok: false, error: `未知 op：${op}` })
    } catch (error) {
      sendJson(res, 200, { ok: false, error: error && error.message ? error.message : String(error) })
    }
  }
}

/* ────────────────────────── 协作工具（看板 / 编队 / 浏览器 / 卸载节点） ────────────────────────── */

function registerCollabTools(ctx, deps) {
  const { store, cfg, configStore, hub, board, squad, browser, automation, tasks, cockpit, bindings, browsers, meeting, runner, audit, trace } = deps

  const resolveEngagement = async (exec, explicit) => {
    if (asText(explicit) !== '') {
      const eng = await store.load(explicit)
      if (eng !== undefined) return eng
      const listed = await store.list()
      const hit = listed.find((row) => lower(row.name) === lower(explicit))
      if (hit !== undefined) return store.load(hit.id)
      throw new Error(`靶标不存在：${explicit}`)
    }
    const info = sessionInfoOf(exec)
    for (const key of [info.id, info.parent]) {
      if (typeof key === 'string' && bindings.has(key)) {
        const eng = await store.load(bindings.get(key))
        if (eng !== undefined) return eng
      }
    }
    const active = await store.activeEngagement()
    if (active === undefined) throw new Error('还没有靶标：先 recon_start')
    return active
  }

  /** 当前调用者的身份（用于看板署名与编队权限）。 */
  const callerOf = (exec) => {
    const info = sessionInfoOf(exec)
    const member = squad.memberBySessionId(info.id)
    if (member !== undefined) return { kind: 'member', role: member.role, name: member.name, key: member.key }
    return { kind: 'leader', role: 'lead', name: '指挥席', key: null }
  }

  const json = (value) => JSON.stringify(value, null, 2)
  const fail = (error) => {
    const message = error && error.message ? error.message : String(error)
    return json({ ok: false, error: message })
  }

  ctx.tools.register({
    name: 'recon_board',
    description:
      '团队看板：所有 Agent 共用的协同办公记录。agent 写看板必须分两层：summary=概括索引，text=完整正文；'
      + '发现（finding）、猜想（hypothesis）、任务（task）、结论（conclusion）、备注（note）都写这里，带节点/漏洞/命令引用，其他人立刻能看到。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['post', 'list', 'view', 'search', 'summarize', 'update', 'edit', 'remove'], description: '默认 post；view 按 id 查看正文，search 按关键词检索，summarize 用模型生成真正概括，edit 改正文，remove 删除条目' },
        kind: { type: 'string', enum: ['finding', 'hypothesis', 'task', 'conclusion', 'note'], description: '条目类型' },
        text: { type: 'string', description: '正文内容：完整证据、判断、下一步' },
        summary: { type: 'string', description: 'agent 条目的概括索引（必填）；不填会自动取正文首行；用户条目忽略' },
        node: { type: 'string', description: '关联节点 id 或 value' },
        vuln: { type: 'string', description: '关联漏洞 id' },
        commandId: { type: 'string', description: '关联命令 id' },
        shots: { type: 'array', items: { type: 'string' }, description: '截图路径（recon_browser 返回的 shot）' },
        id: { type: 'string', description: 'update 时的条目 id' },
        query: { type: 'string', description: 'search 的关键词（匹配概括、正文、类型、作者）' },
        limit: { type: 'number', description: 'list/search 返回条数，默认 40' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        if (asText(args.action, 'post') === 'list') {
          /* 默认返回全部条目；用户返回正文，agent 只返回概括索引，正文用 view 查看。 */
          const asked = Number.isFinite(args.limit) ? Math.max(1, Math.min(10000, Math.floor(args.limit))) : 0
          const rows = asked > 0 ? await board.list(eng.id, asked) : await board.list(eng.id, 1000000)
          return json({
            ok: true,
            entries: rows.map((row) => ({
              id: row.id, kind: row.kind,
              author: row.author,
              summary: boardSummaryOf(row),
              text: row.author && row.author.role === 'user' ? asText(row.text) : '',
              hasBody: !(row.author && row.author.role === 'user'),
              refs: row.refs, shots: row.shots,
            })),
          })
        }
        if (asText(args.action) === 'search') {
          const rows = await board.search(eng.id, asText(args.query), Number(args.limit) || 50)
          return json({
            ok: true,
            entries: rows.map((row) => ({
              id: row.id, kind: row.kind, author: row.author,
              summary: boardSummaryOf(row),
              text: row.author && row.author.role === 'user' ? asText(row.text) : '',
              hasBody: !(row.author && row.author.role === 'user'),
              refs: row.refs, shots: row.shots,
            })),
          })
        }
        if (asText(args.action) === 'summarize') {
          const row = await board.summarizeEntry(eng.id, asText(args.id))
          return json({ ok: true, entry: { id: row.id, kind: row.kind, summary: boardSummaryOf(row), text: row.text } })
        }
        if (asText(args.action) === 'view') {
          const rows = await board.list(eng.id, 1000000)
          const row = rows.find((item) => item.id === asText(args.id))
          if (row === undefined) throw new Error(`看板条目不存在：${asText(args.id)}`)
          board.markViewed(eng.id, caller, row.id)
          return json({ ok: true, entry: { id: row.id, kind: row.kind, author: row.author, text: row.text, refs: row.refs, shots: row.shots } })
        }
        if (asText(args.action) === 'update' || asText(args.action) === 'edit') {
          const row = await board.update(eng.id, asText(args.id), args)
          return json({ ok: true, entry: { id: row.id, kind: row.kind, summary: boardSummaryOf(row), text: row.text } })
        }
        if (asText(args.action) === 'remove') {
          return json(await board.remove(eng.id, asText(args.id)))
        }
        const refs = {}
        if (asText(args.node) !== '') {
          const hit = findNode(eng, args.node)
          refs.nodeIds = hit ? [hit.id] : []
          refs.nodeValue = hit ? hit.value : args.node
        }
        if (asText(args.vuln) !== '') refs.vulnIds = [asText(args.vuln)]
        if (asText(args.commandId) !== '') refs.commandIds = [asText(args.commandId)]
        const summary = asText(args.summary).replace(/\s+/g, ' ').trim()
        const body = asText(args.text).replace(/\s+/g, ' ').trim()
        const bodyPrefix = summary.replace(/…$/g, '').trim()
        if (summary === '' || summary === body || (bodyPrefix.length >= 80 && body.startsWith(bodyPrefix))) {
          throw new Error('agent 看板必须提供真正的概括 summary：要语义提炼对象/位置/结论/下一步，不能复制正文或截断正文；text 仍然写完整正文。')
        }
        const entry = await board.post(eng.id, {
          author: caller,
          kind: asText(args.kind, 'note'),
          text: asText(args.text),
          summary,
          refs,
          shots: asList(args.shots),
        })
        void trace?.push?.(eng.id, {
          kind: 'chat',
          actor: caller,
          title: `看板 +1（${entry.kind}）｜${shortText(entry.text, 90)}`,
          detail: entry.text,
          refs: entry.refs || {},
        })
        return json({ ok: true, id: entry.id, kind: entry.kind, author: caller.name })
      } catch (error) {
        return fail(error)
      }
    },
  })

  ctx.tools.register({
    name: 'recon_asset_remove',
    description:
      '从图谱上卸载一个节点（发现连错了/资产判断错了/误报）。mode=archive 只是归档（隐藏但保留记录），'
      + 'mode=delete 连同它的边与漏洞一起删掉（不可恢复）。删之前先确认 id。',
    parameters: {
      type: 'object',
      properties: {
        node: { type: 'string', description: '节点 id 或 value' },
        mode: { type: 'string', enum: ['archive', 'restore', 'delete'], description: '默认 archive' },
        reason: { type: 'string', description: '为什么要卸载（写进看板，方便复盘）' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      required: ['node'],
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const mode = asText(args.mode, 'archive')
        const result = await store.mutate(eng.id, (draft) => {
          const node = findNode(draft, args.node)
          if (node === undefined) throw new Error(`节点不存在：${args.node}。候选：${candidateHint(draft, args.node).join(' ; ')}`)
          if (mode === 'restore') {
            node.archived = false
            delete node.archivedAt
            delete node.archiveReason
            return { node, removed: 0, archived: false }
          }
          if (mode === 'delete') {
            const before = draft.nodes.length
            draft.nodes = draft.nodes.filter((n) => n.id !== node.id)
            draft.edges = draft.edges.filter((e) => e.from !== node.id && e.to !== node.id)
            draft.vulns = draft.vulns.filter((v) => v.nodeId !== node.id)
            draft.commands = draft.commands.map((c) => ({ ...c, nodeIds: (c.nodeIds || []).filter((n) => n !== node.id) }))
            return { node, removed: before - draft.nodes.length, archived: false }
          }
          node.archived = true
          node.archivedAt = nowIso()
          node.archiveReason = asText(args.reason) || undefined
          return { node, removed: 0, archived: true }
        })
        const caller = callerOf(exec)
        await board.post(eng.id, {
          author: caller,
          kind: 'note',
          text: `${mode === 'delete' ? '删除' : (mode === 'restore' ? '恢复' : '归档')}节点 ${result.node.kind}:${result.node.value}（${result.node.id}）`
            + (asText(args.reason) !== '' ? `；原因：${asText(args.reason)}` : ''),
          refs: { nodeIds: [result.node.id], nodeValue: result.node.value },
        })
        void trace?.push?.(eng.id, {
          kind: 'graph',
          actor: caller,
          title: `${mode === 'delete' ? '删除' : (mode === 'restore' ? '恢复' : '归档')}节点 ${result.node.kind}:${result.node.value}`,
          detail: asText(args.reason),
          refs: { nodeIds: [result.node.id] },
          meta: { op: mode },
        })
        return json({ ok: true, mode, node: { id: result.node.id, value: result.node.value }, removed: result.removed })
      } catch (error) {
        return fail(error)
      }
    },
  })

  ctx.tools.register({
    name: 'recon_squad',
    description:
      '多智能体编队：派独立 Agent 并行干活，或给已有成员追加任务、看队伍、停成员；'
      + 'action=group 可把专业角色加入某个成员的小组（指定模型档位/skills/MCP），小组整体只算一个并发。'
      + '每个成员有自己的角色与视野（图谱/命令/漏洞/看板共享）。只有指挥席能派发（成员不能递归派发）。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['spawn', 'group', 'task', 'list', 'stop', 'remove'], description: '默认 list；group 用于把专业角色加入现有成员的小组' },
        role: { type: 'string', description: '队员角色 id：scout / web / reverser / intranet / qa，或配置里的自定义/临时角色。总指挥/参谋是常设席位，不能 spawn；要给他们派活用 action=task' },
        asRole: { type: 'string', description: '（可选）临时新角色 id，例如 developer / reporter / fuzzer；不存在时自动创建' },
        roleName: { type: 'string', description: '（可选）临时角色的显示名，例如「工具开发」「报告员」' },
        rolePrompt: { type: 'string', description: '（可选）临时角色的职责说明（会写进它的系统提示）' },
        name: { type: 'string', description: '（可选）给新队员起个代号，例如「反序列化专攻」「JS 拆包手」；不填则自动 Web 手#3' },
        prompt: { type: 'string', description: '（可选）这名队员的专属指令：目标、边界、要产出什么、禁止做什么，会以最高优先级注入它的系统提示' },
        skills: { type: 'array', items: { type: 'string' }, description: '（可选）给这名队员点开的 skills 名字，例如 ["web-fingerprint","nuclei-scan"]' },
        mcp: {
          type: 'array',
          description: '（可选）这名队员的专属 MCP 服务：每项 { name, transport, command, args, env, url }。只对该队员生效，别人调不到。',
          items: { type: 'object' },
        },
        tier: { type: 'string', enum: [...MODEL_TIERS, 'dsh'], description: '模型档位：deep / fast / vision / dsh（跟随 DSH），默认取角色默认' },
        task: { type: 'string', description: '任务描述（spawn/task 必填）' },
        member: { type: 'string', description: '成员名字，例如「Web 手#6」（task/stop/remove 用，也接受 #6 这种序号）' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        const action = asText(args.action, 'list')

        if (action === 'list') {
          try { await squad.ensureCore(eng.id) } catch { /* 核心席位补位失败不阻断列表 */ }
          return json({
            ok: true,
            caller: caller.name,
            running: squad.activeCount(eng.id),
            members: squad.list(eng.id),
            roles: squad.roles().map((role) => ({ id: role.id, name: role.name, tier: role.tier, skills: asList(role.skills), mcp: asMcpList(role.mcp) })),
            core: squad.coreRoles().map((role) => ({ id: role.id, name: role.name, tier: role.tier, skills: asList(role.skills), mcp: asMcpList(role.mcp) })),
          })
        }
        if (action === 'spawn') {
          if (caller.kind === 'member') {
            throw new Error('你是编队成员，不能递归派发；把任务写进 recon_board（kind=task）由指挥席派发')
          }
          if (asText(args.task) === '') throw new Error('spawn 需要 task')
          let roleId = asText(args.role, 'web')
          const coreWanted = squad.coreRoleIdOf(roleId)
          if (coreWanted !== '') {
            const core = squad.coreRoles().find((role) => role.id === coreWanted)
            throw new Error(`${core !== undefined ? core.name : coreWanted} 是常设席位（每靶标各一个、自动在岗），不能 spawn；请用 recon_squad task 给席位派活`)
          }
          /* 临时角色：不存在就现开一个（名字+职责由总指挥指定） */
          const asRole = asText(args.asRole).trim()
          if (asRole !== '') {
            await squad.ensureRole({
              roleId: asRole,
              roleName: args.roleName,
              rolePrompt: args.rolePrompt,
              skills: asList(args.skills),
            })
            roleId = asRole
          }
          const member = await squad.spawn({
            engagementId: eng.id,
            roleId,
            tier: asText(args.tier),
            task: asText(args.task),
            origin: 'manual',
            name: asText(args.name),
            promptExtra: asText(args.prompt),
            skills: asList(args.skills),
            mcp: asMcpList(args.mcp),
          })
          return json({ ok: true, member })
        }
        if (action === 'group') {
          if (caller.kind === 'member') throw new Error('只有指挥席可以建立/扩展小组；成员请先 recon_group request')
          const lead = asText(args.member)
          if (lead === '') throw new Error('group 需要 member（组长名字）')
          let roleId = asText(args.role, '')
          if (roleId === '') throw new Error('group 需要 role（要加入的专业角色）')
          const asRole = asText(args.asRole).trim()
          if (asRole !== '') {
            await squad.ensureRole({ roleId: asRole, roleName: args.roleName, rolePrompt: args.rolePrompt, skills: asList(args.skills) })
            roleId = asRole
          }
          const group = await squad.createGroup({
            engagementId: eng.id,
            leadKey: lead,
            roleId,
            name: asText(args.name),
            tier: asText(args.tier),
            task: asText(args.task),
            promptExtra: asText(args.prompt),
            skills: asList(args.skills),
            mcp: asMcpList(args.mcp),
          })
          return json({ ok: true, group })
        }
        if (action === 'task') {
          if (caller.kind === 'member') throw new Error('你是编队成员，不能给其他成员派活；请写看板由指挥席派发')
          try { await squad.ensureCore(eng.id) } catch { /* 目标若为普通成员则不需要核心席位 */ }
          const member = await squad.task(asText(args.member), asText(args.task), eng.id)
          return json({ ok: true, member })
        }
        if (action === 'stop') {
          if (caller.kind === 'member') throw new Error('你是编队成员，不能叫停其他成员')
          return json(await squad.stop(asText(args.member), eng.id))
        }
        if (action === 'remove') {
          if (caller.kind === 'member') throw new Error('你是编队成员，不能回收其他成员')
          return json(await squad.remove(asText(args.member), { engagementId: eng.id }))
        }
        throw new Error(`未知 action：${action}`)
      } catch (error) {
        return fail(error)
      }
    },
  })

  ctx.tools.register({
    name: 'recon_group',
    description:
      '协作小组：当执行成员遇到非自己职责的卡点（如 Web 需要逆向）时，用 action=request 请求总指挥派专业角色；'
      + '总指挥用 recon_squad action=group 把专业角色加入该成员的小组。组内用 action=ask 串行提问并等待对方回答，'
      + '组内消息互相可见，整个小组只算一个并发；action=close 由总指挥让全组各自交接后一起回收。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['request', 'ask', 'post', 'list', 'close'], description: '默认 list' },
        groupId: { type: 'string', description: '小组 id；成员默认使用自己所在小组' },
        member: { type: 'string', description: 'ask 的目标成员名字/序号' },
        role: { type: 'string', description: 'request 需要总指挥派来的专业角色，如 reverser / web / intranet' },
        task: { type: 'string', description: 'request 的卡点说明 / 希望对方处理的任务' },
        question: { type: 'string', description: 'ask 给对方的问题或要求' },
        text: { type: 'string', description: 'post 的组内消息' },
        timeoutMs: { type: 'number', description: 'ask 等待对方回复的毫秒数，默认 300000' },
        skills: { type: 'array', items: { type: 'string' }, description: 'request 建议的技能，供总指挥分派时参考' },
        tier: { type: 'string', enum: [...MODEL_TIERS, 'dsh'], description: 'request 建议的模型档位' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        const action = asText(args.action, 'list')
        const member = caller.kind === 'member' ? squad.members.get(caller.key) : undefined
        if (action === 'request') {
          if (member === undefined) throw new Error('request 只能由编队成员发起')
          const role = asText(args.role)
          if (role === '') throw new Error('request 需要 role（需要什么专业角色）')
          const need = asText(args.task) || '需要专业角色协作'
          const skillNote = asList(args.skills).map((item) => asText(item)).filter((item) => item !== '')
          const requestText = `【协作请求】${member.name}（${member.role}）遇到卡点，需要 ${role}：${need}${skillNote.length > 0 ? `\n建议技能：${skillNote.join(', ')}` : ''}${asText(args.tier) !== '' ? `\n建议档位：${asText(args.tier)}` : ''}`
          await board.post(eng.id, { author: caller, kind: 'task', text: requestText, refs: { groupRequest: true, memberName: member.name, role } })
          let nudged = null
          try { nudged = await cockpit?.nudge?.(eng.id, requestText, { always: true, force: true }) } catch { /* 看板已留请求 */ }
          return json({ ok: true, requested: role, request: requestText, nudged })
        }
        if (action === 'ask') {
          if (member === undefined) throw new Error('ask 只能由编队成员发起')
          const groupId = asText(args.groupId) || asText(member.groupId)
          if (groupId === '') throw new Error('你还没有小组')
          const question = asText(args.question) || asText(args.task) || asText(args.text)
          const result = await squad.groupAsk(groupId, member.key, asText(args.member), question, args.timeoutMs)
          return json(result)
        }
        if (action === 'post') {
          if (member === undefined) throw new Error('post 只能由编队成员发起')
          const groupId = asText(args.groupId) || asText(member.groupId)
          if (groupId === '') throw new Error('你还没有小组')
          return json({ ok: true, group: await squad.groupPost(groupId, member.key, asText(args.text)) })
        }
        if (action === 'list') {
          const groups = member !== undefined
            ? (member.groupId ? [squad.groupView(squad.groups.get(member.groupId))].filter(Boolean) : [])
            : squad.listGroups(eng.id)
          return json({ ok: true, groups })
        }
        if (action === 'close') {
          if (caller.kind === 'member') throw new Error('只有指挥席可以结束并回收整个小组')
          const groupId = asText(args.groupId)
          if (groupId === '') throw new Error('close 需要 groupId')
          return json(await squad.closeGroup(groupId, eng.id))
        }
        throw new Error(`未知 action：${action}`)
      } catch (error) {
        return fail(error)
      }
    },
  })

  ctx.tools.register({
    name: 'recon_skill',
    description: '加载本机成熟技能（$DSH_HOME/skills、$DSH_HOME/redteam/skills、$DSH_PUBLIC_SKILLS/...）。先 list 看目录，再 load 读取完整技能正文；不要凭记忆猜技能内容。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'load'], description: '默认 list' },
        name: { type: 'string', description: 'load 时的技能 name（如 dir-bruteforce）' },
        query: { type: 'string', description: 'list 时按名称/描述过滤' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const action = asText(args.action, 'list')
        if (action === 'list') {
          const query = asText(args.query).toLowerCase()
          const items = (await discoverSkills()).filter((item) => query === ''
            || `${item.name} ${item.description} ${item.whenToUse}`.toLowerCase().includes(query))
          return json({ ok: true, count: items.length, skills: items.map((item) => ({ name: item.name, description: shortText(item.description, 180), whenToUse: shortText(item.whenToUse, 120) })) })
        }
        if (action !== 'load') throw new Error(`未知 action：${action}`)
        const hit = await loadSkill(args.name)
        if (hit === undefined) throw new Error(`技能不存在：${asText(args.name)}`)
        const text = await readFile(hit.path, 'utf8')
        return json({ ok: true, name: hit.name, path: hit.path, content: text })
      } catch (error) { return fail(error) }
    },
  })

  ctx.tools.register({
    name: 'recon_browser',
    description:
      '真实浏览器操作（Playwright + Chromium）：打开页面、点击、填表、按键、取文本/HTML、执行 JS、截图。'
      + '登录态按靶标持久化（storageState），所以「先登录再点」的多步流程可以跨调用续着走。'
      + '每次截图返回 shot 路径，把它写进看板条目（shots）就能在页面上看到缩略图。',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['goto', 'click', 'fill', 'press', 'text', 'html', 'eval', 'screenshot', 'links', 'forms', 'steps'],
          description: '要做的动作，默认 goto',
        },
        url: { type: 'string', description: '目标 URL（goto 必填；其它动作给了就先打开再操作）' },
        selector: { type: 'string', description: 'CSS 选择器（click/fill/text 用）' },
        value: { type: 'string', description: 'fill 的值' },
        text: { type: 'string', description: '按键名（press，如 Enter）' },
        expression: { type: 'string', description: 'eval 的 JS 表达式' },
        x: { type: 'number', description: '坐标点击 x（无 selector 时用）' },
        y: { type: 'number', description: '坐标点击 y' },
        timeoutMs: { type: 'number', description: '动作超时，默认 20000' },
        steps: {
          type: 'array',
          description: '可选多步动作（action=steps 时使用）：每步 {action,url,selector,value,text,x,y,waitMs,expression}',
          items: { type: 'object' },
        },
        headless: { type: 'boolean', description: '是否无头模式，默认 true' },
        maxChars: { type: 'number', description: '页面文本/HTML 返回上限，默认 6000' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        const sessionKey = browsers.sessionKey(exec, caller)
        browsers.begin(eng.id, sessionKey, {
          actor: caller, action: asText(args.action, 'goto'), url: asText(args.url),
        })
        let outcome = null
        try {
          outcome = await browser.run(eng.id, args)
        } finally {
          /* 无论成败都要结束"正在操作浏览器"状态，失败时保留最后一次画面 */
          browsers.end(eng.id, sessionKey, outcome)
        }
        void trace?.push?.(eng.id, {
          kind: 'tool',
          actor: caller,
          title: `浏览器 ${asText(args.action, 'goto')} ${shortText(asText(args.url), 80)}`,
          detail: [asText(args.selector), asText(args.value), asText(args.text), asText(args.expression)].filter((x) => x !== '').join(' · '),
          refs: { tool: 'recon_browser' },
          meta: { ok: outcome !== null && outcome.ok === true, url: outcome && outcome.url ? outcome.url : asText(args.url) },
        })
        if (outcome === null || typeof outcome !== 'object') {
          void trace?.push?.(eng.id, {
            kind: 'tool',
            actor: caller,
            title: `浏览器 ${asText(args.action, 'goto')} ${shortText(asText(args.url), 80)}`,
            detail: [asText(args.selector), asText(args.value), asText(args.text)].filter((x) => x !== '').join(' · '),
            refs: { tool: 'recon_browser' },
          })
          return json({ ok: false, error: '浏览器没有返回结果' })
        }
        if (outcome.ok && asText(args.action) === 'screenshot' && outcome.shot) {
          await board.post(eng.id, {
            author: caller,
            kind: 'finding',
            text: `浏览器截图：${outcome.title || outcome.url || ''}`,
            shots: [outcome.shot],
            refs: outcome.url ? { url: outcome.url } : {},
          })
        }
        return json(outcome)
      } catch (error) {
        return fail(error)
      }
    },
  })

  /* ── 一句话配自动化：用户说"每发现一个新资产就派漏洞猎手"，指挥官调它就行 ── */
  ctx.tools.register({
    name: 'recon_watch',
    description:
      '管理「事件触发」规则：什么时候自动派哪个角色干活。例如用户说「每发现一个新资产就让漏洞猎手去探测」，'
      + '就 action=add, on=node.created, role=hunter, kinds=subdomain,ip,url,service,endpoint, task=…。'
      + 'on 支持 node.created（新资产）、vuln.created（新漏洞）、command.finished（命令跑完）、interval（定时巡检）。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'add', 'remove', 'enable', 'disable'], description: '默认 list' },
        ruleId: { type: 'string', description: '规则 id（remove/enable/disable 用）' },
        on: { type: 'string', enum: ['node.created', 'vuln.created', 'command.finished', 'interval'], description: '触发事件' },
        role: { type: 'string', description: '派哪个队员角色：scout / web / reverser / intranet / qa，或自定义临时角色；总指挥/参谋是常设席位，不能作为触发角色' },
        tier: { type: 'string', enum: [...MODEL_TIERS, 'dsh'], description: '模型档位：deep / fast / vision / dsh（跟随 DSH）' },
        kinds: { type: 'array', items: { type: 'string' }, description: '只在出现这些资产类型时触发（node.created 有效）' },
        severity: { type: 'array', items: { type: 'string' }, description: '只在出现这些等级时触发（vuln.created 有效）' },
        cooldownMs: { type: 'number', description: '冷却毫秒，默认 45000' },
        everyMs: { type: 'number', description: 'interval 的周期毫秒，最小 60000' },
        task: { type: 'string', description: '派给成员的任务模板，可用 {{value}} {{kind}} {{nodeId}} {{title}} {{severity}} {{endpoint}}' },
        enabled: { type: 'boolean', description: '默认 true' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args) {
      try {
        const effective = automation.config()
        const current = configStore.get().automation && typeof configStore.get().automation === 'object'
          ? configStore.get().automation
          : {}
        const rules = Array.isArray(effective.rules) ? effective.rules.map((rule) => ({ ...rule })) : []
        const action = asText(args.action, 'list')

        if (action === 'list') {
          return json({
            ok: true,
            enabled: effective.enabled !== false,
            maxAgents: Number.isFinite(effective.maxAgents) ? effective.maxAgents : 8,
            maxAutomationAgents: Number.isFinite(effective.maxAutomationAgents) ? effective.maxAutomationAgents : 3,
            queued: automation.status().queued,
            rules: rules.map((rule) => ({
              id: rule.id, on: rule.on, role: rule.role, tier: rule.tier || '',
              kinds: rule.whenKinds || [], severity: rule.whenSeverity || [],
              cooldownMs: rule.cooldownMs || 0, everyMs: rule.everyMs || 0,
              enabled: rule.enabled !== false, task: shortText(rule.task || '', 120),
            })),
          })
        }
        if (action === 'add') {
          const on = asText(args.on, 'node.created')
          const roleWanted = asText(args.role, on === 'vuln.created' ? 'web' : (on === 'interval' ? 'scout' : 'web'))
          const coreWanted = squad.coreRoleIdOf(roleWanted)
          if (coreWanted !== '') throw new Error('总指挥/参谋是常设席位，不能作为事件触发角色')
          const wantedKinds = asList(args.kinds).slice().sort()
          const wantedSeverity = asList(args.severity).slice().sort()
          const resolvedRole = canonicalRoleId(squad, roleWanted)
          /* 同类规则已存在就不再叠加；按别名解析后的角色、kinds、severity 一起比较。 */
          const duplicate = rules.find((rule) => {
            if (rule.on !== on || rule.enabled === false) return false
            if (squad.roleOf(rule.role).id !== resolvedRole) return false
            const ruleKinds = asList(rule.whenKinds).slice().sort()
            const ruleSeverity = asList(rule.whenSeverity).slice().sort()
            return JSON.stringify(ruleKinds) === JSON.stringify(wantedKinds)
              && JSON.stringify(ruleSeverity) === JSON.stringify(wantedSeverity)
          })
          if (duplicate !== undefined) {
            return json({
              ok: true,
              duplicate: true,
              existing: duplicate.id,
              on: duplicate.on,
              role: duplicate.role,
              note: `已有同类规则「${duplicate.id}」（${duplicate.on} → ${duplicate.role}），不再新增；如需调整请先 remove 或 disable 它。`,
              total: rules.length,
            })
          }
          const rule = {
            id: asText(args.ruleId, `watch-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`),
            on,
            enabled: args.enabled !== false,
            role: resolvedRole,
            tier: MODEL_CHOICES.includes(asText(args.tier)) ? asText(args.tier) : (on === 'vuln.created' ? 'vision' : 'deep'),
            whenKinds: wantedKinds,
            whenSeverity: wantedSeverity,
            cooldownMs: Number.isFinite(args.cooldownMs) ? args.cooldownMs : 45000,
            task: asText(args.task, on === 'node.created'
              ? '新资产 {{kind}}:{{value}}（{{nodeId}}）刚进图谱，做一轮针对性探测，结论用 recon_vuln 登记并写进看板。'
              : (on === 'vuln.created'
                ? '新漏洞 {{title}}（{{severity}}，{{nodeId}}）需要复现：用 recon_browser 打开 {{endpoint}} 验证并截图，把结论写进看板。'
                : '读取图谱与看板，给出下一步 3 条高价值任务并写进看板。')),
          }
          if (on === 'interval') rule.everyMs = Number.isFinite(args.everyMs) ? Math.max(60000, args.everyMs) : 900000
          rules.push(rule)
          const patch = { automation: { ...current, enabled: true, maxAgents: effective.maxAgents, rules } }
          await configStore.patch(patch)
          return json({
            ok: true,
            added: rule,
            note: '已写入配置并立即生效（automation.enabled=true）',
            total: rules.length,
          })
        }
        const ruleId = asText(args.ruleId)
        if (ruleId === '') throw new Error('缺少 ruleId')
        const index = rules.findIndex((rule) => rule.id === ruleId)
        if (index < 0) throw new Error(`规则不存在：${ruleId}。现有：${rules.map((r) => r.id).join(', ')}`)
        if (action === 'remove') rules.splice(index, 1)
        else if (action === 'enable') rules[index] = { ...rules[index], enabled: true }
        else if (action === 'disable') rules[index] = { ...rules[index], enabled: false }
        else throw new Error(`未知 action：${action}`)
        await configStore.patch({ automation: { ...current, rules } })
        return json({ ok: true, action, ruleId, total: rules.length })
      } catch (error) {
        return fail(error)
      }
    },
  })

  /* ── 通用配置：密钥 / 模型 / 角色 / 记忆 / 技能 / MCP / 环境变量 ── */
  /* ── 命令审计：验收员回看队员执行过程，覆盖不足就返工 ── */
  ctx.tools.register({
    name: 'recon_audit',
    description:
      '命令审计（验收员专用）。action=members 列出可审计的队员与命令数；action=list 看某个队员/角色执行过的命令；'
      + 'action=inspect 按覆盖度规则体检（全端口/服务识别/字典大小/扩展名/子域全源/失败率/重复命令），给出结论与改法；'
      + 'action=rework 把不合格的点变成返工任务派回原队员。总指挥发现某个模块做得不全面时，派 qa 用这个工具审。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['members', 'list', 'inspect', 'rework'], description: '默认 inspect' },
        member: { type: 'string', description: '队员名字，例如「Web 手#6」（不填按 role 审整个角色）' },
        role: { type: 'string', description: '按角色审（member 为空时生效），例如 web' },
        limit: { type: 'number', description: 'list 时返回条数，默认 60' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        if (eng === undefined) return json({ ok: false, error: '还没有靶标' })
        const caller = callerOf(exec)
        if (caller.kind === 'member' && caller.role !== 'qa') throw new Error('命令审计是验收员专用工具')
        const action = asText(args.action, 'inspect')
        if (action === 'members') {
          const rows = await audit.members(eng)
          return json({ ok: true, members: rows.slice(0, 40) })
        }
        if (action === 'list') {
          const rows = audit.commandsOf(eng, {
            member: asText(args.member), role: asText(args.role),
            limit: Number.isFinite(args.limit) ? Number(args.limit) : 60,
          })
          return json({
            ok: true,
            count: rows.length,
            commands: rows.map((row) => ({
              id: row.id, at: row.startedAt, purpose: shortText(asText(row.purpose), 100),
              command: shortText(asText(row.command), 300),
              exitCode: row.exitCode === undefined ? null : row.exitCode,
              timedOut: row.timedOut === true,
            })),
          })
        }
        if (action === 'rework') {
          const result = await audit.rework(eng, { member: asText(args.member), role: asText(args.role) })
          return json({
            ok: true,
            verdict: result.report.verdict,
            verdictText: result.report.verdictText,
            total: result.report.total,
            highCount: result.report.highCount,
            findings: result.report.findings.slice(0, 10),
            task: result.task === undefined || result.task === null ? null : { id: result.task.id, title: result.task.title },
            skipped: result.skipped || '',
          })
        }
        const report = audit.inspect(eng, { member: asText(args.member), role: asText(args.role) })
        return json({ ok: true, ...report })
      } catch (error) {
        return fail(error)
      }
    },
  })

  /* ── 断点续跑：手动中断 / 从断点继续 / 看断点状态 ── */
  ctx.tools.register({
    name: 'recon_checkpoint',
    description:
      '断点续跑。action=status 看断点与运行状态；action=pause 中断当前作战并保存断点（关网/关机/要走人时用）；'
      + 'action=resume 从断点继续（开机后点它就能接着跑，不会从头重扫）。心跳超时也会自动存断点。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['status', 'pause', 'resume'], description: '默认 status' },
        reason: { type: 'string', description: 'pause 时写清中断原因，例如 下班关机 / 断网 / 额度用尽' },
        note: { type: 'string', description: 'resume 时给总指挥的交接说明（可选）' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      const eng = await resolveEngagement(exec, args.engagement)
      if (eng === undefined) return json({ ok: false, error: '还没有项目' })
      const action = asText(args.action, 'status')
      if (action === 'pause') return json(await runner.pause(eng, asText(args.reason) || 'manual'))
      if (action === 'resume') return json(await runner.resume(eng, asText(args.note)))
      return json({ ok: true, ...(await runner.status(eng)) })
    },
  })

  /* ── 全员会议：卡住了就开会让所有角色协同出新方案 ── */
  ctx.tools.register({
    name: 'recon_meeting',
    description:
      '全员会议。action=status 看是否停滞（任务全派完、没人在跑、一段时间无新进展），'
      + 'action=convene 立刻召集全体角色：每人诊断原因 + 出 1-3 条新方案，总指挥汇总成新一轮任务。'
      + '系统也会自动检测停滞并开会（有冷却与轮次上限）。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['status', 'convene'], description: '默认 status' },
        reason: { type: 'string', description: 'convene 时写清为什么要开会' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textBlocks(value) },
    async execute(args, exec) {
      const session = meeting
      if (session === undefined || session === null) return json({ ok: false, error: '会议模块未就绪' })
      const eng = await resolveEngagement(exec, args.engagement)
      if (eng === undefined) return json({ ok: false, error: '还没有项目' })
      if (asText(args.action, 'status') === 'status') {
        const verdict = await session.verdict(eng)
        return json({
          ok: true,
          stalled: verdict.stalled,
          reasons: verdict.reasons,
          meeting: session.status(eng),
          stats: verdict.stats || null,
        })
      }
      const verdict = await session.verdict(eng)
      const result = await session.convene(eng, {
        reason: asText(args.reason) || (verdict.stalled ? verdict.reasons.join('；') : '指挥官手动召开'),
        manual: true,
      })
      return json(result)
    },
  })

  ctx.tools.register({
    name: 'recon_memory',
    description:
      '全局长期记忆：所有 agent 必须完整读取；只有总指挥、参谋可以写入。'
      + '只允许写入最重要、最全局的信息：项目概况、总体目标、特殊攻击手法、已确认漏洞、凭据/账号、环境与工具结论等。'
      + '日常过程、普通汇报、离职交接不要写记忆；离职交接只写看板。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list'], description: '默认 list' },
        title: { type: 'string', description: '记忆标题' },
        content: { type: 'string', description: '记忆内容（完整、可复用的事实）' },
        category: { type: 'string', enum: ['project', 'goal', 'technique', 'vulnerability', 'credential', 'environment', 'other'], description: '记忆类别' },
        importance: { type: 'string', enum: ['high', 'critical'], description: '只有重要/关键信息才允许写入' },
        limit: { type: 'number', description: 'list 返回条数，默认全部' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const caller = callerOf(exec)
        const action = asText(args.action, 'list')
        const current = configStore.get()
        const currentMemory = Array.isArray(current.memory) ? current.memory : []
        const rows = currentMemory.map((item) => memoryEntryOf(item))
        if (action === 'list') {
          const limit = Number.isFinite(Number(args.limit)) ? Math.max(1, Math.floor(Number(args.limit))) : 0
          return json({ ok: true, memory: limit > 0 ? rows.slice(-limit) : rows })
        }
        if (action !== 'add') throw new Error(`未知 action：${action}`)
        if (!(caller.kind === 'leader' || caller.role === 'commander' || caller.role === 'staff')) {
          throw new Error('只有总指挥或参谋可以写入长期记忆；其他角色请把结论报告给总指挥/参谋')
        }
        const title = asText(args.title)
        const content = asText(args.content)
        if (title === '' || content === '') throw new Error('add 需要 title 和 content')
        const category = ['project', 'goal', 'technique', 'vulnerability', 'credential', 'environment', 'other'].includes(asText(args.category))
          ? asText(args.category) : 'other'
        const importance = asText(args.importance, 'high')
        if (importance !== 'high' && importance !== 'critical') throw new Error('importance 必须是 high 或 critical')
        const entry = {
          id: `m${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`,
          title,
          content,
          category,
          importance,
          author: { role: caller.role, name: caller.name },
          createdAt: nowMs(),
        }
        await configStore.patch({ memory: [...currentMemory, entry] })
        return json({ ok: true, memory: entry })
      } catch (error) {
        return fail(error)
      }
    },
  })

  ctx.tools.register({
    name: 'recon_config',
    description:
      '读写驾驶舱配置（等价于页面的「控制台」）。用户说「把 FOFA key 配成 xxx」就用 section=keys, values={fofa:"xxx"}；'
      + '说「高复杂模型换成 X」就用 section=models；角色/提示词/记忆/技能/MCP/环境变量同理。读的时候密钥会打码，不会回显明文。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['get', 'set'], description: '默认 get' },
        section: {
          type: 'string',
          enum: ['keys', 'models', 'role', 'core', 'prompt', 'memory', 'skills', 'mcp', 'env', 'chat', 'automation', 'meeting', 'board', 'trace', 'handover'],
          description: '要读写的配置段（core=常设席位总指挥/参谋；prompt.common=注入所有 Agent 的通用提示词。旧的 role/prompt.extra 驾驶舱人设已由 core.commander 取代）',
        },
        values: { description: 'set 时的新值：对象（keys/models/role/prompt/chat）、数组（memory/skills.enabled/env/mcp）或字符串' },
        field: { type: 'string', description: '只改单个字段时用，如 fofa / deep.model' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const action = asText(args.action, 'get')
        const section = asText(args.section, '')
        if (action === 'set' && section === 'memory') {
          const caller = callerOf(exec)
          if (!(caller.kind === 'leader' || caller.role === 'commander' || caller.role === 'staff')) {
            throw new Error('只有总指挥或参谋可以写入长期记忆；其他角色请报告结论')
          }
        }
        if (action === 'get') {
          const redacted = configStore.redacted({ redactEnv: true })
          if (section === '') {
            return json({
              ok: true,
              sections: Object.keys(redacted),
              keysConfigured: configStore.keyPresence(),
              models: redacted.models,
              role: redacted.role,
              automation: automation.config(),
            })
          }
          return json({ ok: true, section, value: redacted[section] })
        }
        if (section === '') throw new Error('set 需要 section')
        const values = args.values
        if (values === undefined || values === null) throw new Error('set 需要 values')
        const current = configStore.get()
        const patch = {}
        if (section === 'keys') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('keys 需要对象，如 {"fofa":"xxx"}')
          patch.keys = {}
          for (const [field, value] of Object.entries(values)) {
            if (!(field in (current.keys || {}))) continue
            patch.keys[field] = typeof value === 'string' ? value : String(value ?? '')
          }
        } else if (section === 'models') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('models 需要对象')
          patch.models = {}
          for (const tier of MODEL_TIERS) {
            const row = values[tier]
            if (row !== undefined && row !== null && typeof row === 'object') {
              patch.models[tier] = {
                provider: asText(row.provider),
                model: asText(row.model),
                reasoning: asText(row.reasoning),
              }
            }
          }
        } else if (section === 'role' || section === 'prompt' || section === 'chat') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error(`${section} 需要对象`)
          patch[section] = values
        } else if (section === 'core') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('core 需要对象，如 {commander:{prompt:"…"}, staff:{prompt:"…"}}')
          patch.core = values
        } else if (section === 'memory' || section === 'mcp' || section === 'env') {
          if (!Array.isArray(values)) throw new Error(`${section} 需要数组`)
          patch[section] = section === 'memory' ? values.map((item) => memoryEntryOf(item)) : values
        } else if (section === 'skills') {
          const enabled = Array.isArray(values) ? values : (values && Array.isArray(values.enabled) ? values.enabled : null)
          if (enabled === null) throw new Error('skills 需要数组或 {enabled:[...]}')
          patch.skills = { ...(current.skills || {}), enabled }
        } else if (section === 'automation') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('automation 需要对象')
          patch.automation = values
        } else if (section === 'meeting') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('meeting 需要对象')
          const current = configStore.get().meeting || {}
          const clamp = (value, min, max, fallback) => {
            const num = Number(value)
            return Number.isFinite(num) ? Math.min(max, Math.max(min, Math.round(num))) : fallback
          }
          patch.meeting = {
            stallMinutes: clamp(values.stallMinutes, 5, 240, Number(current.stallMinutes) || 20),
            gapMinutes: clamp(values.gapMinutes, 5, 240, Number(current.gapMinutes) || 20),
            maxRounds: clamp(values.maxRounds, 1, 20, Number(current.maxRounds) || 3),
          }
        } else if (section === 'board') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('board 需要对象')
          const current = configStore.get().board || {}
          const limit = [50, 100, 200].includes(Number(values.limit)) ? Number(values.limit) : (Number(current.limit) || 100)
          const wantedMerge = [25, 50, 100].includes(Number(values.mergeCount)) ? Number(values.mergeCount) : (Number(current.mergeCount) || 50)
          const mergeMode = values.mergeMode === 'ai' ? 'ai' : 'deterministic'
          const mergeModel = ['deep', 'fast'].includes(asText(values.mergeModel)) ? asText(values.mergeModel) : (current.mergeModel === 'deep' ? 'deep' : 'fast')
          patch.board = { limit, mergeCount: Math.min(wantedMerge, Math.max(10, Math.floor(limit / 2))), mergeMode, mergeModel }
        } else if (section === 'trace') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('trace 需要对象，如 {limit:1000}')
          const current = configStore.get().trace || {}
          const wanted = Number(values.limit)
          patch.trace = { limit: Number.isFinite(wanted) ? Math.max(100, Math.min(5000, Math.floor(wanted))) : (Number(current.limit) || 500) }
        } else if (section === 'handover') {
          if (typeof values !== 'object' || Array.isArray(values)) throw new Error('handover 需要对象')
          const current = configStore.get().handover || {}
          patch.handover = {
            enabled: values.enabled === undefined ? current.enabled !== false : values.enabled !== false,
            timeoutMs: Number(values.timeoutMs) >= 15000 ? Number(values.timeoutMs) : (Number(current.timeoutMs) || 90000),
            keepSkill: false,
          }
        } else {
          throw new Error(`未知 section：${section}`)
        }
        const next = await configStore.patch(patch)
        return json({
          ok: true,
          section,
          changed: Object.keys(patch[section] || {}),
          keysConfigured: configStore.keyPresence(),
          note: section === 'keys'
            ? '密钥已写入 $DSH_HOME/recon/config.json（0600），并立即注入后续命令环境；页面上只显示"已配置"'
            : '配置已保存并立即生效',
          modelsNow: section === 'models' ? next.models : undefined,
        })
      } catch (error) {
        return fail(error)
      }
    },
  })

  /* ── 任务账本：总指挥拆任务 → 成员执行 → 验收判定 ── */
  ctx.tools.register({
    name: 'recon_task',
    description:
      '任务账本（组织的工单系统）。总指挥先读参谋方案，再登记 mission 并拆成可验收任务派给角色；'
      + '执行者领任务、附证据；只有 QA 能 accept（达标）或 reject（不达标，系统会把意见作为新任务回给总指挥）；'
      + '全部任务通过 QA 验收后，总指挥用 mission close 宣布结束并回收队员。'
      + '一条任务 = 标题 + 目标 + 验收标准 + 负责角色 + 状态。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['create', 'list', 'update', 'accept', 'reject', 'mission'], description: '默认 list；mission 用来登记/查看/关闭作战目标' },
        missionAction: { type: 'string', enum: ['set', 'get', 'close'], description: 'mission 动作：set 登记目标（需先有参谋方案）、get 查看、close 由总指挥宣布结束（停止并回收非核心队员）' },
        id: { type: 'string', description: '任务 id（update/accept/reject 用）' },
        title: { type: 'string', description: '任务标题' },
        goal: { type: 'string', description: '要达成什么（具体到资产/接口）' },
        done: { type: 'string', description: '完成判据（mission set 时的 acceptance 别名）' },
        acceptance: { type: 'string', description: '验收标准：怎样算完成（谁看都能判）' },
        role: { type: 'string', description: '负责角色：scout/web/reverser/intranet/qa 或临时角色 id；commander/staff 仅用于返工/收官等常设席位任务' },
        assignee: { type: 'string', description: '指定成员名字（可选，如「Web 手#6」；不填按角色派）' },
        status: { type: 'string', enum: TASK_STATUSES, description: 'update 用' },
        note: { type: 'string', description: '补充说明 / 驳回原因' },
        commandIds: { type: 'array', items: { type: 'string' }, description: '证据命令 id' },
        vulnIds: { type: 'array', items: { type: 'string' }, description: '证据漏洞 id' },
        nodeIds: { type: 'array', items: { type: 'string' }, description: '证据节点 id' },
        shots: { type: 'array', items: { type: 'string' }, description: '截图路径' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        const action = asText(args.action, 'list')
        if (action === 'mission') {
          const sub = asText(args.missionAction, 'get')
          if (sub === 'get') {
            const mission = await tasks.missionOf(eng.id)
            const rows = await tasks.list(eng.id, 400)
            const passed = rows.filter((row) => row.status === 'passed').length
            const open = rows.filter((row) => row.status !== 'passed' && row.status !== 'failed').length
            const failed = rows.filter((row) => row.status === 'failed').length
            return json({ ok: true, mission, progress: { total: rows.length, passed, open, failed } })
          }
          if (sub === 'set') {
            if (caller.kind === 'member' && caller.role !== 'commander') {
              return json({ ok: false, error: '只有总指挥可以登记/调整作战目标' })
            }
            if (asText(args.goal) === '') throw new Error('set 需要 goal（本轮作战目标）')
            const prev = await tasks.missionOf(eng.id)
            const plan = await latestStaffPlan(board, eng.id, prev === null ? 0 : prev.updatedAt)
            if (plan === undefined) {
              return json({
                ok: false,
                error: '还没有本轮参谋方案，不能登记作战目标',
                hint: '先把任务和上下文派给参谋（recon_squad task role=staff 或常设参谋席位），让参谋把整体方案写进看板 kind=hypothesis；总指挥读方案后再拆任务。',
              })
            }
            const acceptanceText = asText(args.acceptance, args.done)
            const mission = await tasks.setMission(eng.id, {
              goal: asText(args.goal),
              done: acceptanceText,
              status: 'running',
              rounds: (prev === null ? 0 : Number(prev.rounds) || 0) + 1,
            })
            await board.post(eng.id, {
              author: caller, kind: 'task',
              text: `本轮作战目标：${asText(args.goal)}${acceptanceText !== '' ? `\n完成判据：${acceptanceText}` : ''}`,
            })
            return json({ ok: true, mission: await tasks.missionOf(eng.id) })
          }
          if (sub === 'close') {
            if (caller.kind === 'member' && caller.role !== 'commander') {
              return json({ ok: false, error: '只有总指挥可以宣布作战结束；QA 只能提交验收报告' })
            }
            const rows = await tasks.list(eng.id, 400)
            const notPassed = rows.filter((row) => row.status !== 'passed')
            const unverified = rows.filter((row) => row.status === 'passed'
              && (!row.verifiedBy || row.verifiedBy.role !== 'qa'))
            const force = args.status === 'passed' || asText(args.note) === 'force'
            if ((notPassed.length > 0 || unverified.length > 0) && !force) {
              return json({
                ok: false,
                error: notPassed.length > 0
                  ? `还有 ${notPassed.length} 条任务没通过验收，不能宣布完成`
                  : `还有 ${unverified.length} 条任务没有 QA 验收记录，不能宣布完成`,
                pending: (notPassed.length > 0 ? notPassed : unverified).slice(-8).map((row) => `${row.id} [${row.status}] ${row.title}`),
                hint: '先让 QA 对每条任务执行 accept/reject；全部通过并被 QA 复核后，再由总指挥 close。',
              })
            }
            const mission = await tasks.setMission(eng.id, {
              goal: (await tasks.missionOf(eng.id) || {}).goal || '',
              done: (await tasks.missionOf(eng.id) || {}).done || '',
              status: 'done',
            })
            cockpit.pendingNudges?.delete?.(eng.id)
            const stopped = await squad.stopAll(eng.id)
            await board.post(eng.id, {
              author: { role: 'commander', name: '总指挥' }, kind: 'conclusion',
              text: `【任务完成】${mission.goal !== '' ? mission.goal : '本轮作战目标'} 已由 QA 全部验收通过（${rows.filter((r) => r.status === 'passed').length} 条任务），总指挥宣布结束，收队。`,
            })
            const reclaimed = await squad.reclaimIdle(eng.id)
            return json({ ok: true, mission, stopped, reclaimed })
          }
          throw new Error(`未知 missionAction：${sub}`)
        }

        if (action === 'list') {
          const rows = await tasks.list(eng.id, 200)
          const status = asText(args.status)
          const role = asText(args.role)
          const filtered = rows.filter((row) => (status === '' || row.status === status)
            && (role === '' || row.role === role))
          return json({
            ok: true,
            stats: await tasks.stats(eng.id),
            tasks: filtered.map((row) => ({
              id: row.id, title: row.title, role: row.role, assignee: row.assignee || null,
              status: row.status, goal: row.goal, acceptance: row.acceptance,
              evidence: row.evidence, note: row.note,
              verifiedBy: row.verifiedBy || null, verifiedAt: row.verifiedAt || null,
            })),
          })
        }
        if (action === 'create') {
          if (caller.kind === 'member' && caller.role !== 'commander') {
            throw new Error('只有总指挥可以拆解并创建任务；执行者请更新自己任务的状态和证据')
          }
          const mission = await tasks.missionOf(eng.id)
          if (mission === null || mission.status !== 'running') {
            return json({
              ok: false,
              error: '还没有进行中的作战目标，不能拆任务',
              hint: '先让参谋出整体方案并写看板，再由总指挥 recon_task action=mission missionAction=set 登记目标。',
            })
          }
          if (asText(args.title) === '') throw new Error('create 需要 title')
          const task = await tasks.create(eng.id, {
            title: asText(args.title),
            goal: asText(args.goal),
            acceptance: asText(args.acceptance),
            role: canonicalRoleId(squad, args.role),
            /* 任务只登记名字：传啥都换算成在岗成员的名字，换算不到就留空按角色派 */
            assignee: (() => {
              const ref = asText(args.assignee)
              if (ref === '') return ''
              const hit = squad.resolveMemberRef(ref, eng.id)
              if (hit === undefined) throw new Error(`指定成员不存在：${ref}`)
              return hit.name
            })(),
            createdBy: caller.role === 'user' ? { role: 'user', name: '指挥席' } : { role: caller.role, name: caller.name },
          })
          await board.post(eng.id, {
            author: caller,
            kind: 'task',
            text: `[${task.id}] ${task.title}\n目标：${task.goal || '-'}\n验收：${task.acceptance || '-'}\n负责：${task.role}`,
            refs: {},
          })
          return json({ ok: true, task })
        }
        const id = asText(args.id)
        if (id === '') throw new Error(`${action} 需要 id`)
        const evidence = {
          commandIds: asList(args.commandIds),
          vulnIds: asList(args.vulnIds),
          nodeIds: asList(args.nodeIds),
          shots: asList(args.shots),
        }
        if (action === 'update') {
          if (caller.kind === 'member' && caller.role !== 'qa' && (args.status === 'passed' || args.status === 'failed')) {
            throw new Error('只有验收员或指挥席可以直接把任务改成 passed/failed')
          }
          const task = await tasks.update(eng.id, id, { ...args, evidence }, caller)
          return json({ ok: true, task })
        }
        if (action === 'accept') {
          if (caller.kind !== 'member' || caller.role !== 'qa') {
            throw new Error('验收必须由 QA 角色执行：请先用 recon_squad task 让验收员核查证据并 accept/reject')
          }
          const task = await tasks.update(eng.id, id, {
            status: 'passed',
            note: asText(args.note),
            evidence,
            verifiedBy: { role: caller.role, name: caller.name },
            verifiedAt: nowMs(),
          }, caller)
          await board.post(eng.id, {
            author: caller,
            kind: 'conclusion',
            text: `任务 ${id} 验收通过：${task.title}${asText(args.note) !== '' ? `；${asText(args.note)}` : ''}`,
            refs: { vulnIds: evidence.vulnIds, commandIds: evidence.commandIds, nodeIds: evidence.nodeIds },
            shots: evidence.shots,
          })
          /* 闭环：全部任务通过且有 QA 记录 → 强制通知总指挥，最后由总指挥 close 收队 */
          let settle = null
          try {
            const rows = await tasks.list(eng.id, 400)
            const pending = rows.filter((row) => row.status !== 'passed' && row.status !== 'failed')
            const failed = rows.filter((row) => row.status === 'failed')
            const unverified = rows.filter((row) => row.status === 'passed'
              && (!row.verifiedBy || row.verifiedBy.role !== 'qa'))
            const mission = await tasks.missionOf(eng.id)
            if (pending.length === 0 && failed.length === 0 && (mission === null || mission.status !== 'done')) {
              const verified = rows.filter((row) => row.verifiedBy && row.verifiedBy.role === 'qa')
              const evidenceCount = verified.reduce((sum, row) => {
                const ev = row.evidence || {}
                return sum + (Array.isArray(ev.commandIds) ? ev.commandIds.length : 0)
                  + (Array.isArray(ev.vulnIds) ? ev.vulnIds.length : 0)
                  + (Array.isArray(ev.nodeIds) ? ev.nodeIds.length : 0)
                  + (Array.isArray(ev.shots) ? ev.shots.length : 0)
              }, 0)
              await board.post(eng.id, {
                author: { role: 'qa', name: caller.name },
                kind: 'conclusion',
                text: `【QA 终验报告】${eng.name} 共 ${rows.length} 条任务，全部 QA 验收通过；证据引用 ${evidenceCount} 项。${unverified.length > 0 ? `仍有 ${unverified.length} 条任务缺少 QA 验收记录，不能收尾。` : '现在交由总指挥做最终决定。'}`,
              })
              if (unverified.length === 0) {
                const nudgedAll = await cockpit?.nudge?.(eng.id,
                  'QA 已对全部任务完成最终验收，请立即复核任务账本并宣布作战结束',
                  { force: true, final: true, always: true })
                settle = { phase: 'ready-to-close', nudged: nudgedAll }
              } else {
                const nudgedAll = await cockpit?.nudge?.(eng.id,
                  `仍有 ${unverified.length} 条已通过任务缺少 QA 验收记录，请安排 QA 重新核查`,
                  { force: true, always: true })
                settle = { phase: 'needs-qa', nudged: nudgedAll, unverified: unverified.map((row) => row.id) }
              }
            }
          } catch { /* 闭环判定失败不影响验收结果 */ }
          return json({ ok: true, task: { id: task.id, status: task.status }, settle })
        }
        if (action === 'reject') {
          if (caller.kind !== 'member' || caller.role !== 'qa') {
            throw new Error('验收必须由 QA 角色执行：请先用 recon_squad task 让验收员核查证据并 accept/reject')
          }
          const reason = asText(args.note, '未达到验收标准')
          const task = await tasks.update(eng.id, id, {
            status: 'failed', note: reason, evidence,
            verifiedBy: { role: caller.role, name: caller.name },
            verifiedAt: nowMs(),
          }, caller)
          const followUp = await tasks.rework(eng.id, task, reason, { role: 'qa', name: caller.name })
          await board.post(eng.id, {
            author: caller,
            kind: 'task',
            text: `任务 ${id} 验收驳回：${reason}（已生成返工任务 ${followUp.id}，@总指挥 请重新分派）`,
            refs: { vulnIds: evidence.vulnIds, commandIds: evidence.commandIds, nodeIds: evidence.nodeIds },
          })
          /* 闭环：驳回 → 参谋出方案 + 总指挥重排 */
          let staffCall = null
          try {
            const staffMember = squad.list(eng.id).find((m) => m.role === 'staff' && m.status !== 'running')
            const ask = `验收驳回 ${id}（${reason}）。请针对缺口给出 3 条改进方案（每条：怎么做 / 派给谁 / 验收标准），写进看板 kind=hypothesis，供总指挥选择。`
            if (staffMember !== undefined) {
              await squad.task(staffMember.name, ask, eng.id)
              staffCall = { member: staffMember.key, name: staffMember.name, mode: 'task' }
            } else if (caller.kind !== 'member') {
              const invited = await squad.spawn({
                engagementId: eng.id, roleId: 'staff',
                name: '参谋（返工）', promptExtra: '你只出方案不执行；针对验收缺口给可执行、可验收的改进方案。',
                task: ask, origin: 'rework',
                allowCore: true,
              })
              staffCall = { member: invited.key, name: invited.name, mode: 'spawn' }
            }
          } catch { /* 参谋拉不起来不影响返工任务 */ }
          try {
            const prevMission = await tasks.missionOf(eng.id)
            if (prevMission !== null) {
              await tasks.setMission(eng.id, {
                goal: prevMission.goal, done: prevMission.done, status: 'running',
                rounds: (Number(prevMission.rounds) || 0) + 1,
              })
            }
          } catch { /* 轮次统计失败不影响返工 */ }
          const nudged = await cockpit?.nudge?.(eng.id, `任务 ${id} 被验收驳回，已请参谋出方案`)
          return json({ ok: true, task: { id: task.id, status: task.status }, followUp: followUp.id, staff: staffCall, nudged: nudged || null })
        }
        throw new Error(`未知 action：${action}`)
      } catch (error) {
        return fail(error)
      }
    },
  })

  /* ── 组织：编制、招募（含临时角色）、回收、简报 ── */
  ctx.tools.register({
    name: 'recon_org',
    description:
      '组织管理：看编制与在岗成员、招募/回收、生成作战简报。'
      + '总指挥可以用它开**临时角色**（例如 developer 写工具、reporter 出报告）：传 role=developer 与 rolePrompt 即生效并持久化。'
      + '总指挥/参谋是常设席位（全局各一个、自动在岗、不可召唤/回收），只能配置人设或直接派活，不能 recruit。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['state', 'recruit', 'recall', 'brief'], description: '默认 state' },
        role: { type: 'string', description: '角色 id（recruit 必填；新名字即临时角色）' },
        roleName: { type: 'string', description: '临时角色的显示名，例如「工具开发」' },
        rolePrompt: { type: 'string', description: '临时角色的职责说明（会进它的系统提示）' },
        tier: { type: 'string', enum: [...MODEL_TIERS, 'dsh'], description: '模型档位：deep / fast / vision / dsh（跟随 DSH）' },
        task: { type: 'string', description: '招募后立刻下发的任务（可选）' },
        member: { type: 'string', description: '成员名字，例如「Web 手#6」（recall 用）' },
        engagement: { type: 'string', description: '靶标 id 或名称' },
      },
      additionalProperties: false,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => textBlocks(v) },
    async execute(args, exec) {
      try {
        const eng = await resolveEngagement(exec, args.engagement)
        const caller = callerOf(exec)
        const action = asText(args.action, 'state')
        if (action === 'state') {
          return json({
            ok: true,
            commander: caller.name,
            roles: squad.roles().map((role) => ({
              id: role.id, name: role.name, tier: role.tier,
              reportsTo: role.reportsTo || null, temporary: role.temporary === true,
            })),
            core: squad.coreRoles().map((role) => ({
              id: role.id, name: role.name, tier: role.tier, reportsTo: role.reportsTo || null,
            })),
            members: squad.list(eng.id),
            tasks: await tasks.stats(eng.id),
          })
        }
        if (action === 'brief') {
          const stats = statsOf(eng)
          const openTasks = (await tasks.list(eng.id, 200)).filter((row) => row.status !== 'passed' && row.status !== 'failed')
          const boardText = await board.recentText(eng.id, 12)
          return json({
            ok: true,
            engagement: { id: eng.id, name: eng.name, scope: eng.scope },
            stats,
            members: squad.list(eng.id).map((m) => `${m.name}(${m.role}/${m.status})`),
            openTasks: openTasks.map((row) => `${row.id} [${row.role}] ${row.title} — ${row.status}`),
            board: boardText,
          })
        }
        if (caller.kind === 'member') throw new Error('只有总指挥能招募/回收成员')
        if (action === 'recruit') {
          const roleId = asText(args.role)
          if (roleId === '') throw new Error('recruit 需要 role')
          const coreId = squad.coreRoleIdOf(roleId)
          if (coreId !== '') {
            const core = squad.coreRoles().find((role) => role.id === coreId)
            throw new Error(`${core !== undefined ? core.name : coreId} 是常设席位，不能招募；请到控制台「常设席位」里配置`)
          }
          await squad.ensureRole({
            roleId,
            roleName: args.roleName,
            rolePrompt: args.rolePrompt,
          })
          const member = await squad.spawn({
            engagementId: eng.id,
            roleId,
            tier: asText(args.tier),
            task: asText(args.task),
            origin: 'recruit',
          })
          return json({ ok: true, member, role: squad.roleOf(roleId).name })
        }
        if (action === 'recall') {
          const key = asText(args.member)
          if (key === '') throw new Error('recall 需要 member')
          /* 回收＝离职：先让成员交出一份交接（发现/坑/技巧/建议），落看板后再释放 */
          const result = await squad.remove(key, { reason: '回收', engagementId: eng.id })
          return json(result)
        }
        throw new Error(`未知 action：${action}`)
      } catch (error) {
        return fail(error)
      }
    },
  })
}

/** 模型上下文溢出错误的识别与 DSH 正常压缩重试。 */
function isContextWindowError(error) {
  if (error === null || error === undefined) return false
  const code = String(error.code || error.name || (error.data && error.data.code) || '').toUpperCase()
  if (code.includes('CONTEXT_WINDOW') || code.includes('CONTEXT_LENGTH') || code.includes('CONTEXT_OVERFLOW')) return true
  const text = String(error.message || error.detail || error)
  return /context\s+(?:length|window)|maximum\s+context|too\s+(?:large|long)\s+for\s+(?:this\s+|the\s+)?model|input\s+.*exceed/i.test(text)
}

/** 上下文溢出时使用 DSH 自带的正常压缩；压缩出有效结果后再重试。 */
async function recoverContextOverflow(ctx, agent, failure, signal) {
  const compaction = ctx.compaction || (typeof ctx.get === 'function' ? ctx.get('compaction') : undefined)
  if (compaction === undefined || compaction === null || agent === undefined || agent === null || agent.session === undefined) return false
  const before = agent.session.surface ? agent.session.surface.replaceGeneration : -1
  try {
    const result = await compaction.compactIfNeeded(agent, 'context-overflow', signal)
    return result !== null || (agent.session.surface && agent.session.surface.replaceGeneration > before)
  } catch {
    return false
  }
}

/* ────────────────────────── 插件入口 ────────────────────────── */

export function apply(ctx, config = {}) {
  const cfg = {
    root: asText(config.root) || join(dshHome(), 'recon'),
    maxOutputChars: Number.isFinite(config.maxOutputChars) ? config.maxOutputChars : 24000,
    defaultTimeoutMs: Number.isFinite(config.defaultTimeoutMs) ? config.defaultTimeoutMs : 300000,
    systemPrompt: config.systemPrompt !== false,
  }
  const hub = new EventHub()
  const configStore = new ConfigStore(cfg.root)
  const customModels = new CustomModelRegistry(ctx, configStore)
  const store = new ReconStore(cfg.root, (eng) => {
    try {
      hub.broadcast({ type: 'graph', engagementId: eng.id, version: eng.version, stats: statsOf(eng) })
    } catch { /* 广播失败不影响落盘 */ }
  })
  /* 任务账本先于 cockpit / squad 构造：两者都持有同一份引用 */
  const board = new Board(cfg.root, hub, configStore, ctx)
  const trace = new Trace(cfg.root, hub)
  const tasks = new Tasks(cfg.root, hub, trace)
  const cockpit = new Cockpit(ctx, store, cfg, configStore, hub)
  cockpit.tasks = tasks
  cockpit.trace = trace
  cockpit.board = board
  const mcp = new McpBinder(ctx, hub)
  const browser = new BrowserRunner(cfg.root, hub)
  const browsers = new Browsers(store, trace, hub)
  const squad = new Squad({ ctx, store, cfg, configStore, hub, board, tasks, trace, browsers, cockpit })
  cockpit.squad = squad
  const automation = new Automation({ ctx, store, cfg, configStore, hub, board, squad })
  const audit = new Audit({ store, board, tasks, squad, trace, configStore })
  const runner = new Runner({ store, cfg, configStore, hub, board, tasks, squad, cockpit, trace })
  const meeting = new Meeting({
    store, cfg, configStore, hub, board, squad,
    tasks, cockpit, trace,
  })
  const brief = new Brief(ctx, store, cfg, configStore, hub, {
    tasks, board, squad, trace, runner, meeting, audit,
  })
  const bindings = new Map()

  /* 图谱变化 → 事件触发（新资产派猎手、新漏洞派浏览器）+ 前端增量刷新 */
  store.onDelta = (eng, delta) => {
    if (delta.newCommands.length > 0 || delta.newNodes.length > 0 || delta.newVulns.length > 0) {
      try {
        hub.broadcast({
          type: 'delta',
          engagementId: eng.id,
          newNodes: delta.newNodes.map((n) => n.id),
          newVulns: delta.newVulns.map((v) => v.id),
          newCommands: delta.newCommands.map((c) => c.id),
        })
      } catch { /* 广播失败不影响落盘 */ }
    }
    void automation.onDelta(eng, delta).catch((error) => {
      try { void board.post(eng.id, { author: { role: 'system', name: '调度台' }, kind: 'note', text: `自动化事件处理失败：${shortText(error && error.message ? error.message : error, 300)}` }) } catch { /* 观察者失败不外溢 */ }
    })
  }

  const ready = Promise.all([store.init(), configStore.init(), board.init(), tasks.init(), trace.init()])
    .then(async () => {
      try { await squad.migrateCoreRoles() } catch (error) {
        ctx.logger?.warn?.(`[dsh-venery] 常设席位迁移失败：${error && error.message ? error.message : error}`)
      }
      try { await squad.upgradeScoutPrompt() } catch (error) {
        ctx.logger?.warn?.(`[dsh-venery] scout Nday 提示词升级失败：${error && error.message ? error.message : error}`)
      }
      try { await squad.upgradeWebPrompt() } catch (error) {
        ctx.logger?.warn?.(`[dsh-venery] web 提示词升级失败：${error && error.message ? error.message : error}`)
      }
      try { await squad.upgradeStaffPrompt() } catch (error) {
        ctx.logger?.warn?.(`[dsh-venery] staff 提示词升级失败：${error && error.message ? error.message : error}`)
      }
      try { await customModels.syncCurrent() } catch (error) {
        ctx.logger?.warn?.(`[dsh-venery] 自定义模型挂载失败：${error && error.message ? error.message : error}`)
      }
      mcp.sync(configStore.get())
      return true
    })
    .catch((error) => {
      ctx.logger?.error?.(`[dsh-venery] 初始化失败：${error && error.message ? error.message : error}`)
      return false
    })

  ctx.effect(() => configStore.onChange((value) => {
    try {
      mcp.sync(value)
      hub.broadcast({ type: 'config', keys: configStore.keyPresence(), models: value.models })
    } catch { /* 配置观察者不外溢 */ }
  }))

  ctx.effect(() => cockpit.install())
  ctx.effect(() => squad.install())
  /* 上下文溢出：调用 DSH 自带的正常压缩；有有效结果后重试。 */
  ctx.effect(() => ctx.on('agent/request-error', async (payload, next) => {
    if (!isContextWindowError(payload.failure) || (payload.signal && payload.signal.aborted)) return next()
    try {
      const recovered = await recoverContextOverflow(ctx, payload.agent, payload.failure, payload.signal)
      if (recovered) {
        ctx.logger?.warn?.('[dsh-venery] 模型上下文溢出：已通过 ctx.compaction 压缩历史，正在重试')
        return { kind: 'retry' }
      }
    } catch (error) {
      ctx.logger?.warn?.(`[dsh-venery] 上下文溢出压缩失败：${error && error.message ? error.message : error}`)
    }
    return next()
  }, { prepend: true }))
  /* 花名册开机先读：历史正文里的 a7 才能翻回名字 */
  void squad.loadRoster().catch(() => {})
  ctx.effect(() => brief.install())

  const actorForTool = (exec) => {
    try {
      const info = sessionInfoOf(exec) || {}
      if (typeof info.id === 'string') {
        const member = squad.memberBySessionId(info.id)
        if (member !== undefined) return { role: member.role, name: member.name, key: member.key }
        if (COMMANDER_SESSIONS.has(info.id)) return { role: 'commander', name: '总指挥' }
      }
    } catch { /* 回落到默认 */ }
    return { role: 'lead', name: '指挥席' }
  }
  /* 历史数据校正：把返工链的 followUpOf 全部指向真正的根任务 */
  void (async () => {
    try {
      const listed = await store.list()
      for (const row of listed) {
        const tasks = await tasks.raw(row.id)
        const byId = new Map(tasks.map((t) => [t.id, t]))
        let changed = false
        for (const task of tasks) {
          let cursor = task
          let rootId = task.id
          const seen = new Set([task.id])
          for (let depth = 0; depth < 50; depth += 1) {
            const parentId = asText(cursor.followUpOf)
            if (parentId === '') break
            const parent = byId.get(parentId)
            if (parent === undefined || seen.has(parent.id)) { rootId = parentId; break }
            seen.add(parent.id)
            rootId = parent.id
            cursor = parent
          }
          if (asText(task.followUpOf) !== '' && task.followUpOf !== rootId) {
            task.followUpOf = rootId
            changed = true
          }
        }
        if (changed) await tasks.save(row.id, tasks)
      }
    } catch { /* 校正失败不影响启动 */ }
  })()
  registerTools(ctx, store, cfg, bindings, configStore, trace, actorForTool, browsers, meeting, squad)
  registerCollabTools(ctx, { store, cfg, configStore, hub, board, tasks, squad, browser, automation, cockpit, bindings, browsers, meeting, runner, audit, trace })

  /* 内置 bash 工具同样纳入「所有命令留痕」 */
  ctx.effect(() => ctx.on('tools/result', (exec, result) => {
    try {
      if (exec === null || exec === undefined || exec.name !== 'bash') return
      const args = exec.arguments !== null && typeof exec.arguments === 'object' ? exec.arguments : {}
      const command = asText(args.command)
      if (command === '') return
      const info = sessionInfoOf(exec)
      let engagementId
      for (const key of [info.id, info.parent]) {
        if (typeof key === 'string' && bindings.has(key)) { engagementId = bindings.get(key); break }
      }
      if (engagementId === undefined) {
        for (const state of cockpit.sessions.values()) {
          if (state.sessionId === info.id) { engagementId = state.engagementId; break }
        }
      }
      if (engagementId === undefined) return
      const text = contentText(result && result.content)
      const failed = Boolean(result && result.isError)
      const cmdId = `s${Date.now().toString(36)}`
      const cwd = asText(args.workdir) || asText(info.cwd) || cfg.root
      const outputPath = join(store.cmdDir, engagementId, `${cmdId}.log`)
      const body = [
        `# command : ${command}`,
        `# tool    : bash${failed ? ' (error)' : ''}`,
        `# cwd     : ${cwd}`,
        `# started : ${nowIso()}`,
        '',
        '## output',
        text,
        '',
      ].join('\n')
      ensureDir(join(store.cmdDir, engagementId))
        .then(() => writeFile(outputPath, body, 'utf8'))
        .then(() => store.mutate(engagementId, (draft) => {
          draft.commands.push({
            id: cmdId,
            command,
            purpose: asText(args.description) || undefined,
            cwd,
            startedAt: nowIso(),
            exitCode: failed ? null : 0,
            durationMs: 0,
            timedOut: false,
            aborted: false,
            stdoutBytes: text.length,
            stderrBytes: 0,
            truncated: false,
            outputPath,
            source: 'bash',
            sessionId: info.id,
            nodeIds: [],
            tail: text.slice(-4000),
            stderrTail: '',
          })
        }))
        .then(() => trace.push(engagementId, {
          kind: 'command',
          actor: { role: 'system', name: 'bash' },
          title: `${failed ? '✗' : '✓'} ${shortText(command, 120)}`,
          detail: asText(args.description) || '',
          refs: { commandId: cmdId },
          meta: { source: 'bash', bytes: text.length, input: shortText(command, 600), out: shortText(text, 600) },
        }))
        .catch(() => { /* 记录失败不影响主流程 */ })
    } catch { /* 观察者不得影响工具调用 */ }
  }))

  ctx.effect(() => {
    const timer = setInterval(() => { void automation.tick() }, 60000)
    /* 停滞检测：每 3 分钟看一次，真的卡住才开会 */
    const meetingTimer = setInterval(() => { void meeting.tick().catch(() => {}) }, 180000)
    /* 断点心跳：每 2 分钟刷新一次；心跳超时自动存断点并标记「已中断」 */
    const runnerTimer = setInterval(() => { void runner.tick().catch(() => {}) }, 120000)
    /* 总指挥/参谋常驻：每分钟确认一次在岗，缺了就补 */
    const coreTimer = setInterval(() => {
      void (async () => {
        const eng = await store.activeEngagement()
        if (eng === undefined) return
        await squad.ensureCore(eng.id)
      })().catch(() => {})
    }, 60000)
    /* 这几个定时器必须全部清掉：漏一个，插件重载后旧实例会继续每分钟补建
       总指挥/参谋、开会议、存断点，表现就是「凭空多出几个总指挥」。 */
    return () => {
      clearInterval(timer)
      clearInterval(meetingTimer)
      clearInterval(runnerTimer)
      clearInterval(coreTimer)
    }
  })

  ctx.effect(() => {
    const timer = setInterval(() => { void squad.pruneIdle(900000) }, 5 * 60000)
    return () => clearInterval(timer)
  })

  const deps = { store, cfg, configStore, hub, cockpit, mcp, board, tasks, trace, squad, browser, automation, meeting, runner, audit, ctx, browsers, brief, customModels }

  ctx.inject(['webServer'], (host) => {
    host.effect(() => host.webServer.register({
      kind: 'exact',
      path: '/recon/stream',
      handler: async (req, res) => {
        if (req.method !== 'GET') { sendJson(res, 405, { ok: false, error: 'GET only' }); return }
        if (!sameOrigin(req)) { sendJson(res, 403, { ok: false, error: 'cross-origin 被拒绝' }); return }
        await ready
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
          'x-accel-buffering': 'no',
        })
        res.write('retry: 3000\n\n')
        res.write(`data: ${JSON.stringify({ type: 'hello', t: Date.now(), root: store.root })}\n\n`)
        hub.add(res)
      },
    }))

    /* 浏览器截图 / HTML 转储的读取口（限制在 recon 根目录内） */
    host.effect(() => host.webServer.register({
      kind: 'exact',
      path: '/recon/asset',
      handler: async (req, res) => {
        if (req.method !== 'GET') { sendJson(res, 405, { ok: false, error: 'GET only' }); return }
        if (!sameOrigin(req)) { sendJson(res, 403, { ok: false, error: 'cross-origin 被拒绝' }); return }
        let pathname = ''
        try { pathname = new URL(req.url || '/', 'http://x').searchParams.get('p') || '' } catch { pathname = '' }
        const target = resolve(pathname)
        /* 只允许展示浏览器截图和用户上传产物；config.json、browser state、
           chat、commands、board 等派生数据不能通过这个只读口泄露。 */
        const allowedRoots = [join(cfg.root, 'browser'), join(cfg.root, 'uploads')].map((root) => resolve(root))
        const allowed = allowedRoots.some((root) => target === root || target.startsWith(`${root}${sep}`))
        if (pathname === '' || !allowed) {
          sendJson(res, 403, { ok: false, error: '路径不在可读取的 browser/uploads 目录内' })
          return
        }
        const lowerTarget = target.toLowerCase()
        const imageType = lowerTarget.endsWith('.png') ? 'image/png'
          : lowerTarget.endsWith('.jpg') || lowerTarget.endsWith('.jpeg') ? 'image/jpeg'
            : lowerTarget.endsWith('.webp') ? 'image/webp'
              : lowerTarget.endsWith('.gif') ? 'image/gif'
                : ''
        const underBrowser = target.startsWith(`${resolve(cfg.root, 'browser')}${sep}`)
        if (underBrowser && imageType === '') {
          sendJson(res, 403, { ok: false, error: 'browser 目录只允许读取图片截图' })
          return
        }
        try {
          const body = await readFile(target)
          const headers = {
            'content-type': imageType || 'application/octet-stream',
            'cache-control': 'no-store',
            'content-length': body.length,
            'x-content-type-options': 'nosniff',
          }
          if (imageType === '') headers['content-disposition'] = `attachment; filename="${encodeURIComponent(target.split(sep).pop() || 'download')}"`
          res.writeHead(200, headers)
          res.end(body)
        } catch {
          sendJson(res, 404, { ok: false, error: '文件不存在' })
        }
      },
    }))

    host.effect(() => host.webServer.register({
      kind: 'exact',
      path: '/recon/api',
      handler: async (req, res) => {
        await ready
        await makeHandler(deps)(req, res)
      },
    }))
  })

  if (cfg.systemPrompt) {
    ctx.inject(['systemPrompt'], (host) => {
      host.effect(() => host.systemPrompt.section({
        name: 'venery',
        order: 4900,
        text: () => withCommonPrompt(configStore.get(), [
          '## 狩猎（dsh-venery）',
          '',
          '本会话装有红队信息收集插件：所有采集结果都写进一份可视化图谱，用户在 Harness 侧栏「狩猎」页面实时查看（节点=资产，边=关系，菱形=漏洞，左右两栏滚动命令与漏洞，底部还有驾驶舱对话）。',
          '',
          '工作流（信息收集类任务必须照做，不要只在对话里贴结果）：',
          '1. `recon_start` 建靶标 + 落起始资产（用户给的目标）；一次演练只调用一次。',
          '2. `recon_run` 执行 shell 命令（Linux 用 bash、Windows 用 cmd；子域枚举、端口、指纹、目录、POC 验证…），每条都带 purpose；返回 commandId。',
          '3. 命令产出立即落图：少量用 `recon_asset`/`recon_link`/`recon_vuln`，批量用 `recon_ingest`（nodes/edges/vulns 三个数组），并把 commandId 写进证据字段。',
          '4. 「A 发现 B」必须连边：`parent` + `edge`（subdomain_of / resolves_to / has_port / exposes / http_on / links_to / uses_tech / leaks / credentialed_by …）。',
          '5. 任何可验证的风险都要 `recon_vuln` 登记（severity 按实际影响，别一律 high）；验证通过用 `recon_update` 改 verified，误报改 false-positive。',
          '6. 不确定做到哪一步时用 `recon_view` 看图谱现状，再决定下一个动作。',
          '',
          '协作能力（多智能体并行）：',
          '- `recon_board`：团队看板。发现/猜想/任务/结论都写进去（kind + 节点/漏洞/命令引用），所有 Agent 共享。',
          '- `recon_squad`：派独立 Agent 并行干活（role=scout/web/reverser/intranet/qa 或临时角色），不用等当前任务结束；总指挥/参谋是常设席位，不能 spawn，要派活用 action=task。`action=group` 可把专业角色加入某个成员的小组。',
          '- `recon_group`：执行成员遇到跨职责卡点时 `action=request` 请总指挥派专业角色；编组后 `action=ask` 串行求助并等待回复，组内消息共享；总指挥用 `action=close` 让全组各自交接后回收。',
          '- `recon_memory`：读取全局记忆；只有总指挥/参谋可以 add，且只写项目概况、目标、环境、攻击手法、已确认漏洞、凭据等关键事实。',
          '- `recon_skill`：列出/加载本机成熟技能（list/load），按角色 skills 指定的技能名读取完整正文，不要凭记忆猜用法。',
          '  spawn 时可指定 `name`（代号）、`prompt`（专属指令）、`skills`（点开哪些技能）、`asRole/roleName/rolePrompt`（临时开新兵种）。',
          '总指挥原则：能派就派。自己做扫描是最差选择，只在没有合适角色且一条命令能收尾时才亲自执行。',
          '- `recon_org`：看编制与在岗、招募（含 developer 之类临时角色）、回收、出作战简报。',
          '- `recon_task`：任务账本。总指挥拆任务（写清目标与验收标准）→ 成员执行附证据 → 验收 accept/reject，驳回自动生成返工任务回总指挥。',
          '图谱不限类型：assets 的 kind 可以自定任何新类别（api/db/queue/k8s/sbom/osint-profile/leak/file/cookie/session…），',
          '不要为了迁就内置清单把信息塞进 tech/note；新类型会自动配色并出现在图例与筛选里。',
          '职责边界：Web 页面操作与 Web 漏洞归 web 手；JS/APK/EXE 逆向归 reverser；内网横向/隧道/提权归 intranet；',
          '漏洞真伪与任务达标判定归 qa；方案与优先级归 staff；commander 只调度不亲自扫。',
          '- `recon_nday`：信息收集手的指纹 Nday 检索（Exploit-DB + NVD）；探测到指纹后主动查，不必等指令；只查历史漏洞库、不对目标发包，候选先写看板、实测后才 recon_vuln。',
          '- `recon_browser`：真实浏览器（Playwright+Chromium）打开页面、点击、填表、截图，登录态按靶标持久化。',
          '- `recon_asset_remove`：发现连错/判断错时归档或删除节点，并在看板留原因。',
          '- `recon_watch`：用一句话配事件触发（新资产→猎手、新漏洞→浏览器、命令结束→分析、定时巡检）。',
          '- `recon_config`：改密钥（FOFA/GitHub/Shodan…）、模型三档、角色、提示词、记忆、技能、MCP。用户口头说改配置时直接调它。',
          '事件触发默认已开：新资产自动派猎手、新漏洞自动派浏览器（规则在页面「控制台 → 自动化」里调）。',
          '',
          '规矩：每条命令都留痕、每个资产都上图、每个结论都有 commandId 证据。',
          '用户在「狩猎」驾驶舱里也可能直接下指令，那是另一个执行者，共享同一份事实库。',
        ].join('\n')),
      }))
    })
  }

  ctx.effect(() => () => {
    try { hub.closeAll() } catch { /* 已关 */ }
    void cockpit.dispose()
    void squad.disposeAll()
    mcp.dispose()
  })
}
