window.__ModuleLoader__.load({
  id: 'dsh-venery',
  factory(require) {
    const React = require('react')
    const { useState, useEffect, useMemo, useRef, useCallback, useReducer } = React
    const h = React.createElement

    const NS = 'reconGraph'
    const TIERS = ['deep', 'fast', 'vision']
    const MODEL_CHOICES = [...TIERS, 'dsh']
    const THINKING_LEVELS = ['off', 'low', 'medium', 'high']
    const THINKING_LABEL = { off: 'Off', low: 'Low', medium: 'Medium', high: 'High' }
    const TIER_LABEL = { deep: 'Deep', fast: 'Flash', vision: 'Vision', dsh: 'Follow DSH' }
    const asTextLike = (value) => String(value === undefined || value === null ? '' : value).trim()
    const normalizeMemoryList = (value) => (Array.isArray(value) ? value : []).map((item) => {
      if (typeof item === 'string') return { title: '记忆', content: item }
      if (item !== null && typeof item === 'object') {
        return { ...item, title: asTextLike(item.title) || '记忆', content: String(item.content || '') }
      }
      return { title: '记忆', content: '' }
    })
    const mcpLineOf = (row) => {
      const name = asTextLike(row.name) || 'server'
      const simpleKeys = new Set(['name', 'transport', 'command', 'args', 'url', 'enabled'])
      const hasComplex = (row.env && typeof row.env === 'object' && Object.keys(row.env).length > 0)
        || (row.headers && typeof row.headers === 'object' && Object.keys(row.headers).length > 0)
        || Object.keys(row).some((key) => simpleKeys.has(key) === false)
        || row.enabled === false
      if (hasComplex) {
        const payload = { ...row }
        delete payload.name
        return `${name} = ${JSON.stringify(payload)}`
      }
      if ((row.transport || '') === 'streamable-http' || (row.url || '') !== '') return `${name} = ${row.url || ''}`
      return `${name} = ${[row.command || '', ...(Array.isArray(row.args) ? row.args : [])].join(' ').trim()}`
    }
    const parseMcpLines = (text) => {
      const rows = []
      for (const line of String(text || '').split('\n')) {
        const trimmed = line.trim()
        if (trimmed === '') continue
        const eq = trimmed.indexOf('=')
        if (eq <= 0) continue
        const name = trimmed.slice(0, eq).trim()
        const rest = trimmed.slice(eq + 1).trim()
        if (name === '' || rest === '') continue
        if (rest.startsWith('{')) {
          try {
            const parsed = JSON.parse(rest)
            if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
              rows.push({ ...parsed, name, enabled: parsed.enabled !== false })
              continue
            }
          } catch { /* 落回简单格式 */ }
        }
        if (/^https?:\/\//i.test(rest)) rows.push({ name, transport: 'streamable-http', url: rest, enabled: true })
        else {
          const parts = rest.split(/\s+/)
          rows.push({ name, transport: 'stdio', command: parts[0], args: parts.slice(1), enabled: true })
        }
      }
      return rows
    }
    const MODEL_PROTOCOLS = [
      { id: 'openai-completions', label: 'OpenAI 兼容 / Responses API' },
      { id: 'anthropic-messages', label: 'Anthropic 兼容' },
    ]

    /* ───────────────────────── 文案 ───────────────────────── */
    const DICT = {
      zh: {
        title: '狩猎', cockpit: '驾驶舱', subtitle: '资产 · 关系 · 漏洞 · 命令 · 对话',
        assets: '资产', vulns: '漏洞', commands: '命令', settings: '控制台',
        search: '搜索资产 / IP / 漏洞关键字', refresh: '刷新', fit: '适应',
        showVulns: '漏洞节点', exportJson: '导出', newEngagement: '新建靶标', deleteEngagement: '删除靶标',
        newEngagementName: '新靶标名称', deleteEngagementConfirm: '删除整个靶标及其资产/漏洞/命令/对话记录？',
        empty: '还没有任何图谱数据', emptyHint: '在下面驾驶舱里说一句「从这里开始收集」，或者让主会话调用 recon_start。',
        loading: '读取图谱…', selectHint: '点节点或列表查看详情', engagement: '靶标',
        commandFeed: '命令流', vulnFeed: '漏洞列表', live: 'LIVE', paused: '已暂停',
        collapse: '折叠子树', expand: '展开', collapseAll: '全部折叠', expandAll: '全部展开',
        provenance: '来源命令', viewOutput: '看输出', noProvenance: '还没有关联命令（可让 AI 用 recon_run 的 node 参数挂证据）',
        nodeDetail: '节点详情', vulnDetail: '漏洞详情', evidence: '证据',
        chatPlaceholder: '让 AI 继续收集什么…（Enter 发送 · Shift+Enter 换行 · 可拖入文件 / 粘贴截图 / 点📎选文件）',
        send: '发送', stop: '停止', thinking: '思维流', showThinking: '显示思维', thinkingEmpty: '等待模型开始思考…',
        tierDeep: 'Deep', tierFast: 'Flash', tierVision: 'Vision', tierDsh: '跟随 DSH', model: '模型', tier: '档位',
        connecting: '连接中', connected: '已连接', offline: '未连接', streamPaused: '事件流断开，已切轮询',
        status: '状态', severity: '等级', endpoint: '位置', param: '参数', payload: 'Payload',
        description: '描述', note: '备注', tech: '指纹', tags: '标签', degree: '关联',
        exitCode: '退出码', duration: '耗时', cwd: '工作目录', purpose: '意图', source: '来源', startedAt: '时间',
        outputPath: '输出文件', stderr: 'stderr', noOutput: '（无输出）', markVerified: '已验证',
        markFalse: '误报', markOpen: '打开', markFixed: '已修复', delete: '删除', confirmDelete: '确认删除？',
        dockChat: '对话', dockBoard: '看板', dockSquad: '队伍',
        boardEmpty: '看板还空着：AI 的发现、猜想、任务都会写在这里。', boardKind: '类型', boardPost: '发布',
        boardHint: '写下发现或猜想，所有 Agent 都能看到…',
        squadEmpty: '还没有队员。派一个出去并行干活吧。', squadRole: '角色', squadTask: '任务',
        squadSpawn: '派遣', squadStop: '停止', squadRemove: '移除', squadAsk: '追加任务',
        runningAgents: '在跑', agentIdle: '待命', agentDone: '收工', agentStarting: '启动中',
        archive: '归档', archiveReason: '归档原因', archived: '已归档', restore: '恢复',
        shots: '截图', openShot: '查看截图', boardRefNode: '节点', boardRefVuln: '漏洞', boardRefCmd: '命令',
        rolesHint: '本页统一管理通用提示词、常设席位与队员岗位。总指挥就是最高统领：驾驶舱 lead 与编队总指挥共用同一个总指挥提示词；参谋同样共用参谋提示词。常设席位与队员岗位都可以配置提示词、技能、模型与专属 MCP。',
        commonPrompt: '通用提示词',
        commonHint: '注入所有 Agent（驾驶舱、汇报席、主会话与每名队员，含自动化/会议/续跑派发的成员）：最终提示词 = 通用提示词 + 自身提示词。留空不注入；主会话仅在开启插件工作流注入时生效。',
        commonPlaceholder: '例如：只在授权范围内行动；所有结论必须带 commandId；拿不准的标 info。',
        cockpitRole: '驾驶舱总指挥（lead）',
        coreSeats: '常设席位（总指挥 / 参谋）',
        coreSeatsHint: '每个靶标固定各一个，自动在岗、不会被回收，也不能被召唤为队员；这里只改他们的人设、模型、技能与 MCP。',
        squadRoles: '队员岗位（可派遣）',
        tabAutomation: '并发与自动化', automationHint: '先设总并发与自动化独立并发上限；自动化任务超过自己的上限时会排队。下面配置事件触发规则。',
        tabMeeting: '轨迹会议与交接',
        meetingHint: '轨迹最高显示数量；全员会议采用周期审查：任务活动期间每 N 分钟检查，只在只剩总指挥/参谋且都空闲时询问总指挥；回复 STUCK/卡壳才自动召开会议，mission close 后停止审查。',
        meetingReview: '周期审查（分钟）', meetingRounds: '最多自动召开轮次',
        handoverEnabled: '离职交接', handoverTimeout: '交接等待上限（秒）', handoverSkill: '交接输出',
        automationEnabled: '是否启用自动化', maxAgents: '最大成员数（总指挥/参谋除外）', maxAutomationAgents: '自动化独立并发上限', automationRules: '事件规则', ruleAdd: '加规则', ruleOn: '事件',
        ruleRole: '角色', ruleTier: '模型', ruleCooldown: '冷却(ms)', ruleTask: '任务模板', ruleKinds: '资产类型',
        kindFinding: '发现', kindHypothesis: '猜想', kindTask: '任务', kindConclusion: '结论', kindNote: '备注',
        tabModels: '模型', tabKeys: '密钥', tabRole: '角色与提示词', tabMemory: '记忆', tabSkills: '技能', tabMcp: 'MCP', tabUi: '外观',
        save: '保存', saved: '已保存', saving: '保存中…', apply: '应用', add: '添加', remove: '移除',
        keysHint: '密钥以明文写在本机 $DSH_HOME/recon/config.json（权限 0600，未加密），并以环境变量注入 recon_run 的命令环境。',
        envHint: '额外环境变量，每行 KEY=VALUE',
        modelHint: '先添加模型并给它起个名字；然后 Deep / Flash / Vision 各自从下拉里选这个名字，选中即把它的 provider/model/思考深度应用到该档；留空跟随 DSH。',
        mcpHint: 'stdio 填 command + args（逗号分隔）；streamable-http 填 url。保存后立即向 mcpManager 注册。',
        mcpStatus: 'MCP 运行时状态', noSkills: '没有可列出的技能', memoryEmpty: '还没有记忆条目',
        roleName: '角色名', mission: '使命', rules: '规则（每行一条）', extraPrompt: '驾驶舱附加指令（只影响 lead）',
        customModels: '自定义模型', customModelsHint: '添加模型（名称 → Base URL → API Key → 协议 → 模型 id → 思考深度）。模型 id 可用「获取模型」自动从 /models 拉取；保存后注册到 DSH；三档都留空时全部跟随 DSH。', addModel: '添加模型', apiKey: 'API Key', baseUrl: 'Base URL', modelId: '模型 id', thinkingDepth: '思考深度', protocol: '协议', savedKey: '已保存，留空不修改', needKey: '必填', keySaved: 'Key 已保存', keyMissing: 'Key 未保存', route: '路由',
        accent: '主色', glow: '光晕', grid: '网格', scanlines: '扫描线', danger: 'danger',
        tierChanged: '已切换档位', nodesHidden: '隐藏', viewFull: '全屏', close: '关闭',
        userLabel: '你', aiLabel: '驾驶舱', toolLabel: '工具', copyCmd: '复制命令',
        thinkingCollapsed: '思维已折叠', turnEnd: '本轮完成', turnAborted: '已中断', errorLabel: '错误',
      },
      en: {
        title: 'Venery', cockpit: 'Cockpit', subtitle: 'assets · links · vulns · commands · chat',
        assets: 'Assets', vulns: 'Vulns', commands: 'Commands', settings: 'Console',
        search: 'Search assets / IP / vulnerabilities', refresh: 'Refresh', fit: 'Fit',
        showVulns: 'Vuln nodes', exportJson: 'Export', newEngagement: 'New target', deleteEngagement: 'Delete target',
        newEngagementName: 'New target name', deleteEngagementConfirm: 'Delete this target with its assets, vulns, commands and chat?',
        empty: 'No graph data yet', emptyHint: 'Ask the cockpit below to start collecting, or have the main session call recon_start.',
        loading: 'Loading…', selectHint: 'Pick a node or a row', engagement: 'Target',
        commandFeed: 'Command feed', vulnFeed: 'Vuln list', live: 'LIVE', paused: 'PAUSED',
        collapse: 'Collapse subtree', expand: 'Expand', collapseAll: 'Collapse all', expandAll: 'Expand all',
        provenance: 'Provenance', viewOutput: 'View output', noProvenance: 'No linked command yet',
        nodeDetail: 'Node', vulnDetail: 'Vulnerability', evidence: 'Evidence',
        chatPlaceholder: 'What should the AI collect next… (Enter to send · Shift+Enter newline · drop files / paste screenshots / 📎 to pick)',
        send: 'Send', stop: 'Stop', thinking: 'Reasoning', showThinking: 'Show reasoning', thinkingEmpty: 'Waiting for the model…',
        tierDeep: 'Deep', tierFast: 'Flash', tierVision: 'Vision', tierDsh: 'Follow DSH', model: 'Model', tier: 'Tier',
        connecting: 'connecting', connected: 'live', offline: 'offline', streamPaused: 'stream lost, polling',
        status: 'Status', severity: 'Severity', endpoint: 'Endpoint', param: 'Param', payload: 'Payload',
        description: 'Description', note: 'Note', tech: 'Tech', tags: 'Tags', degree: 'Links',
        exitCode: 'Exit', duration: 'Duration', cwd: 'CWD', purpose: 'Purpose', source: 'Source', startedAt: 'Time',
        outputPath: 'Output', stderr: 'stderr', noOutput: '(no output)', markVerified: 'Verified',
        markFalse: 'False +', markOpen: 'Open', markFixed: 'Fixed', delete: 'Delete', confirmDelete: 'Delete?',
        dockChat: 'Chat', dockBoard: 'Board', dockSquad: 'Squad',
        boardEmpty: 'Board is empty: findings, hypotheses and tasks from every agent land here.', boardKind: 'Kind', boardPost: 'Post',
        boardHint: 'Write a finding or a hypothesis the whole team can see…',
        squadEmpty: 'No teammates yet — dispatch one to work in parallel.', squadRole: 'Role', squadTask: 'Task',
        squadSpawn: 'Dispatch', squadStop: 'Stop', squadRemove: 'Remove', squadAsk: 'Add task',
        runningAgents: 'running', agentIdle: 'idle', agentDone: 'done', agentStarting: 'starting',
        archive: 'Archive', archiveReason: 'Reason', archived: 'archived', restore: 'Restore',
        shots: 'Shots', openShot: 'Open', boardRefNode: 'node', boardRefVuln: 'vuln', boardRefCmd: 'cmd',
        rolesHint: 'One page for the common prompt, the standing seats and squad roles. The commander is the single highest leader: the cockpit lead and the squad commander share the same commander prompt; the staff seat uses the staff prompt. Both standing seats and member roles can configure prompt, skills, model and MCP.',
        commonPrompt: 'Common prompt',
        commonHint: 'Injected into every agent (cockpit, briefing seat, main session and every member, including automation/meeting/resume dispatches): final prompt = common prompt + its own prompt. Empty disables it; the main session only receives it while the plugin workflow injection is enabled.',
        commonPlaceholder: 'e.g. Stay inside the authorized scope; every conclusion cites a commandId; mark uncertain items as info.',
        cockpitRole: 'Cockpit commander (lead)',
        coreSeats: 'Standing seats (commander / staff)',
        coreSeatsHint: 'Exactly one each per target, always on duty, never released, and never summonable as a member; edit only their persona, model, skills and MCP here.',
        squadRoles: 'Member roles (dispatchable)',
        tabAutomation: 'Concurrency & automation', automationHint: 'Set total concurrency and the separate automation concurrency cap; excess automation jobs queue. Event rules follow below.',
        tabMeeting: 'Trace, meetings & handover',
        meetingHint: 'Max trace rows to render; all-hands review runs every N minutes while a mission is active, only when commander/staff are the only idle seats; STUCK triggers a meeting, mission close stops reviews.',
        meetingReview: 'Review interval (minutes)', meetingRounds: 'Max auto meeting rounds',
        handoverEnabled: 'Handover on release', handoverTimeout: 'Handover wait (seconds)', handoverSkill: 'Handover output',
        automationEnabled: 'Automation enabled', maxAgents: 'Max members (excluding core)', maxAutomationAgents: 'Automation concurrency cap', automationRules: 'Event rules', ruleAdd: 'Add rule', ruleOn: 'Event',
        ruleRole: 'Role', ruleTier: 'Model', ruleCooldown: 'Cooldown(ms)', ruleTask: 'Task template', ruleKinds: 'Asset kinds',
        kindFinding: 'finding', kindHypothesis: 'hypothesis', kindTask: 'task', kindConclusion: 'conclusion', kindNote: 'note',
        tabModels: 'Models', tabKeys: 'Keys', tabRole: 'Roles & prompts', tabMemory: 'Memory', tabSkills: 'Skills', tabMcp: 'MCP', tabUi: 'Look',
        save: 'Save', saved: 'Saved', saving: 'Saving…', apply: 'Apply', add: 'Add', remove: 'Remove',
        keysHint: 'Keys are stored in plain text in $DSH_HOME/recon/config.json (mode 0600, not encrypted) and exported as env vars to recon_run.',
        envHint: 'Extra env vars, one KEY=VALUE per line',
        modelHint: 'Add a model and give it a name; then pick that name under Deep / Flash / Vision. The selection applies its provider/model/thinking depth to that tier; empty follows DSH.',
        mcpHint: 'stdio: command + args (comma separated); streamable-http: url. Saved entries register immediately.',
        mcpStatus: 'MCP runtime', noSkills: 'No skills listed', memoryEmpty: 'No memory entries',
        roleName: 'Role', mission: 'Mission', rules: 'Rules (one per line)', extraPrompt: 'Cockpit extra instructions (lead only)',
        customModels: 'Custom models', customModelsHint: 'Add a model (name → Base URL → API key → protocol → model id → thinking depth). Use Fetch models to auto-load /models; it registers into DSH on save; empty tiers follow DSH.', addModel: 'Add model', apiKey: 'API Key', baseUrl: 'Base URL', modelId: 'Model id', thinkingDepth: 'Thinking depth', protocol: 'Protocol', savedKey: 'Saved — leave blank to keep', needKey: 'Required', keySaved: 'Key saved', keyMissing: 'Key missing', route: 'Route',
        accent: 'Accent', glow: 'Glow', grid: 'Grid', scanlines: 'Scanlines', danger: 'danger',
        tierChanged: 'tier changed', nodesHidden: 'hidden', viewFull: 'Full', close: 'Close',
        userLabel: 'You', aiLabel: 'Cockpit', toolLabel: 'tool', copyCmd: 'Copy',
        thinkingCollapsed: 'reasoning hidden', turnEnd: 'turn complete', turnAborted: 'aborted', errorLabel: 'error',
      },
    }

    /* ───────────────────────── 配色 ───────────────────────── */
    const KIND_COLOR = {
      root: '#a78bfa', domain: '#38bdf8', subdomain: '#22d3ee', ip: '#34d399', cidr: '#0ea5e9',
      host: '#0ea5e9', port: '#fbbf24', service: '#fb923c', url: '#c084fc', endpoint: '#e879f9',
      credential: '#f87171', account: '#fb7185', employee: '#facc15', cert: '#2dd4bf',
      repo: '#a78bfa', bucket: '#06b6d4', tech: '#94a3b8', note: '#64748b',
      source: '#f472b6', fingerprint: '#e879f9', secret: '#f43f5e',
    }
    /* 未知类型：按名字稳定哈希到一组高区分度颜色，保证自定义 kind 也有专属色 */
    const KIND_FALLBACK = [
      '#7dd3fc', '#a3e635', '#fda4af', '#c4b5fd', '#5eead4', '#fcd34d',
      '#f0abfc', '#93c5fd', '#bae6fd', '#fdba74', '#86efac', '#d8b4fe',
    ]
    const colorOfKind = (kind) => {
      const key = String(kind || 'note')
      if (KIND_COLOR[key] !== undefined) return KIND_COLOR[key]
      let hash = 0
      for (let index = 0; index < key.length; index += 1) hash = (hash * 31 + key.charCodeAt(index)) % 99991
      return KIND_FALLBACK[hash % KIND_FALLBACK.length]
    }
    const SEV_COLOR = { critical: '#f43f5e', high: '#fb923c', medium: '#facc15', low: '#34d399', info: '#64748b' }
    const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    const DASH_EDGES = new Set(['discovered_from', 'related', 'uses_tech', 'links_to'])

    /* ───────────────────────── 样式 ───────────────────────── */
    const CSS = `
.rc2{--rc-accent:#22d3ee;--rc-accent-dim:rgba(34,211,238,.14);--rc-danger:#f43f5e;
  position:relative;display:flex;flex-direction:column;height:100%;min-height:0;overflow:hidden;
  background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:13px;
  font-variant-numeric:tabular-nums}
.rc2[data-accent="violet"]{--rc-accent:#a78bfa;--rc-accent-dim:rgba(167,139,250,.14)}
.rc2[data-accent="lime"]{--rc-accent:#a3e635;--rc-accent-dim:rgba(163,230,53,.14)}
.rc2[data-accent="amber"]{--rc-accent:#fbbf24;--rc-accent-dim:rgba(251,191,36,.14)}
.rc2-glow{box-shadow:0 0 0 1px color-mix(in srgb,var(--rc-accent) 22%,transparent),
  0 0 24px -8px color-mix(in srgb,var(--rc-accent) 45%,transparent)}
.rc2-scan{position:absolute;inset:0;pointer-events:none;z-index:3;opacity:.35;
  background:repeating-linear-gradient(180deg,rgba(255,255,255,.03) 0 1px,transparent 1px 3px);
  mix-blend-mode:screen}
.rc2-top{display:flex;align-items:center;gap:10px;padding:8px 12px;flex:0 0 auto;
  border-bottom:1px solid color-mix(in srgb,var(--rc-accent) 26%,var(--dsw-alias-border-l1));
  background:linear-gradient(180deg,color-mix(in srgb,var(--rc-accent) 7%,transparent),transparent),
    var(--dsw-alias-bg-layer-1);flex-wrap:wrap;z-index:4}
.rc2-brand{display:flex;align-items:center;gap:9px;min-width:0}
.rc2-logo{width:22px;height:22px;color:var(--rc-accent);filter:drop-shadow(0 0 6px color-mix(in srgb,var(--rc-accent) 60%,transparent))}
.rc2-brand h1{margin:0;font-size:13.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
.rc2-brand small{display:block;font-size:10px;letter-spacing:.16em;color:var(--dsw-alias-label-secondary);text-transform:uppercase}
.rc2-spacer{flex:1 1 auto}
.rc2-chip{display:inline-flex;align-items:center;gap:5px;height:22px;padding:0 8px;border-radius:4px;
  border:1px solid color-mix(in srgb,var(--rc-accent) 24%,var(--dsw-alias-border-l1));
  background:color-mix(in srgb,var(--rc-accent) 6%,transparent);font-size:10.5px;letter-spacing:.06em;
  text-transform:uppercase;color:var(--dsw-alias-label-secondary);white-space:nowrap}
.rc2-chip b{font-size:12px;font-weight:700;color:var(--rc-accent);font-variant-numeric:tabular-nums}
.rc2-chip.warn b{color:var(--rc-danger)}
/* 进行中的按钮文字：轻微呼吸，表示请求已发出还在等结果 */
.rc2-briefwaiting{display:inline-block;opacity:.7;font-size:11.5px;letter-spacing:.02em;
  animation:rc2-busy-pulse 1.2s ease-in-out infinite}
.rc2-busy{display:inline-block;animation:rc2-busy-pulse 1s ease-in-out infinite}
@keyframes rc2-busy-pulse{0%,100%{opacity:.55}50%{opacity:1}}
/* 可点击的提问芯片：整句中文，别用大写与字间距 */
button.rc2-chip{cursor:pointer;text-transform:none;letter-spacing:0;font-size:11px;height:24px;padding:0 9px}
button.rc2-chip:hover{color:var(--rc-accent);border-color:var(--rc-accent);
  background:color-mix(in srgb,var(--rc-accent) 14%,transparent)}
.rc2-btn{height:26px;padding:0 9px;border-radius:4px;cursor:pointer;font-size:11.5px;letter-spacing:.04em;
  border:1px solid color-mix(in srgb,var(--rc-accent) 22%,var(--dsw-alias-border-l1));
  background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);
  display:inline-flex;align-items:center;gap:5px;white-space:nowrap;transition:all .15s}
.rc2-btn:hover{border-color:var(--rc-accent);color:var(--rc-accent);
  box-shadow:0 0 14px -6px var(--rc-accent)}
.rc2-btn.on{background:var(--rc-accent-dim);border-color:var(--rc-accent);color:var(--rc-accent)}
.rc2-btn.ghost{background:transparent}
.rc2-btn.danger{color:var(--rc-danger);border-color:color-mix(in srgb,var(--rc-danger) 40%,transparent)}
.rc2-btn:disabled{opacity:.4;cursor:not-allowed}
.rc2-select{height:26px;border-radius:4px;font-size:12px;padding:0 6px;max-width:200px;
  border:1px solid color-mix(in srgb,var(--rc-accent) 22%,var(--dsw-alias-border-l1));
  background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary)}
.rc2-main{flex:1 1 auto;display:flex;min-height:0;position:relative}
.rc2-rail{display:flex;flex-direction:column;min-height:0;min-width:0;max-width:100%;overflow:hidden;
  background:color-mix(in srgb,var(--dsw-alias-bg-layer-1) 70%,transparent)}
.rc2-rail.left{flex:0 0 292px;min-width:0;border-right:1px solid var(--dsw-alias-border-l1)}
.rc2-projects{display:flex;align-items:center;gap:6px;margin-right:4px}
.rc2-projects .rc2-select{max-width:260px;height:24px;font-size:11.5px}
.rc2-dock.expanded{height:320px}
.rc2-splitter{flex:0 0 6px;cursor:col-resize;position:relative;background:linear-gradient(180deg,transparent 0%,rgba(34,211,238,.10) 50%,transparent 100%)}
.rc2-splitter::after{content:'';position:absolute;left:2px;top:0;bottom:0;width:2px;background:linear-gradient(180deg,transparent,rgba(34,211,238,.45),transparent);opacity:.55;transition:opacity .15s}
.rc2-splitter:hover::after{opacity:1;background:linear-gradient(180deg,transparent,var(--rc-accent),transparent)}
.rc2-hsplitter{flex:0 0 6px;cursor:row-resize;width:100%;position:relative;background:linear-gradient(90deg,transparent,rgba(34,211,238,.10),transparent)}
.rc2-hsplitter::after{content:'';position:absolute;top:2px;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,rgba(34,211,238,.45),transparent);opacity:.55}
.rc2-hsplitter:hover::after{opacity:1;background:linear-gradient(90deg,transparent,var(--rc-accent),transparent)}
.rc2-hsplit-labelled{overflow:visible}
.rc2-hsplit-tag{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);
  padding:1px 6px;border-radius:3px;font-size:9.5px;font-weight:700;letter-spacing:.03em;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap;pointer-events:none;
  color:var(--dsw-alias-label-secondary);background:rgba(2,6,23,.82);
  border:1px solid color-mix(in srgb,var(--rc-accent) 26%,transparent);
  opacity:.55;transition:opacity .15s,color .15s,border-color .15s;z-index:2}
.rc2-hsplitter:hover .rc2-hsplit-tag{opacity:1;color:var(--rc-accent);border-color:var(--rc-accent)}
.rc2-hsplitter.dock-split{flex:0 0 7px;background:linear-gradient(90deg,transparent 20%,rgba(34,211,238,.14),transparent 80%)}
.rc2-hsplitter.dock-split::before{content:'';position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);
  width:46px;height:3px;border-radius:2px;background:rgba(34,211,238,.5);box-shadow:0 0 8px rgba(34,211,238,.6)}
.rc2-hsplitter.dock-split:hover::before{background:var(--rc-accent);box-shadow:0 0 12px var(--rc-accent)}
.rc2-tree{flex:1 1 auto;overflow:auto;min-height:0;
  background-image:radial-gradient(circle at 1px 1px,rgba(34,211,238,.10) 1px,transparent 0);
  background-size:18px 18px;background-position:-1px -1px}
.rc2-tree svg{display:block}
.rc2-tree svg g{transition:opacity .12s}
.rc2-tree svg g:hover text{fill:var(--rc-accent)}
.rc2-tree svg g:hover circle{r:5.4}
.rc2-tree-detail{flex:0 0 auto;max-height:44%;overflow:auto;padding:8px;border-top:1px solid var(--dsw-alias-border-l1);
  background:color-mix(in srgb,var(--dsw-alias-bg-2) 88%,transparent)}
.rc2-legend{background:transparent;border:0;font:inherit;color:inherit;cursor:pointer;opacity:1}
.rc2-legend.off{opacity:.35;text-decoration:line-through}
.rc2-legend:hover{color:var(--rc-accent)}
.rc2-lanelegend{display:flex;flex-wrap:wrap;gap:6px;padding:3px 8px 4px;border-bottom:1px solid var(--dsw-alias-border-l1)}
.rc2-lanetag.live{color:var(--dsw-alias-label-primary)}
.rc2-lanetag i.pulse{animation:rc2TagPulse 1.15s ease-in-out infinite}
@keyframes rc2TagPulse{0%,100%{opacity:1;box-shadow:0 0 0 0 currentColor}50%{opacity:.45;box-shadow:0 0 0 2px color-mix(in srgb,currentColor 26%,transparent)}}
.rc2-lanetag{display:inline-flex;align-items:center;gap:4px;font-size:10px;color:var(--dsw-alias-fg-3)}
.rc2-lanetag i{width:7px;height:7px;border-radius:50%;display:inline-block;box-shadow:0 0 6px currentColor}
.rc2-rail.right{flex:0 0 384px;min-width:0;max-width:100%;border-left:1px solid var(--dsw-alias-border-l1)}
.rc2-feed-split{flex:0 0 auto;min-height:168px;max-height:44%}
.rc2-feed-grow{flex:1 1 auto;min-height:140px}
.rc2-vulnrow{padding:4px 7px}
.rc2-vulnrow .rc2-mono{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.rc2-panelspot{position:fixed;inset:0;z-index:70;background:rgba(3,6,11,.74);backdrop-filter:blur(6px);
  display:flex;align-items:center;justify-content:center;padding:22px}
.rc2-panelspotcard{width:min(1180px,94vw);height:auto;min-height:48vh;max-height:92vh;display:flex;flex-direction:column;
  background:linear-gradient(180deg,color-mix(in srgb,var(--rc-accent) 5%,var(--dsw-alias-bg-1)),var(--dsw-alias-bg-1) 120px);
  border:1px solid color-mix(in srgb,var(--rc-accent) 22%,var(--dsw-alias-border-l1));border-radius:14px;
  box-shadow:0 30px 90px rgba(0,0,0,.7),0 0 0 1px rgba(255,255,255,.03) inset;overflow:hidden}
.rc2-panelspothead{display:flex;align-items:center;gap:9px;padding:12px 14px;border-bottom:1px solid var(--dsw-alias-border-l1);
  background:color-mix(in srgb,var(--dsw-alias-bg-2) 70%,transparent);backdrop-filter:blur(6px)}
.rc2-panelspothead .rc2-zoom-title{font-size:14.5px;font-weight:600;letter-spacing:.2px;color:var(--dsw-alias-fg-1)}
.rc2-panelspothead .rc2-zoom-sub{font-size:11.5px;color:var(--dsw-alias-fg-3);font-family:var(--rc-mono)}
.rc2-panelspotbody{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;overflow:hidden;
  padding:0;scrollbar-width:thin}
.rc2-zoomclose{width:26px;height:26px;border-radius:50%;border:1px solid var(--dsw-alias-border-l1);background:transparent;
  color:var(--dsw-alias-fg-3);cursor:pointer;font-size:12px;line-height:1;display:flex;align-items:center;justify-content:center;transition:.12s}
.rc2-zoomclose:hover{background:var(--rc-danger);border-color:var(--rc-danger);color:#fff}

/* 放大后的可读性：轨迹 */
.rc2-panelspot .rc2-feed{overflow:auto;padding:2px 0}
.rc2-panelspot .rc2-trace{padding:10px 16px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l1) 45%,transparent);transition:background .12s}
.rc2-panelspot .rc2-trace:hover{background:color-mix(in srgb,var(--rc-accent) 6%,transparent)}
.rc2-panelspot .rc2-trace-title{font-size:13px;line-height:1.5;color:#eaf1fa;-webkit-line-clamp:unset;white-space:normal}
.rc2-panelspot .rc2-trace-detail{font-size:12px;line-height:1.65;color:#a8b8cc;-webkit-line-clamp:unset;white-space:pre-wrap;margin-top:3px}
.rc2-panelspot .rc2-trace .rc2-meta{font-size:10.5px}

/* 放大后的可读性：看板 */
.rc2-panelspot .rc2-boarditem{padding:12px 16px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l1) 45%,transparent)}
.rc2-panelspot .rc2-boarditem:hover{background:color-mix(in srgb,var(--rc-accent) 5%,transparent)}
.rc2-panelspot .rc2-boardtext{font-size:13.5px;line-height:1.82;color:#e6eef8}
.rc2-panelspot .rc2-boarditem .rc2-meta{font-size:11.5px}

/* 放大后的可读性：对话 */
.rc2-panelspot .rc2-chat{overflow:auto;padding:14px 18px;display:flex;flex-direction:column;gap:12px}
.rc2-panelspot .rc2-msg .body{font-size:13.5px;line-height:1.8;max-width:76ch}



/* markdown 表格：等宽可横滚，窄画布下不撑破容器 */
.rc2-mdtablewrap{max-width:100%;min-width:0;width:100%;overflow-x:auto;margin:4px 0;border-radius:4px;
  border:1px solid var(--dsw-alias-border-l1);background:color-mix(in srgb,var(--dsw-alias-bg-base,#0b1220) 60%,transparent)}
.rc2-mdtable{border-collapse:collapse;width:100%;font-size:11px;line-height:1.5}
.rc2-mdtable th,.rc2-mdtable td{padding:3px 8px;text-align:left;vertical-align:top;
  border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l1) 70%,transparent);white-space:nowrap}
.rc2-mdtable th{background:color-mix(in srgb,var(--rc-accent) 10%,transparent);
  color:var(--dsw-alias-label-primary);font-weight:650;position:sticky;top:0}
.rc2-mdtable tbody tr:last-child td{border-bottom:0}
.rc2-mdtable tbody tr:hover td{background:color-mix(in srgb,var(--rc-accent) 6%,transparent)}
.rc2-mdtable td.rc2-num,.rc2-mdtable th.rc2-num{text-align:right;font-variant-numeric:tabular-nums}

/* 只有思维链的轮次：折叠成一行，避免几十个空气泡把对话区刷成「一直没变」 */
.rc2-silent { margin: 4px 0; border-left: 2px solid var(--dsw-alias-border-secondary, #334155); padding-left: 6px; }
.rc2-silentbtn { width: 100%; text-align: left; background: transparent; border: 0; cursor: pointer;
  color: var(--dsw-alias-label-secondary, #94a3b8); font-size: 11px; padding: 2px 0; font-family: inherit; }
.rc2-silentbtn:hover { color: var(--rc-accent); }
.rc2-silentbody { max-height: 260px; overflow-y: auto; padding: 2px 0 4px; }
.rc2-silentrow { padding: 2px 0; font-size: 11px; }
.rc2-silentrow .rc2-reason { font-size: 11px; opacity: 0.82; white-space: pre-wrap; }

/* 放大后的可读性：漏洞列表 */
.rc2-panelspot .rc2-vulnrow{padding:11px 16px;border-bottom:1px solid color-mix(in srgb,var(--dsw-alias-border-l1) 45%,transparent);cursor:pointer;transition:background .12s}
.rc2-panelspot .rc2-vulnrow:hover{background:color-mix(in srgb,var(--rc-accent) 7%,transparent)}
.rc2-panelspot .rc2-vulnrow .rc2-mono{font-size:13px !important;line-height:1.55;color:#eaf1fa}
.rc2-panelspot .rc2-vulnrow .rc2-meta{font-size:11px}
.rc2-panelspot .rc2-sev{font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:600;letter-spacing:.3px}

/* 单条放大（命令 / 漏洞 / 看板条目）—— 始终盖在面板放大之上 */
.rc2-spot{position:fixed;inset:0;z-index:80;background:rgba(3,6,11,.78);backdrop-filter:blur(6px);
  display:flex;align-items:center;justify-content:center;padding:28px}
.rc2-spotcard{width:min(1080px,94vw);height:auto;min-height:54vh;max-height:88vh;display:flex;flex-direction:column;
  background:linear-gradient(180deg,color-mix(in srgb,var(--rc-accent) 6%,var(--dsw-alias-bg-1)),var(--dsw-alias-bg-1) 110px);
  border:1px solid color-mix(in srgb,var(--rc-accent) 26%,var(--dsw-alias-border-l1));border-radius:14px;
  box-shadow:0 32px 96px rgba(0,0,0,.72);overflow:hidden}
.rc2-spothead{display:flex;align-items:center;gap:9px;padding:12px 14px;border-bottom:1px solid var(--dsw-alias-border-l1);
  background:color-mix(in srgb,var(--dsw-alias-bg-2) 72%,transparent)}
.rc2-spothead .rc2-mono{font-size:13px;color:#eaf1fa}
.rc2-spotbody{flex:1 1 auto;min-height:0;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:12px}
.rc2-spotbody pre{white-space:pre-wrap;word-break:break-word;font-family:var(--rc-mono);font-size:12.5px;line-height:1.72;
  background:color-mix(in srgb,var(--dsw-alias-bg-2) 85%,transparent);border:1px solid var(--dsw-alias-border-l1);
  border-left:3px solid color-mix(in srgb,var(--rc-accent) 55%,transparent);border-radius:8px;padding:12px 14px;margin:0;max-height:none;color:#dbe7f5}
.rc2-spotmeta{display:flex;flex-wrap:wrap;gap:6px}
.rc2-spotbody .rc2-boardtext{font-size:13.5px;line-height:1.82;white-space:pre-wrap;color:#e6eef8;max-width:82ch}
.rc2-spotlong{font-size:13px !important;line-height:1.8 !important;padding:14px 16px !important}
.rc2-chattarget{height:22px;max-width:170px;font-size:11px}
.rc2-zoom{flex:0 0 auto;width:18px;height:16px;line-height:14px;text-align:center;padding:0;font-size:11px;
  border:1px solid var(--dsw-alias-border-l1);border-radius:3px;background:transparent;color:var(--dsw-alias-fg-3);cursor:pointer;opacity:0;transition:opacity .12s}
.rc2-item:hover .rc2-zoom,.rc2-boarditem:hover .rc2-zoom{opacity:1}
.rc2-zoom:hover{color:var(--rc-accent);border-color:var(--rc-accent)}
.rc2-modal-mask{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(4,8,14,.62);backdrop-filter:blur(2px)}
.rc2-modal{width:min(440px,86vw);border-radius:10px;border:1px solid var(--dsw-alias-border-l2);background:color-mix(in srgb,var(--dsw-alias-bg-base) 96%,transparent);box-shadow:0 18px 48px rgba(0,0,0,.55);padding:14px 16px 12px;display:flex;flex-direction:column;gap:9px}
.rc2-modal-title{font-size:13px;font-weight:600;color:var(--dsw-alias-label-primary)}
.rc2-modal-detail{font-size:11.5px;line-height:1.6;color:var(--dsw-alias-label-secondary);white-space:pre-wrap;max-height:36vh;overflow:auto}
.rc2-modal-input{width:100%;box-sizing:border-box;padding:8px 10px;border-radius:7px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:12.5px;font-family:inherit;outline:none;resize:vertical}
.rc2-modal-input:focus{border-color:color-mix(in srgb,var(--rc-accent) 62%,transparent);box-shadow:0 0 0 2px color-mix(in srgb,var(--rc-accent) 18%,transparent)}
.rc2-modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:2px}
.rc2-hud-min{padding:0;background:transparent;border:none;box-shadow:none;display:flex;align-items:center;gap:5px}
.rc2-hud-toggle{width:30px;height:30px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2);background:rgba(10,16,26,.86);color:#cfdcec;font-size:13px;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,.35)}
.rc2-hud-toggle:hover{border-color:color-mix(in srgb,var(--rc-accent) 55%,transparent);color:#fff}
.rc2-hud-badge{font:9px/1 ui-monospace,monospace;color:#22d3ee;background:#22d3ee1a;border-radius:999px;padding:2px 5px}
.rc2-hud-collapse{width:24px;height:22px;padding:0;line-height:1}
.rc2-canvas-host{position:relative;display:flex;flex:1 1 auto;min-width:0}
.rc2-browsers{position:absolute;top:50%;left:10px;transform:translateY(-50%);z-index:6;display:flex;flex-direction:column;gap:8px;align-items:flex-start;pointer-events:auto}
.rc2-bpane{width:206px;border-radius:8px;overflow:hidden;background:rgba(10,16,26,.92);border:1px solid var(--dsw-alias-border-l2);box-shadow:0 8px 22px rgba(0,0,0,.45);cursor:pointer;transition:transform .12s,border-color .12s}
.rc2-bpane:hover{transform:translateY(-1px);border-color:color-mix(in srgb,var(--rc-accent) 55%,transparent)}
.rc2-bpane.running{border-color:color-mix(in srgb,var(--rc-accent) 62%,transparent)}
.rc2-bpane.error{border-color:#f87171aa}
.rc2-bpane-head{display:flex;align-items:center;gap:5px;padding:4px 6px;font-size:10px;color:#dbe6f4;background:rgba(255,255,255,.03)}
.rc2-bpane-name{flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc2-bpane-state{font-size:9px;opacity:.72}
.rc2-bpane-shot{display:block;width:100%;height:118px;object-fit:cover;object-position:top center;background:#0b1220}
.rc2-bpane-empty{display:flex;align-items:center;justify-content:center;height:118px;font-size:10px;color:#7d8ba1}
.rc2-bpane-url{padding:3px 6px;font:9px/1.3 ui-monospace,monospace;color:#8fa3bd;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border-top:1px solid rgba(255,255,255,.05)}
.rc2-dot{width:6px;height:6px;border-radius:50%;background:#64748b;flex:0 0 auto}
.rc2-dot.running{background:#22d3ee;box-shadow:0 0 0 2px #22d3ee33;animation:rc2pulse 1.4s infinite}
.rc2-dot.error{background:#f87171}
@keyframes rc2pulse{0%,100%{opacity:1}50%{opacity:.35}}
.rc2-missionbar{display:flex;align-items:center;gap:6px;padding:6px 8px;border-bottom:1px solid var(--dsw-alias-border-l1);background:color-mix(in srgb,var(--rc-accent) 4%,transparent)}
.rc2-trace{display:flex;flex-direction:column;gap:2px;padding:6px 8px;border-radius:4px;cursor:pointer;
  border-left:2px solid transparent;transition:background .12s}
.rc2-trace:hover{background:color-mix(in srgb,var(--rc-accent) 7%,transparent)}
.rc2-trace.open{background:var(--dsw-alias-bg-2);border-left-color:var(--rc-accent)}
.rc2-trace-head{display:flex;align-items:center;gap:5px;font-size:10.5px;color:var(--dsw-alias-fg-3)}
.rc2-tk{font-size:9.5px;padding:0 4px;border-radius:3px;border:1px solid transparent;white-space:nowrap}
.rc2-trace-actor{font-size:10.5px;font-weight:600;max-width:96px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc2-trace-title{font-size:11.5px;color:var(--dsw-alias-fg-1);line-height:1.45;white-space:pre-wrap;word-break:break-word}
.rc2-trace-detail{font-size:11px;color:var(--dsw-alias-fg-3);white-space:pre-wrap;word-break:break-word;line-height:1.55;max-height:340px;overflow:auto}
.rc2-trace-refs{display:flex;flex-wrap:wrap;gap:4px;margin-top:2px}
.rc2-spotrel{border-top:1px dashed var(--dsw-alias-border-l1);padding-top:8px;display:flex;flex-direction:column;gap:3px}
.rc2-relrow{display:flex;align-items:center;gap:6px;width:100%;text-align:left;padding:4px 6px;border-radius:4px;
  border:1px solid transparent;background:transparent;color:inherit;cursor:pointer;font-size:11.5px}
.rc2-relrow:hover{background:color-mix(in srgb,var(--rc-accent) 9%,transparent);border-color:var(--dsw-alias-border-l1)}
.rc2-reltext{color:var(--dsw-alias-fg-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 auto}
.rc2-spotkv{font-size:11px;padding:1px 6px;border-radius:3px;border:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-fg-3)}
.rc2-spotkv b{color:var(--dsw-alias-fg-1);font-weight:600}
.rc2-rail.right > .rc2-railhead:nth-of-type(2){border-top:1px solid var(--dsw-alias-border-l1)}
.rc2-railhead{display:flex;align-items:center;gap:8px;padding:7px 10px;flex:0 0 auto;
  border-bottom:1px solid var(--dsw-alias-border-l1);font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--dsw-alias-label-secondary)}
.rc2-railhead-title{flex:0 0 auto;white-space:nowrap}
.rc2-railhead .rc2-spacer{flex:1 1 auto}
.rc2-boardbar{display:flex;align-items:center;justify-content:flex-end;gap:6px;padding:5px 8px;flex:0 0 auto;flex-wrap:wrap;row-gap:4px;
  border-bottom:1px solid var(--dsw-alias-border-l1);min-width:0}
.rc2-boardbar .rc2-select{flex:0 0 auto;height:24px!important;box-sizing:border-box}
.rc2-boardbar .rc2-spacer{flex:1 1 auto}
.rc2-boardbar-actions{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex:0 1 auto;min-width:0;flex-wrap:wrap;margin-left:auto}
.rc2-boardbar-actions .rc2-search{height:24px!important;box-sizing:border-box}
.rc2-boardbar .rc2-row{margin-bottom:0;flex:0 0 auto;align-items:center}
.rc2-boardbar .rc2-row .rc2-search{height:24px!important;width:64px!important;box-sizing:border-box}
.rc2-boardbar .rc2-row .rc2-btn{height:24px!important;box-sizing:border-box;white-space:nowrap}
.rc2-boardwho{display:inline-flex;align-items:center;height:24px;box-sizing:border-box;font-size:10px;line-height:1;white-space:nowrap;flex:0 0 auto;max-width:130px;overflow:hidden;
  text-overflow:ellipsis;padding:0 6px;border-radius:8px;border:1px solid var(--dsw-alias-border-l1);
  color:var(--rc-accent);background:color-mix(in srgb,var(--rc-accent) 8%,transparent)}
.rc2-railhead b{color:var(--rc-accent);font-weight:700}
.rc2-feed{flex:1 1 auto;overflow:auto;padding:4px 6px 12px;scroll-behavior:smooth}
.rc2-item{display:flex;flex-direction:column;gap:2px;padding:5px 7px;border-radius:4px;cursor:pointer;
  border-left:2px solid transparent;margin-bottom:2px;transition:background .15s}
.rc2-item:hover{background:color-mix(in srgb,var(--rc-accent) 8%,transparent)}
.rc2-item.sel{background:var(--rc-accent-dim);border-left-color:var(--rc-accent)}
.rc2-item.fresh{animation:rc2-in .9s ease-out}
@keyframes rc2-in{from{background:color-mix(in srgb,var(--rc-accent) 26%,transparent)}to{background:transparent}}
.rc2-line{display:flex;align-items:center;gap:6px;min-width:0}
.rc2-mono{font-family:ui-monospace,Menlo,monospace;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 auto}
.rc2-meta{font-size:10px;color:var(--dsw-alias-label-secondary);letter-spacing:.04em;white-space:nowrap}
.rc2-exit{font-family:ui-monospace,Menlo,monospace;font-size:10px;padding:0 4px;border-radius:3px;border:1px solid currentColor}
.rc2-exit.ok{color:#34d399}.rc2-exit.bad{color:var(--rc-danger)}.rc2-exit.tmo{color:#fbbf24}
.rc2-sev{font-size:9.5px;font-weight:700;letter-spacing:.08em;padding:1px 5px;border-radius:3px;color:#0b0f14;text-transform:uppercase}
.rc2-dot{width:6px;height:6px;border-radius:50%;background:var(--rc-accent);box-shadow:0 0 8px var(--rc-accent)}
.rc2-dot.pulse{animation:rc2-pulse 1.1s ease-in-out infinite}
@keyframes rc2-pulse{0%,100%{opacity:.35;transform:scale(.85)}50%{opacity:1;transform:scale(1.15)}}
.rc2-canvas{position:relative;flex:1 1 auto;min-width:0;min-height:0;overflow:hidden;
  background:radial-gradient(circle at 1px 1px,color-mix(in srgb,var(--rc-accent) 22%,transparent) 1px,transparent 0) 0 0/28px 28px,
  radial-gradient(60% 60% at 50% 50%,color-mix(in srgb,var(--rc-accent) 6%,transparent),transparent 70%),
  var(--dsw-alias-bg-base)}
.rc2-canvas svg{display:block;width:100%;height:100%;cursor:grab}
.rc2-canvas svg.dragging{cursor:grabbing}
.rc2-node{cursor:pointer}
.rc2-node text{pointer-events:none;user-select:none}
.rc2-hud{position:absolute;border-radius:6px;padding:8px 9px;font-size:11.5px;z-index:2;
  background:color-mix(in srgb,var(--dsw-alias-bg-layer-1) 86%,transparent);
  border:1px solid color-mix(in srgb,var(--rc-accent) 22%,var(--dsw-alias-border-l1));
  backdrop-filter:blur(6px);box-shadow:0 10px 30px -18px #000}
.rc2-hud.tl{top:10px;left:10px;max-width:52%}
.rc2-hud.tr{top:10px;right:10px;width:288px;max-height:62%;overflow:auto}
.rc2-hud.bl{left:10px;bottom:10px;display:flex;flex-wrap:wrap;gap:4px 10px;max-width:56%}
.rc2-hud.br{right:10px;bottom:10px;display:flex;gap:2px;align-items:center;padding:2px 4px}
.rc2-hud.br .rc2-zoom{min-width:26px;padding:0 4px;height:22px;line-height:20px;border-radius:4px;
  color:#f8fafc;font-weight:700;font-size:11px;letter-spacing:0;
  background:rgba(2,6,23,.82);border:1px solid rgba(148,163,184,.42);
  text-shadow:0 1px 2px rgba(0,0,0,.9);font-family:ui-monospace,Menlo,monospace}
.rc2-hud.br .rc2-btn{padding:0 3px;min-width:22px;height:22px;line-height:1;font-size:11px}
.rc2-zoom{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--rc-accent);
  min-width:38px;text-align:center;letter-spacing:.04em}
.rc2-hud.bl{display:flex;flex-wrap:nowrap;align-items:center;gap:6px;max-width:calc(100% - 20px);z-index:6;
  overflow:hidden;white-space:nowrap;padding:4px 8px}
.rc2-legscroll{display:flex;flex-wrap:nowrap;align-items:center;gap:4px 10px;min-width:0;flex:1 1 auto;
  overflow-x:auto;overflow-y:hidden;scrollbar-width:thin;scrollbar-color:color-mix(in srgb,var(--rc-accent) 45%,transparent) transparent}
.rc2-legscroll::-webkit-scrollbar{height:3px}
.rc2-legscroll::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--rc-accent) 45%,transparent);border-radius:2px}
.rc2-legscroll > *{flex:0 0 auto}
.rc2-legtail{display:flex;align-items:center;gap:4px;flex:0 0 auto;
  padding-left:5px;border-left:1px solid color-mix(in srgb,var(--rc-accent) 26%,transparent)}
.rc2-legtail .rc2-legend{padding:1px 5px;font-size:10.5px;gap:4px}
.rc2-zoomgroup{display:flex;align-items:center;gap:1px;flex:0 0 auto;
  padding-left:5px;border-left:1px solid color-mix(in srgb,var(--rc-accent) 26%,transparent)}
.rc2-zoomgroup .rc2-btn{padding:0 3px;min-width:20px;height:20px;line-height:1;font-size:11px}
.rc2-zoomval{min-width:30px;padding:0 4px;height:20px;line-height:18px;border-radius:4px;text-align:center;
  color:#f8fafc;font-weight:700;font-size:10.5px;font-family:ui-monospace,Menlo,monospace;
  background:rgba(2,6,23,.88);border:1px solid rgba(148,163,184,.5);text-shadow:0 1px 2px rgba(0,0,0,.9)}
.rc2-hud.br{pointer-events:none}
.rc2-hud.br > *{pointer-events:auto}
/* 画布很窄时：图例展开会占满整行，此时把右下缩放条收起（滚轮与双击仍然可用） */
.rc2-hud.br.compact-hide{opacity:0;pointer-events:none;transition:opacity .12s}
.rc2-hud.bl.wide{flex-wrap:wrap;white-space:normal;max-width:calc(100% - 20px);align-items:flex-start;z-index:8}
.rc2-hud.bl.wide .rc2-zoomgroup{margin-left:auto}
.rc2-hud.bl.wide .rc2-legscroll{flex-wrap:wrap;overflow:visible;max-height:min(200px,30vh);overflow-y:auto}
.rc2-hud.bl.wide .rc2-legtail{position:sticky;bottom:0;background:inherit}
.rc2-legend{font-size:10px;color:var(--dsw-alias-label-secondary);display:inline-flex;align-items:center;gap:4px;
  padding:1px 5px;border-radius:4px;border:1px solid transparent;background:transparent;cursor:pointer}
.rc2-legend:hover{color:var(--rc-accent);border-color:color-mix(in srgb,var(--rc-accent) 30%,transparent)}
.rc2-legend.on{color:var(--rc-accent);border-color:color-mix(in srgb,var(--rc-accent) 60%,transparent);
  background:color-mix(in srgb,var(--rc-accent) 14%,transparent)}
.rc2-legend.all{letter-spacing:.08em}
.rc2-legend i{width:6px;height:6px;border-radius:50%;display:inline-block}
.rc2-search{width:210px;height:24px;border-radius:4px;padding:0 7px;font-size:11.5px;outline:none;
  border:1px solid color-mix(in srgb,var(--rc-accent) 24%,var(--dsw-alias-border-l1));
  background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary)}
.rc2-search:focus{border-color:var(--rc-accent);box-shadow:0 0 12px -6px var(--rc-accent)}
.rc2-kv{display:flex;gap:6px;font-size:11px;line-height:1.6;margin-top:2px}
.rc2-kv .k{flex:0 0 58px;color:var(--dsw-alias-label-secondary);letter-spacing:.04em}
.rc2-kv .v{flex:1 1 auto;min-width:0;word-break:break-word;font-family:ui-monospace,Menlo,monospace}
.rc2-sect{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--rc-accent);margin:9px 0 4px;
  display:flex;align-items:center;gap:6px}
.rc2-sect::after{content:'';flex:1 1 auto;height:1px;background:linear-gradient(90deg,color-mix(in srgb,var(--rc-accent) 40%,transparent),transparent)}
.rc2-pre{margin:0;padding:7px 8px;border-radius:4px;font-family:ui-monospace,Menlo,monospace;font-size:11px;
  line-height:1.6;white-space:pre-wrap;word-break:break-word;max-height:260px;overflow:auto;
  background:var(--dsw-alias-bg-base);border:1px solid var(--dsw-alias-border-l1)}
.rc2-pre.tall{max-height:46vh}
.rc2-cmd{display:flex;align-items:center;gap:6px;padding:4px 6px;border-radius:4px;cursor:pointer;
  border:1px solid var(--dsw-alias-border-l1);margin-bottom:3px;background:var(--dsw-alias-bg-base)}
.rc2-cmd:hover{border-color:var(--rc-accent)}
.rc2-cmd span{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc2-dock{flex:0 0 auto;border-top:1px solid color-mix(in srgb,var(--rc-accent) 26%,var(--dsw-alias-border-l1));
  background:linear-gradient(0deg,color-mix(in srgb,var(--rc-accent) 6%,transparent),transparent),var(--dsw-alias-bg-layer-1);
  display:flex;flex-direction:column;z-index:4}
.rc2-dock.expanded{height:min(38vh,360px)}
.rc2-shots{display:flex;gap:6px;padding:6px 10px 0;flex-wrap:wrap}
.rc2-shot{position:relative;width:56px;height:42px;border-radius:4px;overflow:hidden;border:1px solid var(--rc-accent)}
.rc2-shot img{width:100%;height:100%;object-fit:cover;display:block}
.rc2-shot button{position:absolute;top:0;right:0;width:14px;height:14px;padding:0;line-height:12px;
  border:none;background:rgba(0,0,0,.65);color:#fff;font-size:10px;cursor:pointer}
.rc2-dockhead{display:flex;align-items:center;gap:8px;padding:5px 10px;font-size:10.5px;
  letter-spacing:.14em;text-transform:uppercase;color:var(--dsw-alias-label-secondary);
  flex-wrap:nowrap;overflow:hidden;flex:0 0 auto;min-height:28px}
/* 头部里的按钮/下拉/页签宽度固定，不参与伸缩，避免文字变化把按钮推来推去 */
.rc2-dockhead > *:not(.rc2-spacer){flex:0 0 auto}
/* 思维链/主 agent 输出预览：单独占一行，永远在按钮行下面 */
.rc2-thinkrow{display:flex;align-items:baseline;gap:8px;padding:0 10px 5px;min-width:0;
  font-size:10.5px;color:color-mix(in srgb,var(--rc-accent) 66%,var(--dsw-alias-label-secondary));
  flex:0 0 auto}
.rc2-thinklabel{flex:0 0 auto;letter-spacing:.12em;text-transform:uppercase;opacity:.72}
.rc2-thinkpeek{flex:1 1 auto;min-width:0;font-family:ui-monospace,Menlo,monospace;font-size:10.5px;
  color:inherit;white-space:pre-wrap;word-break:break-word;opacity:.9}
.rc2-meetingbar{display:flex;align-items:center;gap:8px;padding:5px 10px;margin-bottom:6px;
  border-radius:5px;border:1px solid var(--dsw-alias-border-l1);font-size:11px;
  background:color-mix(in srgb,var(--rc-accent) 5%,transparent)}
.rc2-mb-label{flex:0 0 auto;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--dsw-alias-label-secondary);opacity:.8}
.rc2-mb-state{flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--dsw-alias-label-secondary)}
.rc2-queue{flex:0 0 auto;border-top:1px dashed color-mix(in srgb,var(--rc-accent) 34%,transparent);
  background:color-mix(in srgb,var(--rc-accent) 5%,transparent);max-height:152px;display:flex;flex-direction:column}
.rc2-queuehead{display:flex;align-items:center;gap:8px;padding:3px 10px;cursor:pointer;font-size:10.5px}
.rc2-queuebadge{padding:1px 6px;border-radius:4px;font-weight:600;
  background:color-mix(in srgb,var(--rc-accent) 20%,transparent);color:var(--rc-accent)}
.rc2-queuetip{flex:1 1 auto;min-width:0;color:var(--dsw-alias-label-secondary);opacity:.8;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc2-queuetoggle{color:var(--rc-accent)}
.rc2-queuelist{overflow:auto;padding:0 8px 4px;display:flex;flex-direction:column;gap:3px}
.rc2-queueitem{display:flex;align-items:center;gap:6px;font-size:11.5px;padding:2px 4px;border-radius:4px;
  background:color-mix(in srgb,var(--dsw-alias-bg-base) 70%,transparent)}
.rc2-queueidx{flex:0 0 auto;width:14px;text-align:center;font-size:10px;opacity:.6}
.rc2-queuetext{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--dsw-alias-label-primary)}
.rc2-queuetarget{flex:0 0 auto;font-size:9.5px;padding:0 4px;border-radius:3px;opacity:.8;
  border:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-secondary)}
.rc2-qbtn{flex:0 0 auto;height:20px;padding:0 6px;border-radius:4px;cursor:pointer;font-size:10px;
  border:1px solid var(--dsw-alias-border-l1);background:transparent;color:var(--dsw-alias-label-secondary)}
.rc2-qbtn:hover{color:var(--dsw-alias-label-primary);border-color:var(--rc-accent)}
.rc2-qbtn.go{border-color:color-mix(in srgb,#fb923c 55%,transparent);color:#fb923c}
.rc2-briefwrap{flex:1 1 auto;display:flex;flex-direction:column;min-height:0}
.rc2-briefhint{flex:0 0 auto;padding:2px 12px 0;font-size:10px;letter-spacing:.08em;
  color:var(--dsw-alias-label-secondary);opacity:.7}
.rc2-briefinput{display:flex;gap:8px;align-items:flex-end;padding:6px 12px 8px}
.rc2-briefinput .rc2-grow{flex:1 1 auto;min-height:30px;max-height:96px;resize:none}
.rc2-brief{flex:1 1 auto;overflow:auto;padding:8px 12px 10px;min-height:0}
.rc2-bgrid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);gap:10px;align-items:start}
.rc2-bcol{display:flex;flex-direction:column;gap:10px;min-width:0}
.rc2-bsec{border:1px solid var(--dsw-alias-border-l1);border-radius:6px;background:var(--dsw-alias-bg-base);
  padding:7px 9px 8px;min-width:0}
.rc2-bsec > h4{margin:0 0 6px;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--dsw-alias-label-secondary);display:flex;align-items:center;gap:6px}
.rc2-bsec > h4 b{color:var(--rc-accent);font-weight:600}
.rc2-bstats{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:9px}
.rc2-bstat{display:flex;align-items:baseline;gap:5px;padding:3px 8px;border-radius:5px;
  border:1px solid color-mix(in srgb,var(--rc-accent) 22%,transparent);
  background:color-mix(in srgb,var(--rc-accent) 7%,transparent);font-size:10.5px;
  color:var(--dsw-alias-label-secondary)}
.rc2-bstat b{font-size:12px;color:var(--dsw-alias-label-primary);font-weight:700}
.rc2-bstat.warn{border-color:color-mix(in srgb,#fb923c 40%,transparent);background:color-mix(in srgb,#fb923c 9%,transparent)}
.rc2-bstat.ok{border-color:color-mix(in srgb,#34d399 40%,transparent);background:color-mix(in srgb,#34d399 9%,transparent)}
.rc2-minimap{width:100%;height:auto;max-height:230px;display:block;pointer-events:none;user-select:none}
.rc2-bkind{display:flex;flex-wrap:wrap;gap:4px 8px;font-size:10.5px;margin-top:6px}
.rc2-bkind span{display:inline-flex;align-items:center;gap:4px;color:var(--dsw-alias-label-secondary)}
.rc2-bkind i{width:7px;height:7px;border-radius:50%;display:inline-block}
.rc2-brow{display:flex;gap:7px;align-items:baseline;font-size:11.5px;line-height:1.55;
  padding:3px 0;border-bottom:1px dotted color-mix(in srgb,var(--dsw-alias-border-l1) 70%,transparent)}
.rc2-brow:last-child{border-bottom:0}
.rc2-brow .k{flex:0 0 auto;font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;padding:0 4px;
  border-radius:3px;border:1px solid currentColor;opacity:.85}
.rc2-brow .t{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--dsw-alias-label-primary)}
.rc2-brow .m{flex:0 0 auto;font-size:10px;color:var(--dsw-alias-label-secondary)}
.rc2-bempty{font-size:11px;color:var(--dsw-alias-label-secondary);opacity:.75;padding:2px 0}
.rc2-chat{flex:1 1 auto;overflow:auto;padding:8px 12px;display:flex;flex-direction:column;gap:7px}
.rc2-msg{max-width:min(760px,92%);border-radius:6px;padding:6px 9px;font-size:12.5px;line-height:1.65;
  white-space:pre-wrap;word-break:break-word;border:1px solid var(--dsw-alias-border-l1)}
.rc2-msg.user{align-self:flex-end;background:var(--rc-accent-dim);border-color:color-mix(in srgb,var(--rc-accent) 40%,transparent)}
.rc2-msg.ai{align-self:flex-start;background:var(--dsw-alias-bg-base)}
.rc2-msg .who{font-size:9.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--dsw-alias-label-secondary);margin-bottom:3px}
.rc2-msg .body{white-space:pre-wrap}
.rc2-reason{margin-top:5px;padding:5px 7px;border-left:2px solid color-mix(in srgb,var(--rc-accent) 50%,transparent);
  font-family:ui-monospace,Menlo,monospace;font-size:10.5px;line-height:1.6;color:var(--dsw-alias-label-secondary);
  max-height:150px;overflow:auto;white-space:pre-wrap}
.rc2-caret{display:inline-block;width:6px;height:12px;background:var(--rc-accent);vertical-align:-1px;
  animation:rc2-blink 1s steps(2,start) infinite;margin-left:2px}
@keyframes rc2-blink{to{visibility:hidden}}
.rc2-tool{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--dsw-alias-label-secondary);
  padding:2px 7px;border-radius:3px;background:color-mix(in srgb,var(--rc-accent) 7%,transparent);
  border-left:2px solid color-mix(in srgb,var(--rc-accent) 45%,transparent);max-width:92%;word-break:break-word}
.rc2-inputrow{display:flex;align-items:flex-end;gap:7px;padding:8px 10px 10px}
.rc2-input{flex:1 1 auto;min-height:34px;max-height:120px;resize:vertical;border-radius:5px;padding:7px 9px;
  font-family:inherit;font-size:12.5px;line-height:1.5;outline:none;
  border:1px solid color-mix(in srgb,var(--rc-accent) 26%,var(--dsw-alias-border-l1));
  background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary)}
.rc2-input:focus{border-color:var(--rc-accent);box-shadow:0 0 16px -8px var(--rc-accent)}
.rc2-drawer{position:absolute;inset:0;z-index:20;display:flex;justify-content:flex-end;
  background:rgba(4,8,12,.55);backdrop-filter:blur(2px)}
.rc2-panel{width:min(760px,94%);height:100%;display:flex;flex-direction:column;
  background:var(--dsw-alias-bg-layer-1);border-left:1px solid color-mix(in srgb,var(--rc-accent) 32%,transparent);
  box-shadow:-24px 0 60px -30px #000}
.rc2-panelhead{display:flex;align-items:center;gap:10px;padding:9px 12px;border-bottom:1px solid var(--dsw-alias-border-l1)}
.rc2-panelhead h2{margin:0;font-size:12.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--rc-accent)}
.rc2-tabs{display:flex;gap:2px;padding:8px 12px 0;flex-wrap:wrap}
.rc2-tab{height:26px;padding:0 9px;border-radius:4px 4px 0 0;border:1px solid transparent;border-bottom:none;
  background:transparent;cursor:pointer;font-size:11px;letter-spacing:.06em;color:var(--dsw-alias-label-secondary)}
.rc2-tab.on{background:var(--dsw-alias-bg-base);border-color:var(--dsw-alias-border-l1);color:var(--rc-accent)}
.rc2-panelbody{flex:1 1 auto;overflow:auto;padding:12px;background:var(--dsw-alias-bg-base)}
.rc2-field{display:flex;flex-direction:column;gap:3px;margin-bottom:9px}
.rc2-field label{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--dsw-alias-label-secondary)}
.rc2-field input,.rc2-field textarea,.rc2-field select{border-radius:4px;padding:6px 8px;font-size:12px;
  font-family:inherit;outline:none;background:var(--dsw-alias-bg-layer-1);
  border:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-primary)}
.rc2-field input:focus,.rc2-field textarea:focus,.rc2-field select:focus{border-color:var(--rc-accent)}
.rc2-field textarea{min-height:64px;resize:vertical;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;line-height:1.6}
.rc2-grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.rc2-grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}
.rc2-row{display:flex;gap:6px;align-items:center;margin-bottom:6px}
.rc2-boardcfg-row{flex-wrap:wrap;gap:8px;align-items:center}
.rc2-field select.rc2-boardcfg-select{height:34px;min-height:34px;min-width:114px;box-sizing:border-box;line-height:1.4;
  padding:6px 28px 6px 9px;font-size:12px;border-radius:5px;max-width:100%}
.rc2-field select.rc2-boardcfg-select.rc2-boardcfg-select-wide{min-width:178px}
.rc2-note{font-size:10.5px;line-height:1.6;color:var(--dsw-alias-label-secondary);margin:2px 0 10px}
.rc2-docktabs{display:flex;gap:2px}
.rc2-docktab{height:24px;padding:0 8px;border-radius:4px;border:1px solid transparent;background:transparent;
  color:var(--dsw-alias-label-secondary);font-size:11px;letter-spacing:.06em;cursor:pointer}
.rc2-docktab.on{background:var(--rc-accent-dim);color:var(--rc-accent);
  border-color:color-mix(in srgb,var(--rc-accent) 35%,transparent)}
.rc2-docktab .n{margin-left:4px;font-size:10px;opacity:.8}
.rc2-board{flex:1 1 auto;overflow:auto;padding:8px 12px;display:flex;flex-direction:column;gap:8px}
.rc2-boarditem{border:1px solid var(--dsw-alias-border-l1);border-radius:6px;padding:7px 9px;background:var(--dsw-alias-bg-base)}
.rc2-boardhead{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.rc2-author{font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:0 6px;border-radius:3px;
  border:1px solid currentColor;line-height:16px}
.rc2-kind{font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;padding:0 5px;border-radius:3px;
  background:color-mix(in srgb,var(--rc-accent) 14%,transparent);color:var(--rc-accent)}
.rc2-kind.k-hypothesis{background:rgba(250,204,21,.16);color:#facc15}
.rc2-kind.k-task{border:1px dashed color-mix(in srgb,var(--rc-accent) 50%,transparent);background:transparent}
.rc2-kind.k-conclusion{background:rgba(52,211,153,.16);color:#34d399}
.rc2-kind.k-note{background:rgba(148,163,184,.16);color:#94a3b8}
.rc2-boardtext{margin-top:5px;font-size:12px;line-height:1.65;word-break:break-word;
  min-width:0;max-width:100%;overflow-wrap:anywhere}
.rc2-boardtext.rc2-md{white-space:normal}
.rc2-refs{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.rc2-refchip{font-size:10px;padding:1px 6px;border-radius:10px;cursor:pointer;background:var(--dsw-alias-bg-layer-1);
  border:1px solid var(--dsw-alias-border-l1);color:var(--dsw-alias-label-secondary)}
.rc2-refchip:hover{border-color:var(--rc-accent);color:var(--rc-accent)}
.rc2-thumbs{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.rc2-thumb{display:block;width:88px;height:60px;border-radius:4px;overflow:hidden;border:1px solid var(--dsw-alias-border-l1)}
.rc2-thumb img{width:100%;height:100%;object-fit:cover;display:block}
.rc2-squadlist{display:flex;flex-direction:column;gap:6px}
.rc2-sqcard{border:1px solid var(--dsw-alias-border-l1);border-radius:7px;background:var(--dsw-alias-bg-base);padding:0 9px;transition:border-color .12s,background .12s}
.rc2-sqcard:hover{border-color:color-mix(in srgb,var(--rc-accent) 45%,transparent);background:color-mix(in srgb,var(--rc-accent) 4%,var(--dsw-alias-bg-base))}
.rc2-sqrow{display:flex;align-items:center;gap:8px;min-height:44px;flex-wrap:nowrap}
.rc2-sqid{display:flex;align-items:center;gap:6px;flex:0 1 auto;min-width:0;max-width:44%}
.rc2-sqstate{display:flex;align-items:center;gap:5px;flex:0 0 auto}
.rc2-sqpill{font:9.5px/1 ui-monospace,monospace;padding:3px 6px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-secondary)}
.rc2-sqpill.running{color:#22d3ee;border-color:#22d3ee66;background:#22d3ee14}
.rc2-sqpill.starting{color:#fbbf24;border-color:#fbbf2466}
.rc2-sqpill.done{color:#34d399;border-color:#34d39955}
.rc2-sqtask{flex:1 1 auto;min-width:0;font-size:11.5px;color:var(--dsw-alias-label-secondary);white-space:pre-wrap;word-break:break-word}
.rc2-sqacts{display:flex;align-items:center;gap:4px;flex:0 0 auto}
.rc2-sqout{display:flex;align-items:flex-start;gap:8px;padding:0 0 7px 14px;font-size:10.5px;color:var(--dsw-alias-label-secondary)}
.rc2-sqtool{flex:0 0 auto;font-family:ui-monospace,monospace;color:var(--rc-accent);opacity:.85}
.rc2-sqtext{flex:1 1 auto;min-width:0;line-height:1.5;font-family:ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
.rc2-squadcard{border:1px solid var(--dsw-alias-border-l1);border-radius:6px;padding:7px 9px;background:var(--dsw-alias-bg-base)}
.rc2-squadout{margin-top:5px;font-family:ui-monospace,Menlo,monospace;font-size:10.5px;line-height:1.6;
  color:var(--dsw-alias-label-secondary);white-space:pre-wrap;max-height:120px;overflow:auto}
.rc2-md{line-height:1.62;min-width:0;max-width:100%;overflow-wrap:anywhere}
.rc2-md .rc2-mdp{margin:0}
.rc2-md .rc2-mdgap{height:4px}
.rc2-md .rc2-mdh{margin:2px 0 2px;font-weight:650;line-height:1.35}
.rc2-md .rc2-mdh1{font-size:14px}
.rc2-md .rc2-mdh2{font-size:13px}
.rc2-md .rc2-mdh3{font-size:12.4px;color:color-mix(in srgb,var(--rc-accent) 70%,var(--dsw-alias-label-primary))}
.rc2-md .rc2-mdh4{font-size:12px;color:var(--dsw-alias-label-secondary)}
.rc2-md .rc2-mdlist{margin:2px 0 2px;padding-left:17px;display:flex;flex-direction:column;gap:1px}
.rc2-md .rc2-mdol{padding-left:19px}
.rc2-md .rc2-mdlist li{list-style:disc}
.rc2-md .rc2-mdol li{list-style:decimal}
.rc2-md .rc2-mdquote{margin:3px 0;padding:2px 8px;border-left:2px solid color-mix(in srgb,var(--rc-accent) 45%,transparent);
  color:var(--dsw-alias-label-secondary)}
.rc2-md .rc2-mdhr{border:0;border-top:1px solid var(--dsw-alias-border-l1);margin:5px 0}
.rc2-md b{color:var(--dsw-alias-label-primary);font-weight:650}
.rc2-md .rc2-code{font-family:ui-monospace,Menlo,monospace;font-size:11px;padding:0 3px;border-radius:3px;
  background:color-mix(in srgb,var(--rc-accent) 12%,transparent)}
.rc2-md a{color:var(--rc-accent);text-decoration:none;border-bottom:1px dotted color-mix(in srgb,var(--rc-accent) 55%,transparent)}
.rc2-md a:hover{text-decoration:underline}
.rc2-codeblock{margin:4px 0;padding:7px 9px;border-radius:4px;background:var(--dsw-alias-bg-base);
  border:1px solid var(--dsw-alias-border-l1);font-family:ui-monospace,Menlo,monospace;font-size:11px;
  line-height:1.6;overflow:auto;white-space:pre-wrap;word-break:break-word}
.rc2-code{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;padding:0 3px;border-radius:3px;
  background:color-mix(in srgb,var(--rc-accent) 12%,transparent)}
.rc2-mdlist{margin:3px 0 3px 18px;padding:0}
.rc2-mdgap{height:5px}
.rc2-msg .body a{color:var(--rc-accent)}
.rc2-attachbar{display:flex;flex-wrap:wrap;gap:6px;padding:6px 10px 0}
.rc2-quickchips{display:flex;flex-wrap:wrap;gap:4px;padding:6px 10px 0}
.rc2-attach{display:flex;align-items:center;gap:5px;font-size:10.5px;padding:2px 7px;border-radius:4px;
  border:1px solid color-mix(in srgb,var(--rc-accent) 40%,transparent);color:var(--rc-accent);cursor:pointer}
.rc2-attach span{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rc2-attach button{border:none;background:transparent;color:inherit;cursor:pointer;font-size:10px;padding:0}
.rc2-menubox{position:fixed;z-index:50;min-width:150px;padding:4px;border-radius:6px;
  background:var(--dsw-alias-bg-overlay);border:1px solid color-mix(in srgb,var(--rc-accent) 35%,transparent);
  box-shadow:0 16px 40px -20px #000}
.rc2-menubox button{display:block;width:100%;text-align:left;padding:5px 8px;border:none;background:transparent;
  color:var(--dsw-alias-label-primary);font-size:11.5px;cursor:pointer;border-radius:4px}
.rc2-menubox button:hover{background:var(--rc-accent-dim);color:var(--rc-accent)}
.rc2-filterbar{display:flex;gap:3px;padding:4px 8px;flex-wrap:wrap;align-items:center}
.rc2-merged{margin:4px 8px;border:1px dashed color-mix(in srgb,var(--rc-accent) 45%,var(--dsw-alias-border-l1));border-radius:6px;background:color-mix(in srgb,var(--rc-accent) 4%,transparent);overflow:hidden;flex:0 0 auto}
.rc2-merged-head{width:100%;display:flex;align-items:center;gap:6px;padding:5px 8px;font-size:10.5px;color:var(--rc-accent);background:none;border:none;cursor:pointer;text-align:left}
.rc2-merged-head:hover{background:color-mix(in srgb,var(--rc-accent) 8%,transparent)}
.rc2-merged-body{padding:2px 8px 6px;display:flex;flex-direction:column;gap:4px;max-height:200px;overflow:auto}
.rc2-merged-item{border-top:1px dashed color-mix(in srgb,var(--dsw-alias-border-l1) 60%,transparent);padding-top:4px}
.rc2-merged-sample{font-size:11px;line-height:1.5;color:#a8b8cc;margin-top:2px;white-space:pre-wrap;overflow-wrap:anywhere}
.rc2-merged-authors{margin-top:4px;display:flex;flex-direction:column;gap:3px}
.rc2-merged-toggle{align-self:flex-start;font-size:10px;padding:0 4px;border:1px dashed var(--dsw-alias-border-l1);border-radius:4px;background:none;color:#94a3b8;cursor:pointer}
.rc2-merged-authorlist{display:flex;flex-direction:column;gap:2px}
.rc2-merged-authorrow{display:flex;align-items:center;gap:6px;font-size:10.5px}
.rc2-fchip{font-size:10px;padding:1px 6px;border-radius:10px;cursor:pointer;border:1px solid var(--dsw-alias-border-l1);
  background:transparent;color:var(--dsw-alias-label-secondary)}
.rc2-fchip.on{border-color:var(--rc-accent);color:var(--rc-accent);background:var(--rc-accent-dim)}
.rc2-kindfilter{display:flex;flex-wrap:wrap;gap:3px;max-height:66px;overflow:auto}
@media (max-width: 1280px){
  .rc2-rail.left,.rc2-rail.right{display:none}
  .rc2-hud.tr{display:none}
  .rc2-hud.tl{max-width:80%}
}
.rc2-empty{flex:1 1 auto;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;
  padding:36px;text-align:center;color:var(--dsw-alias-label-secondary)}
.rc2-empty h3{margin:0;font-size:14px;color:var(--dsw-alias-label-primary)}
.rc2-empty p{margin:0;max-width:520px;font-size:12px;line-height:1.7}
.rc2-err{color:var(--rc-danger);font-size:11.5px;padding:6px 10px}
.rc2-center{flex:1 1 auto;display:flex;align-items:center;justify-content:center;color:var(--dsw-alias-label-secondary)}
.rc2.rc2-no-grid .rc2-canvas{background:radial-gradient(60% 60% at 50% 50%,color-mix(in srgb,var(--rc-accent) 6%,transparent),transparent 70%),var(--dsw-alias-bg-1)}
.rc2.rc2-glow{box-shadow:inset 0 0 80px -60px color-mix(in srgb,var(--rc-accent) 80%,transparent)}
`

    /* ───────────────────────── 通信 ───────────────────────── */
    const baseUrl = () => (typeof window !== 'undefined' && window.location ? window.location.origin : '')
    const apiUrl = (path) => {
      try { return new URL(path, baseUrl()).toString() } catch { return path }
    }

    async function api(payload) {
      try {
        const res = await fetch(apiUrl('/recon/api'), {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload || {}),
        })
        const text = await res.text()
        try { return JSON.parse(text) } catch { return { ok: false, error: `HTTP ${res.status}` } }
      } catch (error) {
        return { ok: false, error: error && error.message ? error.message : String(error) }
      }
    }

    const clamp = (v, min, max) => Math.min(max, Math.max(min, v))
    const shortText = (value, max) => {
      const text = String(value === undefined || value === null ? '' : value)
      return text.length > max ? `${text.slice(0, max - 1)}…` : text
    }
    /** 极简 markdown：代码块 / 行内代码 / 粗体 / 链接 / 列表。先整体转义，再按行拼装。 */
    /* ───────── Markdown 渲染：agent 输出按 markdown 显示，而不是原样贴 ───────── */
    function renderMd(text, keyPrefix = 'md') {
      const raw = String(text === undefined || text === null ? '' : text).replace(/\r\n/g, '\n')
      const escape = (value) => String(value)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
      /* 行内：代码 → 粗体 → 斜体 → 删除线 → 链接 → 裸 URL，最后统一注入 */
      const inline = (value) => {
        const slots = []
        const keep = (html) => { slots.push(html); return `\u0000${slots.length - 1}\u0000` }
        let out = escape(value)
        out = out.replace(/`([^`]+)`/g, (_m, code) => keep(`<code class="rc2-code">${code}</code>`))
        out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
          (_m, label, href) => keep(`<a href="${href}" target="_blank" rel="noreferrer">${label}</a>`))
        out = out.replace(/(https?:\/\/[^\s<>"')]+)/g,
          (_m, href) => keep(`<a href="${href}" target="_blank" rel="noreferrer">${href}</a>`))
        out = out.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
        out = out.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<i>$2</i>')
        out = out.replace(/~~([^~]+)~~/g, '<del>$1</del>')
        return out.replace(/\u0000(\d+)\u0000/g, (_m, index) => slots[Number(index)] || '')
      }
      const nodes = []
      const push = (node) => nodes.push(node)

      /* 先按 ``` 切出代码块，其余按行扫描 */
      const blocks = raw.split(/```/)
      blocks.forEach((block, blockIndex) => {
        if (blockIndex % 2 === 1) {
          const body = block.replace(/^[a-zA-Z0-9_+-]*\n/, '').replace(/\n$/, '')
          push(h('pre', { key: `${keyPrefix}-code-${blockIndex}`, className: 'rc2-codeblock' }, body))
          return
        }
        const lines = block.split('\n')
        let bullets = []        // 无序列表
        let numbered = []       // 有序列表
        let quote = []          // 引用块
        const flush = () => {
          if (bullets.length > 0) {
            push(h('ul', { key: `${keyPrefix}-ul-${blockIndex}-${nodes.length}`, className: 'rc2-mdlist' },
              bullets.map((item, index) => h('li', { key: index, dangerouslySetInnerHTML: { __html: inline(item) } }))))
            bullets = []
          }
          if (numbered.length > 0) {
            push(h('ol', { key: `${keyPrefix}-ol-${blockIndex}-${nodes.length}`, className: 'rc2-mdlist rc2-mdol' },
              numbered.map((item, index) => h('li', { key: index, dangerouslySetInnerHTML: { __html: inline(item) } }))))
            numbered = []
          }
          if (quote.length > 0) {
            push(h('blockquote', { key: `${keyPrefix}-q-${blockIndex}-${nodes.length}`, className: 'rc2-mdquote' },
              quote.map((item, index) => h('div', { key: index, dangerouslySetInnerHTML: { __html: inline(item) } }))))
            quote = []
          }
        }
        const isTableRow = (text) => /^\s*\|.*\|\s*$/.test(text) || /^\s*[^|\s][^|]*\|[^|]*$/.test(text) && text.includes('|')
        const isTableDivider = (text) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(text)
        const splitRow = (text) => String(text).trim()
          .replace(/^\|/, '').replace(/\|$/, '')
          .split('|').map((cell) => cell.trim())
        const buildTable = (headerLine, rows) => {
          const head = splitRow(headerLine)
          const body = rows.map((row) => splitRow(row))
          return h('div', { key: `${keyPrefix}-tbl-${blockIndex}-${nodes.length}`, className: 'rc2-mdtablewrap' },
            h('table', { className: 'rc2-mdtable' },
              h('thead', null, h('tr', null, head.map((cell, index) => h('th', {
                key: index, dangerouslySetInnerHTML: { __html: inline(cell) },
              })))),
              h('tbody', null, body.map((row, rowIndex) => h('tr', { key: rowIndex },
                head.map((_cell, cellIndex) => h('td', {
                  key: cellIndex, dangerouslySetInnerHTML: { __html: inline(row[cellIndex] === undefined ? '' : row[cellIndex]) },
                })))))))
        }
        for (let li = 0; li < lines.length; li += 1) {
          const line = lines[li]
          const trimmed = line.trim()
          if (trimmed === '') { flush(); push(h('div', { key: `${keyPrefix}-gap-${blockIndex}-${nodes.length}`, className: 'rc2-mdgap' })); continue }
          /* 表格：当前行有竖线，下一行是 |---|---| 分隔行 */
          if (isTableRow(trimmed) && li + 1 < lines.length && isTableDivider(lines[li + 1])) {
            flush()
            const headerLine = trimmed
            const rows = []
            let ri = li + 2
            while (ri < lines.length && isTableRow(lines[ri].trim()) && lines[ri].trim() !== '') {
              rows.push(lines[ri])
              ri += 1
            }
            push(buildTable(headerLine, rows))
            li = ri - 1
            continue
          }
          const heading = /^(#{1,6})\s+(.*)$/.exec(trimmed)
          if (heading !== null) {
            flush()
            const level = Math.min(4, heading[1].length)
            push(h(`h${level + 2}`, {
              key: `${keyPrefix}-h-${blockIndex}-${nodes.length}`,
              className: `rc2-mdh rc2-mdh${level}`,
              dangerouslySetInnerHTML: { __html: inline(heading[2]) },
            }))
            continue
          }
          if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
            flush()
            push(h('hr', { key: `${keyPrefix}-hr-${blockIndex}-${nodes.length}`, className: 'rc2-mdhr' }))
            continue
          }
          const bullet = /^\s*[-*+]\s+(.*)$/.exec(line)
          if (bullet !== null) { numbered.length > 0 && flush(); bullets.push(bullet[1]); continue }
          const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line)
          if (ordered !== null) { bullets.length > 0 && flush(); numbered.push(ordered[1]); continue }
          const quoted = /^\s*>\s?(.*)$/.exec(line)
          if (quoted !== null) { flush(); quote.push(quoted[1]); continue }
          flush()
          push(h('div', {
            key: `${keyPrefix}-p-${blockIndex}-${nodes.length}`,
            className: 'rc2-mdp',
            dangerouslySetInnerHTML: { __html: inline(line) },
          }))
        }
        flush()
      })
      return nodes
    }

    /** 按当前开关决定渲染 markdown 还是显示原文。 */
    function mdOrText(text, keyPrefix, on) {
      if (text === undefined || text === null || text === '') return ''
      return on ? renderMd(text, keyPrefix) : String(text)
    }

    const fmtTime = (iso) => {
      if (!iso) return ''
      try { return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) } catch { return '' }
    }

    /* ───────────────────────── 图布局 ───────────────────────── */
    const TRACE_LIMIT = 500
    const TRACE_BUFFER_MAX = 5000

    const CENTER = { x: 900, y: 560 }

    function ensurePositions(map, nodes, edges) {
      const alive = new Set(nodes.map((n) => n.id))
      for (const key of Array.from(map.keys())) if (!alive.has(key)) map.delete(key)
      const adjacency = new Map()
      for (const edge of edges) {
        if (!adjacency.has(edge.from)) adjacency.set(edge.from, [])
        if (!adjacency.has(edge.to)) adjacency.set(edge.to, [])
        adjacency.get(edge.from).push(edge.to)
        adjacency.get(edge.to).push(edge.from)
      }
      const depth = new Map()
      const seeds = nodes.filter((n) => n.seed || n.kind === 'root').map((n) => n.id)
      const start = seeds.length > 0 ? seeds : nodes.slice(0, 1).map((n) => n.id)
      const queue = []
      for (const id of start) { depth.set(id, 0); queue.push(id) }
      while (queue.length > 0) {
        const id = queue.shift()
        const d = depth.get(id) || 0
        for (const next of adjacency.get(id) || []) {
          if (depth.has(next)) continue
          depth.set(next, d + 1)
          queue.push(next)
        }
      }
      const missing = nodes.filter((n) => !map.has(n.id))
      for (const node of missing) {
        const savedX = Number(node.x)
        const savedY = Number(node.y)
        if (Number.isFinite(savedX) && Number.isFinite(savedY) && savedX !== 0 && savedY !== 0) {
          map.set(node.id, { x: savedX, y: savedY, vx: 0, vy: 0 })
          continue
        }
        const d = depth.has(node.id) ? depth.get(node.id) : Math.max(1, Math.round(Math.sqrt(missing.length)))
        const ring = Math.min(6, d)
        const radius = 100 + ring * 128
        const angle = (missing.indexOf(node) + 0.5) * 2.399963 + (ring % 2 ? Math.PI : 0)
        map.set(node.id, { x: CENTER.x + Math.cos(angle) * radius, y: CENTER.y + Math.sin(angle) * radius, vx: 0, vy: 0 })
      }
    }

    function tickGraph(map, nodes, edges, alpha) {
      const rows = nodes.map((n) => map.get(n.id)).filter(Boolean)
      if (rows.length === 0) return
      const n = rows.length
      const k2 = 22000
      for (let i = 0; i < n; i += 1) {
        const a = rows[i]
        for (let j = i + 1; j < n; j += 1) {
          const b = rows[j]
          let dx = a.x - b.x
          let dy = a.y - b.y
          let d2 = dx * dx + dy * dy
          if (n > 400 && d2 > 240000) continue
          if (d2 < 1) { dx = (i % 2 === 0 ? 1 : -1) * 0.7; dy = (j % 2 === 0 ? 1 : -1) * 0.7; d2 = 1 }
          const dist = Math.sqrt(d2)
          const force = (k2 / d2) * alpha
          const fx = (dx / dist) * force
          const fy = (dy / dist) * force
          a.vx += fx; a.vy += fy
          b.vx -= fx; b.vy -= fy
        }
      }
      const byId = new Map(nodes.map((node, index) => [node.id, rows[index]]))
      for (const edge of edges) {
        const a = byId.get(edge.from)
        const b = byId.get(edge.to)
        if (a === undefined || b === undefined) continue
        const dx = b.x - a.x
        const dy = b.y - a.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (dist - 135) * 0.006 * alpha
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        a.vx += fx; a.vy += fy
        b.vx -= fx; b.vy -= fy
      }
      for (const row of rows) {
        row.vx += (CENTER.x - row.x) * 0.0016 * alpha
        row.vy += (CENTER.y - row.y) * 0.0016 * alpha
        row.vx *= 0.84
        row.vy *= 0.84
        row.x += clamp(row.vx, -40, 40)
        row.y += clamp(row.vy, -40, 40)
      }
    }

    /* ───────────────────────── 侧栏图标 ───────────────────────── */
    function ReconIcon(props) {
      const size = props && Number.isFinite(props.size) ? props.size : 20
      return h('svg', { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true, style: { display: 'block' } },
        h('g', { stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linecap': 'round' },
          h('path', { d: 'M12 5.6 6.4 10.2M12 5.6l5.6 4.6M6.4 10.2l2.1 6.1M17.6 10.2l-2.1 6.1M8.5 16.3h7' })),
        h('g', { fill: 'currentColor' },
          h('circle', { cx: 12, cy: 4.6, r: 2.2 }),
          h('circle', { cx: 5.6, cy: 10.6, r: 1.8, opacity: 0.85 }),
          h('circle', { cx: 18.4, cy: 10.6, r: 1.8, opacity: 0.85 }),
          h('circle', { cx: 7.9, cy: 17.2, r: 1.6, opacity: 0.7 }),
          h('circle', { cx: 16.1, cy: 17.2, r: 1.6, opacity: 0.7 })))
    }

    /* ───────────────────────── 错误边界 ───────────────────────── */
    class PanelBoundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { error: null }
      }

      static getDerivedStateFromError(error) {
        return { error }
      }

      render() {
        if (this.state.error !== null) {
          return h('div', { className: 'rc2-empty' },
            h('h3', null, '面板渲染出错'),
            h('p', null, String(this.state.error && this.state.error.message ? this.state.error.message : this.state.error)),
            h('button', { className: 'rc2-btn on', onClick: () => this.setState({ error: null }) }, '重试'))
        }
        return this.props.children
      }
    }

    /* ───────────────────────── 主界面 ───────────────────────── */
    function CockpitPage(props) {
      const t = (props && props.t) || ((key) => key)
      const [data, setData] = useState(null)
      const [error, setError] = useState(null)
      const [loading, setLoading] = useState(true)
      const [conn, setConn] = useState('connecting')
      const [selection, setSelection] = useState(null)
      const [query, setQuery] = useState('')
      /* foldOwners: 被折叠的子节点 -> 折叠它的父节点集合
         这样 A 同时是 B、C 的子节点时，B 折叠与 C 折叠各自记一次（两边都显示 +1），
         任一处点展开都能把 A 放出来（清除该子节点的全部折叠记录）。 */
      const [foldOwners, setFoldOwners] = useState(() => new Map())
      const [showVulns, setShowVulns] = useState(true)
      const [showArchived, setShowArchived] = useState(false)
      const [showThinking, setShowThinking] = useState(true)
      /* 只有思维链、没有正文的轮次折叠起来：否则几十个空气泡刷屏，看起来「输出一直不变」 */
      const [openSilent, setOpenSilent] = useState({})
      const [dockOpen, setDockOpen] = useState(true)
      const [settingsOpen, setSettingsOpen] = useState(false)
      const [view, setView] = useState({ x: 0, y: 0, k: 0.55 })
      const [provenance, setProvenance] = useState(null)
      const [commandText, setCommandText] = useState(null)
      const [chat, setChat] = useState({ messages: [], streaming: { text: '', reasoning: '' }, busy: false, tier: 'deep' })
      const [toolLines, setToolLines] = useState([])
      const [draft, setDraft] = useState('')
      const [shots, setShots] = useState([])
      const [dockTab, setDockTab] = useState('chat')
      const briefRef = useRef(null)
      const [runnerInfo, setRunnerInfo] = useState({ phase: 'idle', running: 0, checkpoint: null })
      const [pausing, setPausing] = useState(false)
      const [resuming, setResuming] = useState(false)
      const [meetingInfo, setMeetingInfo] = useState({ round: 0, reviewActive: false, reviewMinutes: 5 })
      const [meetingBusy, setMeetingBusy] = useState(false)
      /* Markdown 渲染开关：默认开，用户可一键切回原文（记忆到 localStorage） */
      const [mdOn, setMdOn] = useState(() => {
        try { return window.localStorage.getItem('rc2.mdRender') !== '0' } catch { return true }
      })
      const toggleMd = useCallback(() => {
        setMdOn((prev) => {
          const next = !prev
          try { window.localStorage.setItem('rc2.mdRender', next ? '1' : '0') } catch { /* 忽略 */ }
          return next
        })
      }, [])
      const [chatQueue, setChatQueue] = useState([])
      const [queueOpen, setQueueOpen] = useState(true)
      const [briefDraft, setBriefDraft] = useState('')
      const [briefMsgs, setBriefMsgs] = useState([])
      const [briefStream, setBriefStream] = useState('')
      const [briefBusy, setBriefBusy] = useState(false)
      const [boardEntries, setBoardEntries] = useState([])
      const [boardLimit, setBoardLimit] = useState(100)
      const [boardTotal, setBoardTotal] = useState(0)
      const [boardAgentCount, setBoardAgentCount] = useState(0)
      const [boardUserCount, setBoardUserCount] = useState(0)
      const [boardCompressCount, setBoardCompressCount] = useState(50)
      const [boardDraft, setBoardDraft] = useState('')
      const [boardKind, setBoardKind] = useState('finding')
      const [squadMembers, setSquadMembers] = useState([])
      const [squadRunning, setSquadRunning] = useState(0)
      const [roleList, setRoleList] = useState([])
      const [taskItems, setTaskItems] = useState([])
      const [taskRole, setTaskRole] = useState('web')
      const [taskStats, setTaskStats] = useState({ total: 0, open: 0, doing: 0, blocked: 0, passed: 0, failed: 0 })
      const [chatTarget, setChatTarget] = useState('lead')
      const [memberMsgs, setMemberMsgs] = useState([])
      const [memberStream, setMemberStream] = useState({ text: '', reasoning: '' })
      const [traceEvents, setTraceEvents] = useState([])
      const [traceLimit, setTraceLimit] = useState(() => {
        try {
          const saved = Number(window.localStorage.getItem('rc2.traceLimit'))
          return Number.isFinite(saved) ? Math.max(100, Math.min(5000, Math.floor(saved))) : TRACE_LIMIT
        } catch { return TRACE_LIMIT }
      })
      const [leftWidth, setLeftWidth] = useState(() => {
        try {
          const saved = Number(window.localStorage.getItem('rc2.leftWidth'))
          return Number.isFinite(saved) && saved >= 180 ? Math.min(620, saved) : 320
        } catch { return 320 }
      })
      const [traceSel, setTraceSel] = useState(null)
      const [mission, setMission] = useState(null)
      const [missionProgress, setMissionProgress] = useState(null)
      const [rightWidth, setRightWidth] = useState(() => {
        try {
          const saved = Number(window.localStorage.getItem('rc2.rightWidth'))
          return Number.isFinite(saved) && saved >= 260 ? Math.min(720, saved) : 384
        } catch { return 384 }
      })
      const [delegation, setDelegation] = useState(null)
      const [dockHeight, setDockHeight] = useState(() => {
        try {
          const saved = Number(window.localStorage.getItem('rc2.dockHeight'))
          return Number.isFinite(saved) && saved >= 140 ? Math.min(620, saved) : 320
        } catch { return 320 }
      })
      const [vulnRatio, setVulnRatio] = useState(() => {
        try {
          const saved = Number(window.localStorage.getItem('rc2.vulnRatio'))
          return Number.isFinite(saved) && saved > 0.15 && saved < 0.85 ? saved : 0.42
        } catch { return 0.42 }
      })
      const treeRef = useRef(null)
      const [traceKind, setTraceKind] = useState('all')
      const [traceNoBash, setTraceNoBash] = useState(true)
      const [traceQuery, setTraceQuery] = useState('')
      const [traceOpen, setTraceOpen] = useState({})
      const [panelSpot, setPanelSpot] = useState(null)
      const [spot, setSpot] = useState(null)
      const [spotText, setSpotText] = useState('')
      const [spotBusy, setSpotBusy] = useState(false)
      const [spawnRole, setSpawnRole] = useState('web')
      const [spawnName, setSpawnName] = useState('')
      const [spawnSkills, setSpawnSkills] = useState('')
      const [spawnPrompt, setSpawnPrompt] = useState('')
      const [spawnTier, setSpawnTier] = useState('deep')
      const [spawnTask, setSpawnTask] = useState('')
      const [files, setFiles] = useState([])
      const [uploading, setUploading] = useState(false)
      const [boardQuery, setBoardQuery] = useState('')
      const [boardKindFilter, setBoardKindFilter] = useState('all')
      const [boardAuthor, setBoardAuthor] = useState('all')
      /* 看板压缩条目的展开状态：按作者汇总块 / 单条按角色明细 */
      const [mergedBlockOpen, setMergedBlockOpen] = useState({})
      const [mergedDetailOpen, setMergedDetailOpen] = useState({})
      const [kindFilter, setKindFilter] = useState(() => new Set())
      /* 图例固定高亮：{kind} 或 {vuln:true}，null 表示不高亮；只有「全部」能清掉 */
      const [legendFocus, setLegendFocus] = useState(null)
      const [legendExpanded, setLegendExpanded] = useState(false)
      const [hiddenKinds, setHiddenKinds] = useState(() => new Set())
      const [layoutEpoch, setLayoutEpoch] = useState(0)
      const [browserPanes, setBrowserPanes] = useState([])
      /* 图谱左上角「搜索 / 筛选」面板可收起，收起后不占显示区域 */
      const [dialogState, setDialogState] = useState(null)
      const [dialogInput, setDialogInput] = useState('')
      const dialogResolver = useRef(null)
      const openDialog = useCallback((spec) => new Promise((resolve) => {
        dialogResolver.current = resolve
        setDialogInput(typeof spec.value === 'string' ? spec.value : '')
        setDialogState(spec)
      }), [])
      const closeDialog = useCallback((value) => {
        const resolve = dialogResolver.current
        dialogResolver.current = null
        setDialogState(null)
        if (typeof resolve === 'function') resolve(value)
      }, [])
      const uiPrompt = useCallback((spec) => openDialog({ kind: 'prompt', ...(typeof spec === 'string' ? { title: spec } : spec) }), [openDialog])
      const uiConfirm = useCallback((spec, detail) => openDialog({
        kind: 'confirm',
        /* 同时接受 uiConfirm('标题', '说明') 与 uiConfirm({ title, detail, okText })：
           后者曾被当成 title 对象直接渲染成 React child，点「删」就整页渲染失败。 */
        ...(typeof spec === 'string'
          ? { title: spec, detail }
          : (spec !== null && typeof spec === 'object' ? spec : { title: String(spec ?? '') })),
      }), [openDialog])
      const uiAlert = useCallback((spec, detail) => openDialog({
        kind: 'alert',
        ...(typeof spec === 'string' ? { title: spec, detail } : (spec !== null && typeof spec === 'object' ? spec : { title: String(spec ?? '') })),
      }), [openDialog])
      /* 弹窗打开时全局 Esc 关闭（焦点不在输入框时也管用） */
      useEffect(() => {
        if (dialogState === null) return undefined
        const onKey = (event) => {
          if (event.key !== 'Escape') return
          event.preventDefault()
          closeDialog(dialogState.kind === 'prompt' ? null : false)
        }
        window.addEventListener('keydown', onKey, true)
        return () => window.removeEventListener('keydown', onKey, true)
      }, [dialogState, closeDialog])
      const [hudOpen, setHudOpen] = useState(() => {
        try { return window.localStorage.getItem('rc2.hudOpen') !== '0' } catch { return true }
      })
      const toggleHud = useCallback((next) => {
        setHudOpen((prev) => {
          const value = typeof next === 'boolean' ? next : !prev
          try { window.localStorage.setItem('rc2.hudOpen', value ? '1' : '0') } catch { /* 忽略 */ }
          return value
        })
      }, [])
      const lastEngagementId = useRef(null)
      const [menu, setMenu] = useState(null)
      const [usage, setUsage] = useState({ input: 0, output: 0, total: 0, turns: 0 })
      const fileInputRef = useRef(null)

      const positions = useRef(new Map())
      const [, bump] = useReducer((n) => n + 1, 0)
      const canvasRef = useRef(null)
      const chatRef = useRef(null)
      const viewRef = useRef(view)
      const dataRef = useRef(null)
      const sim = useRef({ alpha: 0, running: false, raf: 0 })
      const inited = useRef(false)
      const pointer = useRef({ mode: null, id: null, dx: 0, dy: 0, px: 0, py: 0 })
      const saveTimer = useRef(0)
      const refreshTimer = useRef(0)
      const refreshSeq = useRef(0)
      const arrowId = useMemo(() => `rc2-arrow-${Math.random().toString(36).slice(2, 8)}`, [])

      viewRef.current = view
      dataRef.current = data

      const engagement = data && data.engagement ? data.engagement : null
      const engagements = data && Array.isArray(data.engagements) ? data.engagements : []
      const nodes = engagement ? engagement.nodes : []
      const edges = engagement ? engagement.edges : []
      const vulns = engagement ? engagement.vulns : []
      const commands = engagement ? engagement.commands : []
      const stats = engagement ? engagement.stats : null
      const uiCfg = (data && data.config && data.config.ui) || {}
      const accent = uiCfg.accent || 'cyan'
      const rootClass = `rc2${uiCfg.glow !== false ? ' rc2-glow' : ''}${uiCfg.grid === false ? ' rc2-no-grid' : ''}`

      /* ── 拉取 ── */
      const refresh = useCallback(async (engId) => {
        const seq = ++refreshSeq.current
        const res = await api({ op: 'overview', engagement: engId })
        /* 轮询和 SSE 可能同时刷新；只接受最后一次请求，避免旧响应覆盖新项目/新状态。 */
        if (seq !== refreshSeq.current) return res
        if (res && res.ok) {
          setData(res)
          setError(null)
          /* 切项目：清空坐标并触发一次强制重排（否则节点画不出来） */
          const nextEngId = res.engagement ? res.engagement.id : null
          if (nextEngId !== null && nextEngId !== lastEngagementId.current) {
            lastEngagementId.current = nextEngId
            positions.current.clear()
            inited.current = false
            setLayoutEpoch((value) => value + 1)
            /* 在同一个刷新回调里先清项目级状态；下面新的 board/squad/trace/task 数据会再覆盖。 */
            setChatQueue([])
            setFiles([])
            setShots([])
            setToolLines([])
            setBoardAuthor('all')
            setBoardQuery('')
            setBoardKindFilter('all')
            setKindFilter(new Set())
            setHiddenKinds(new Set())
            setShowArchived(false)
            setShowVulns(true)
            setTaskRole('web')
            setSelection(null)
            setMemberMsgs([])
            setMemberStream({ text: '', reasoning: '' })
            setBriefMsgs([])
            setBriefStream('')
            setMission(null)
            setMissionProgress(null)
          }
          if (Array.isArray(res.board)) setBoardEntries(res.board)
          if (Number.isFinite(res.boardLimit)) setBoardLimit(res.boardLimit)
          if (Number.isFinite(res.boardTotal)) setBoardTotal(res.boardTotal)
          if (Number.isFinite(res.boardAgentCount)) setBoardAgentCount(res.boardAgentCount)
          if (Number.isFinite(res.boardUserCount)) setBoardUserCount(res.boardUserCount)
          if (res.chat && res.chat.usage) setUsage(res.chat.usage)
          if (res.squad) {
            setSquadMembers(res.squad.members || [])
            setSquadRunning(res.squad.running || 0)
          }
          if (Array.isArray(res.roles)) setRoleList(res.roles)
          if (Array.isArray(res.trace)) setTraceEvents(res.trace)
          if (Number.isFinite(res.traceLimit)) {
            setTraceLimit(res.traceLimit)
            try { window.localStorage.setItem('rc2.traceLimit', String(res.traceLimit)) } catch { /* 忽略 */ }
          }
          void api({ op: 'mission.get', engagement: res.engagement ? res.engagement.id : undefined }).then((mres) => {
            if (!mres || !mres.ok) return
            setMission(mres.mission || null)
            setMissionProgress(mres.progress || null)
          })
          if (res.delegation) setDelegation(res.delegation)
          if (Array.isArray(res.browsers)) setBrowserPanes(res.browsers)
          if (res.tasks) {
            setTaskItems(res.tasks.items || [])
            setTaskStats(res.tasks.stats || { total: 0, open: 0, doing: 0, blocked: 0, passed: 0, failed: 0 })
          }
          if (res.chat) {
            setChat((prev) => ({
              messages: res.chat.messages || [],
              streaming: prev.busy && res.chat.busy ? prev.streaming : { text: '', reasoning: '' },
              busy: Boolean(res.chat.busy),
              tier: res.chat.tier || prev.tier,
            }))
          }
        } else {
          setError(res && res.error ? res.error : '读取失败')
        }
        setLoading(false)
        return res
      }, [t])

      const scheduleRefresh = useCallback((engId) => {
        clearTimeout(refreshTimer.current)
        refreshTimer.current = setTimeout(() => { void refresh(engId) }, 220)
      }, [refresh])

      useEffect(() => { void refresh() }, [refresh])

      const chatTargetKey = chatTarget.startsWith('member:') ? chatTarget.slice(7) : (chatTarget.startsWith('role:') ? '' : chatTarget)
      const chatTargetRole = chatTarget.startsWith('role:') ? chatTarget.slice(5) : ''
      const chatTargetMember = chatTarget.startsWith('member:')
        ? squadMembers.find((member) => member.key === chatTargetKey)
        : null
      const targetBusy = chatTarget === 'lead' ? chat.busy === true : chatTargetMember !== null && chatTargetMember !== undefined && (chatTargetMember.status === 'running' || chatTargetMember.status === 'starting')
      const chatTargetKeyRef = useRef(chatTargetKey)
      chatTargetKeyRef.current = chatTargetKey
      useEffect(() => {
        /* 在岗队员被回收后自动回到总指挥；按角色对话不受影响 */
        if (chatTarget === 'lead' || chatTargetRole !== '') return undefined
        if (squadMembers.some((member) => member.key === chatTargetKey)) return undefined
        setChatTarget('lead')
        return undefined
      }, [chatTarget, chatTargetKey, chatTargetRole, squadMembers])

      useEffect(() => {
        setSquadRunning(squadMembers.filter((row) => row.status === 'running').length)
      }, [squadMembers])

      useEffect(() => {
        let cancelled = false
        if (chatTarget === 'lead' || chatTargetKey === '' || chatTargetRole !== '') return undefined
        api({ op: 'squad.transcript', member: chatTargetKey, engagement: engagement ? engagement.id : undefined }).then((res) => {
          if (cancelled) return
          if (res && res.ok) setMemberMsgs(res.messages || [])
        })
        return () => { cancelled = true }
      }, [chatTarget, chatTargetKey, chatTargetRole])

      /* 没有靶标时清空所有项目级状态，避免空态仍显示上一个项目的对话/看板。 */
      useEffect(() => {
        if (engagement !== null && engagement !== undefined) return
        setChatQueue([])
        setFiles([])
        setShots([])
        setToolLines([])
        setBoardEntries([])
        setSquadMembers([])
        setTraceEvents([])
        setTaskItems([])
        setTaskStats({ total: 0, open: 0, doing: 0, blocked: 0, passed: 0, failed: 0 })
        setChat((prev) => ({ ...prev, messages: [], streaming: { text: '', reasoning: '' }, busy: false }))
        setMemberMsgs([])
        setMemberStream({ text: '', reasoning: '' })
        setBriefMsgs([])
        setBriefStream('')
        setMission(null)
        setMissionProgress(null)
      }, [engagement === null || engagement === undefined ? '' : engagement.id])

      /* ── SSE ── */
      useEffect(() => {
        let source
        try {
          source = new EventSource(apiUrl('/recon/stream'))
        } catch {
          setConn('offline')
          return undefined
        }
        source.onopen = () => setConn('live')
        source.onerror = () => setConn('offline')
        source.onmessage = (event) => {
          let payload
          try { payload = JSON.parse(event.data) } catch { return }
          const current = dataRef.current && dataRef.current.engagement ? dataRef.current.engagement.id : null
          if (payload.type === 'hello') { setConn('live'); return }
          if (payload.type === 'graph') {
            if (payload.engagementId === current) scheduleRefresh(current)
            return
          }
          if (payload.engagementId !== undefined && current !== null && payload.engagementId !== current) return
          /* 汇报席事件独立处理：绝不写进 chat 的 messages / streaming */
          if (payload.type === 'brief.delta') {
            setBriefStream((prev) => prev + payload.text)
            return
          }
          if (payload.type === 'brief.message') {
            const msg = payload.message || {}
            if ((msg.text || '') === '' && (msg.reasoning || '') === '') { setBriefStream(''); return }
            setBriefMsgs((prev) => prev.filter((m) => m.id !== msg.id).concat([msg]))
            setBriefStream('')
            return
          }
          if (payload.type === 'brief.status') {
            setBriefBusy(payload.status === 'running')
            return
          }
          if (payload.type === 'brief.error') {
            setBriefBusy(false)
            setBriefStream('')
            setBriefMsgs((prev) => prev.concat([{ id: `be_${Date.now()}`, role: 'assistant', text: `汇报席出错：${payload.text || '未知错误'}` }]))
            return
          }
          if (payload.type === 'brief.user') {
            const msg = payload.message || {}
            setBriefMsgs((prev) => prev.concat([msg]))
            return
          }
          if (payload.type === 'brief.cleared') {
            setBriefMsgs([])
            setBriefStream('')
            return
          }
          if (payload.type === 'chat.delta') {
            setChat((prev) => ({ ...prev, streaming: { ...prev.streaming, text: prev.streaming.text + payload.text } }))
          } else if (payload.type === 'chat.reasoning') {
            setChat((prev) => ({ ...prev, streaming: { ...prev.streaming, reasoning: prev.streaming.reasoning + payload.text } }))
          } else if (payload.type === 'chat.user' || payload.type === 'chat.message') {
            const msg = payload.message || {}
            const hasBody = (msg.text || '') !== '' || (msg.reasoning || '') !== ''
            /* 只有工具调用的中间轮会发空记录：丢掉它，别插空气泡、也别清掉正在增长的文字 */
            if (payload.type === 'chat.message' && hasBody === false) return
            setChat((prev) => {
              const list = prev.messages.filter((m) => m.id !== msg.id)
              list.push(msg)
              return {
                ...prev,
                messages: list,
                streaming: payload.type === 'chat.message' && hasBody ? { text: '', reasoning: '' } : prev.streaming,
              }
            })
          } else if (payload.type === 'chat.tool') {
            setToolLines((prev) => [...prev.slice(-60), { id: `t${Date.now()}${Math.random()}`, kind: 'call', name: payload.name, text: payload.args }])
          } else if (payload.type === 'chat.tool-result') {
            setToolLines((prev) => [...prev.slice(-60), { id: `r${Date.now()}${Math.random()}`, kind: 'result', ok: payload.ok, text: payload.text }])
          } else if (payload.type === 'browser') {
            /* 实时更新左侧浏览器画面 */
            const entry = payload.entry
            if (entry === null || entry === undefined) { scheduleRefresh(current); return }
            setBrowserPanes((prev) => {
              const row = {
                key: entry.key,
                name: entry.actor && entry.actor.name ? entry.actor.name : '指挥席',
                role: entry.actor && entry.actor.role ? entry.actor.role : 'lead',
                action: entry.action || 'goto',
                url: entry.url || '',
                title: entry.title || '',
                shot: entry.shot || null,
                status: entry.status || 'idle',
                error: entry.error || '',
                ageMs: 0,
              }
              const rest = prev.filter((item) => item.key !== row.key)
              const next = [...rest, row]
              const rank = (item) => (item.status === 'running' ? 0 : item.status === 'error' ? 2 : 1)
              next.sort((a, b) => rank(a) - rank(b) || Number(a.ageMs || 0) - Number(b.ageMs || 0))
              return next
            })
          } else if (payload.type === 'browser.shot') {
            scheduleRefresh(current)
          } else if (payload.type === 'chat.status') {
            setChat((prev) => ({ ...prev, busy: payload.status === 'running' }))
          } else if (payload.type === 'chat.turn-end') {
            setChat((prev) => ({ ...prev, busy: false, streaming: { text: '', reasoning: '' } }))
          } else if (payload.type === 'chat.error') {
            setChat((prev) => ({ ...prev, busy: false }))
            setToolLines((prev) => [...prev.slice(-60), { id: `e${Date.now()}`, kind: 'error', text: payload.text }])
          } else if (payload.type === 'chat.cleared') {
            setChat((prev) => ({ ...prev, messages: [], streaming: { text: '', reasoning: '' } }))
            setToolLines([])
          } else if (payload.type === 'board.post') {
            setBoardEntries((prev) => (prev.some((row) => row.id === payload.entry.id) ? prev : [...prev, payload.entry]))
          } else if (payload.type === 'board.update') {
            setBoardEntries((prev) => {
              const exists = prev.some((row) => row.id === payload.entry.id)
              if (!exists) return [...prev, payload.entry]
              return prev.map((row) => (row.id === payload.entry.id ? payload.entry : row))
            })
          } else if (payload.type === 'board.remove') {
            setBoardEntries((prev) => prev.filter((row) => row.id !== payload.id))
          } else if (payload.type === 'squad.spawn' || payload.type === 'squad.status' || payload.type === 'squad.remove') {
            if (payload.type === 'squad.remove') {
              setSquadMembers((prev) => prev.filter((row) => row.key !== payload.key))
            } else {
              setSquadMembers((prev) => {
                const rest = prev.filter((row) => row.key !== payload.member.key)
                return [payload.member, ...rest]
              })
            }
            scheduleRefresh(current)
          } else if (payload.type === 'squad.group') {
            scheduleRefresh(current)
          } else if (payload.type === 'trace') {
            const event = payload.event
            if (event !== null && event !== undefined) {
              setTraceEvents((prev) => (prev.some((row) => row.id === event.id) ? prev : [...prev.slice(-(Math.max(TRACE_BUFFER_MAX, traceLimit) - 1)), event]))
            }
          } else if (payload.type === 'squad.chat') {
            if (payload.key === chatTargetKeyRef.current) {
              setMemberMsgs((prev) => (prev.some((m) => m.id === payload.message.id) ? prev : [...prev, payload.message]))
            }
          } else if (payload.type === 'squad.message') {
            if (payload.key === chatTargetKeyRef.current) {
              setMemberMsgs((prev) => (prev.some((m) => m.id === payload.message.id) ? prev : [...prev, payload.message]))
              setMemberStream({ text: '', reasoning: '' })
            }
          } else if (payload.type === 'squad.delta') {
            if (payload.key === chatTargetKeyRef.current) setMemberStream((prev) => ({ ...prev, text: prev.text + payload.text }))
            setSquadMembers((prev) => prev.map((row) => (row.key === payload.key
              ? { ...row, lastText: `${row.lastText || ''}${payload.text}`, status: 'running' }
              : row)))
          } else if (payload.type === 'squad.tool') {
            setSquadMembers((prev) => prev.map((row) => (row.key === payload.key ? { ...row, lastTool: payload.name } : row)))
          } else if (payload.type === 'squad.error') {
            setToolLines((prev) => [...prev.slice(-60), { id: `se${Date.now()}`, kind: 'error', text: `${payload.key || ''} ${payload.text || '成员出错'}` }])
          } else if (payload.type === 'chat.usage') {
            setUsage(payload.usage)
          } else if (payload.type === 'delta') {
            scheduleRefresh(current)
          } else if (payload.type === 'config') {
            void refresh(current)
          }
        }
        return () => { try { source.close() } catch { /* 已关 */ } }
      }, [refresh, scheduleRefresh, traceLimit])

      /* ── 轮询兜底 ── */
      useEffect(() => {
        const timer = setInterval(() => {
          const current = dataRef.current && dataRef.current.engagement ? dataRef.current.engagement.id : undefined
          void refresh(current)
        }, conn === 'live' ? 15000 : 4000)
        return () => clearInterval(timer)
      }, [conn, refresh])

      /* ── 选中副作用：来源命令 / 命令输出 ── */
      useEffect(() => {
        let cancelled = false
        setProvenance(null)
        setCommandText(null)
        if (selection === null) return undefined
        const engId = engagement ? engagement.id : undefined
        if (selection.type === 'node') {
          api({ op: 'provenance', nodeId: selection.id, engagement: engagement ? engagement.id : undefined }).then((res) => {
            if (!cancelled && res && res.ok) setProvenance(res)
          })
        } else if (selection.type === 'command') {
          api({ op: 'command', commandId: selection.id, engagement: engagement ? engagement.id : undefined }).then((res) => {
            if (!cancelled) setCommandText(res && res.ok ? { text: res.text, command: res.command } : { text: res && res.error ? res.error : '' })
          })
        }
        return () => { cancelled = true }
      }, [selection, engagement && engagement.id])

      /* ── 前端派生：度数 / 出边子节点（store 不存 degree） ── */
      const degreeMap = useMemo(() => {
        const map = new Map()
        for (const edge of edges) {
          map.set(edge.from, (map.get(edge.from) || 0) + 1)
          map.set(edge.to, (map.get(edge.to) || 0) + 1)
        }
        return map
      }, [edges])

      const childrenMap = useMemo(() => {
        const map = new Map()
        for (const edge of edges) {
          if (!map.has(edge.from)) map.set(edge.from, [])
          map.get(edge.from).push(edge.to)
        }
        return map
      }, [edges])

      /* ── 折叠：被折叠节点 + 它们的全部后代都隐藏 ── */
      const hidden = useMemo(() => {
        const out = new Set()
        if (foldOwners.size === 0) return out
        const outgoing = childrenMap
        for (const foldedId of foldOwners.keys()) {
          if (foldedId === undefined) continue
          const queue = [...(outgoing.get(foldedId) || [])]
          if (!out.has(foldedId)) out.add(foldedId)
          const seen = new Set([foldedId])
          while (queue.length > 0) {
            const id = queue.shift()
            if (seen.has(id)) continue
            seen.add(id)
            out.add(id)
            for (const next of outgoing.get(id) || []) queue.push(next)
          }
        }
        return out
      }, [foldOwners, childrenMap])

      /* 每个父节点自己折叠了多少后代（徽标 +N 独立计算） */
      const collapsedCounts = useMemo(() => {
        const counts = new Map()
        if (foldOwners.size === 0) return counts
        const outgoing = childrenMap
        for (const [foldedId, owners] of foldOwners) {
          const seen = new Set()
          const queue = [...(outgoing.get(foldedId) || [])]
          while (queue.length > 0) {
            const id = queue.shift()
            if (seen.has(id)) continue
            seen.add(id)
            for (const next of outgoing.get(id) || []) queue.push(next)
          }
          for (const owner of owners) {
            counts.set(owner, (counts.get(owner) || 0) + 1 + seen.size)
          }
        }
        return counts
      }, [foldOwners, childrenMap])

      /* 某个节点当前是否"折叠着自己的子节点"（决定按钮显示折叠还是展开） */
      const ownsFold = useCallback((id) => {
        for (const owners of foldOwners.values()) if (owners.has(id)) return true
        return false
      }, [foldOwners])

      const visibleNodes = useMemo(() => nodes.filter((n) => !hidden.has(n.id)
        && (showArchived || n.archived !== true)
        && (kindFilter.size === 0 || kindFilter.has(n.kind))
        && !hiddenKinds.has(n.kind)), [hidden, showArchived, kindFilter, hiddenKinds, nodes])
      const visibleEdges = useMemo(() => {
        const allow = new Set(visibleNodes.map((n) => n.id))
        return edges.filter((e) => allow.has(e.from) && allow.has(e.to))
      }, [edges, visibleNodes])

      /* ── 模拟 ── */
      useEffect(() => {
        if (nodes.length === 0) return
        ensurePositions(positions.current, nodes, edges)
        if (!inited.current) {
          inited.current = true
          requestAnimationFrame(() => fit())
        }
        startSimulation(0.9)
        /* 切换项目后必须重新布局：engagement.id 变化也算依赖 */
      }, [layoutEpoch, engagement && engagement.id, nodes.length])

      const startSimulation = useCallback((alpha) => {
        sim.current.alpha = Math.max(sim.current.alpha, alpha)
        if (sim.current.running) return
        sim.current.running = true
        const step = () => {
          const current = dataRef.current && dataRef.current.engagement
          if (current === null || current === undefined) { sim.current.running = false; return }
          tickGraph(positions.current, current.nodes, current.edges, Math.max(0.15, sim.current.alpha))
          bump()
          sim.current.alpha *= 0.972
          if (sim.current.alpha > 0.03) sim.current.raf = requestAnimationFrame(step)
          else { sim.current.running = false; persistLayout() }
        }
        sim.current.raf = requestAnimationFrame(step)
      }, [])

      useEffect(() => () => { if (sim.current.raf) cancelAnimationFrame(sim.current.raf) }, [])

      const persistLayout = useCallback(() => {
        clearTimeout(saveTimer.current)
        saveTimer.current = setTimeout(() => {
          const rows = Array.from(positions.current, ([id, p]) => ({ id, x: p.x, y: p.y }))
          const eng = dataRef.current && dataRef.current.engagement ? dataRef.current.engagement.id : undefined
          if (rows.length > 0) api({ op: 'saveLayout', positions: rows, engagement: eng })
        }, 900)
      }, [])

      const toWorld = useCallback((clientX, clientY) => {
        const rect = canvasRef.current ? canvasRef.current.getBoundingClientRect() : { left: 0, top: 0 }
        const v = viewRef.current
        return { x: (clientX - rect.left - v.x) / v.k, y: (clientY - rect.top - v.y) / v.k }
      }, [])

      const onPointerDown = useCallback((event) => {
        const target = event.target
        let nodeEl = target && typeof target.closest === 'function' ? target.closest('[data-node-id]') : null
        if (nodeEl === null || nodeEl === undefined) {
          /* 指针捕获后 target 会被重定向到 <svg>，用坐标做一次命中测试 */
          const probe = document.elementFromPoint(event.clientX, event.clientY)
          nodeEl = probe && typeof probe.closest === 'function' ? probe.closest('[data-node-id]') : null
        }
        const world = toWorld(event.clientX, event.clientY)
        if (nodeEl !== null && nodeEl !== undefined) {
          const raw = String(nodeEl.getAttribute('data-node-id'))
          if (raw.startsWith('vuln:')) { setSelection({ type: 'vuln', id: raw.slice(5) }); return }
          /* 双击（同一节点 400ms 内两次按下）= 折叠/展开子树 */
          const pos = positions.current.get(raw)
          if (pos !== undefined) {
            pointer.current = { mode: 'node', id: raw, dx: world.x - pos.x, dy: world.y - pos.y, px: event.clientX, py: event.clientY, captured: false, moved: false }
            setSelection({ type: 'node', id: raw })
          }
          return
        }
        pointer.current = { mode: 'pan', id: null, dx: 0, dy: 0, px: event.clientX, py: event.clientY, sx: event.clientX, sy: event.clientY }
        event.currentTarget.setPointerCapture(event.pointerId)
      }, [toWorld])

      const onPointerMove = useCallback((event) => {
        const state = pointer.current
        if (state.mode === 'pan') {
          const v = viewRef.current
          setView({ x: v.x + (event.clientX - state.px), y: v.y + (event.clientY - state.py), k: v.k })
          state.px = event.clientX
          state.py = event.clientY
          return
        }
        if (state.mode === 'node') {
          const world = toWorld(event.clientX, event.clientY)
          const pos0 = positions.current.get(state.id)
          if (pos0 !== undefined && (Math.abs(event.clientX - state.px) > 2 || Math.abs(event.clientY - state.py) > 2)) state.moved = true
          if (state.captured !== true) {
            /* 真正开始拖动才捕获指针：单击/双击期间不捕获，避免 dblclick 被吃掉 */
            state.captured = true
            try { event.currentTarget.setPointerCapture(event.pointerId) } catch { /* 忽略 */ }
          }
          const pos = positions.current.get(state.id)
          if (pos !== undefined) {
            pos.x = world.x - state.dx
            pos.y = world.y - state.dy
            pos.vx = 0
            pos.vy = 0
            startSimulation(0.22)
            bump()
          }
        }
      }, [startSimulation, toWorld])

      const onPointerUp = useCallback((event) => {
        const state = pointer.current
        const dragged = state.mode === 'node' && state.moved === true
        const wasPan = state.mode === 'pan'
        const moved = wasPan && state.sx !== undefined
          ? Math.abs(event.clientX - state.sx) + Math.abs(event.clientY - state.sy)
          : 999
        pointer.current = { mode: null, id: null, dx: 0, dy: 0, px: 0, py: 0 }
        try { event.currentTarget.releasePointerCapture(event.pointerId) } catch { /* 已释放 */ }
        if (dragged) persistLayout()
        /* 点空白（非拖拽平移）→ 取消选中 */
        if (wasPan && moved < 5) {
          setSelection(null)
          setMenu(null)
        }
      }, [persistLayout])

      /* 画布可能晚于挂载才出现（首屏 loading / 空态），所以用 callback ref 绑定滚轮：
         节点一挂上就绑定，卸载就解绑——不再依赖 effect 的首次执行时机。 */
      const wheelCleanup = useRef(null)
      const attachCanvas = useCallback((node) => {
        if (wheelCleanup.current !== null) {
          try { wheelCleanup.current() } catch { /* 已解绑 */ }
          wheelCleanup.current = null
        }
        canvasRef.current = node
        if (node === null || node === undefined) return
        const onWheel = (event) => {
          event.preventDefault()
          const rect = node.getBoundingClientRect()
          const mx = event.clientX - rect.left
          const my = event.clientY - rect.top
          const v = viewRef.current
          /* 触控板捏合在 Chrome 里是 ctrlKey+wheel：步长更细 */
          const step = event.ctrlKey ? 1.04 : 1.14
          const factor = event.deltaY < 0 ? step : 1 / step
          const nextK = clamp(v.k * factor, 0.12, 3.4)
          if (nextK === v.k) return
          setView({
            x: mx - ((mx - v.x) * nextK) / v.k,
            y: my - ((my - v.y) * nextK) / v.k,
            k: nextK,
          })
        }
        node.addEventListener('wheel', onWheel, { passive: false })
        wheelCleanup.current = () => node.removeEventListener('wheel', onWheel)
      }, [])

      useEffect(() => () => {
        if (wheelCleanup.current !== null) {
          try { wheelCleanup.current() } catch { /* 已解绑 */ }
          wheelCleanup.current = null
        }
      }, [])

      const fit = useCallback((retry = true) => {
        const element = canvasRef.current
        if (element === null || element === undefined) return
        const rect = element.getBoundingClientRect()
        const rows = Array.from(positions.current.values())
        if (rows.length === 0) return
        if (rect.width === 0 || rect.height === 0) {
          if (retry) requestAnimationFrame(() => fit(false))
          return
        }
        let minX = Infinity; let minY = Infinity; let maxX = -Infinity; let maxY = -Infinity
        for (const row of rows) {
          minX = Math.min(minX, row.x); minY = Math.min(minY, row.y)
          maxX = Math.max(maxX, row.x); maxY = Math.max(maxY, row.y)
        }
        const pad = 90
        const width = Math.max(220, maxX - minX + pad * 2)
        const height = Math.max(180, maxY - minY + pad * 2)
        const k = clamp(Math.min(rect.width / width, rect.height / height), 0.16, 1.5)
        setView({ x: (rect.width - (maxX - minX) * k) / 2 - minX * k, y: (rect.height - (maxY - minY) * k) / 2 - minY * k, k })
      }, [])

      const focusNode = useCallback((id) => {
        const element = canvasRef.current
        const pos = positions.current.get(id)
        if (element === null || element === undefined || pos === undefined) return
        const rect = element.getBoundingClientRect()
        const k = Math.max(0.8, viewRef.current.k)
        setView({ x: rect.width / 2 - pos.x * k, y: rect.height / 2 - pos.y * k, k })
      }, [])

      const toggleCollapse = useCallback((id) => {
        setFoldOwners((prev) => {
          const next = new Map()
          for (const [child, owners] of prev) next.set(child, new Set(owners))
          const ownsNow = Array.from(next.values()).some((owners) => owners.has(id))
          if (ownsNow) {
            /* 展开：把自己折叠的每个子节点彻底放出——连同其他父节点对它的折叠记录一起清掉，
               所以「A 同时是 B、C 的子节点」时，B 或 C 任一处点展开都能把 A 放出来。 */
            for (const [child, owners] of Array.from(next.entries())) {
              if (owners.has(id)) next.delete(child)
            }
            /* 自己若被别人折叠着，也一并展开，避免"展开后自己还藏着" */
            next.delete(id)
            return next
          }
          const kids = childrenMap.get(id) || []
          /* 叶子节点没有可折叠的子树；隐藏自己会导致无法再次点开。 */
          if (kids.length === 0) return next
          for (const kid of kids) {
            const owners = next.get(kid) || new Set()
            owners.add(id)
            next.set(kid, owners)
          }
          return next
        })
      }, [childrenMap])

      /* ── 操作 ── */
      const uploadFiles = useCallback(async (fileList) => {
        if (engagement === null) return
        const picks = Array.from(fileList || []).slice(0, 12)
        if (picks.length === 0) return
        setUploading(true)
        for (const file of picks) {
          if (!file || file.size > 24 * 1024 * 1024) continue
          const base64 = await new Promise((resolvePromise) => {
            const reader = new FileReader()
            reader.onload = () => {
              const dataUrl = String(reader.result || '')
              resolvePromise(dataUrl.includes(',') ? dataUrl.slice(dataUrl.indexOf(',') + 1) : '')
            }
            reader.readAsDataURL(file)
          })
          if (base64 === '') continue
          if (/^image\//.test(file.type)) {
            setShots((prev) => [...prev.slice(-3), {
              id: `shot${Date.now()}${Math.random().toString(36).slice(2, 5)}`,
              name: file.name || 'image.png',
              mediaType: file.type || 'image/png',
              dataUrl: `data:${file.type || 'image/png'};base64,${base64}`,
              base64,
            }])
            continue
          }
          const res = await api({ op: 'chat.upload', engagement: engagement.id, name: file.name, base64 })
          if (res && res.ok && res.file) setFiles((prev) => [...prev.slice(-11), res.file])
        }
        setUploading(false)
      }, [engagement])

      /* ── 消息投递（lead / 队员 / 按角色）── */
      const deliver = useCallback(async (job) => {
        const text = String(job.text || '').trim()
        if (text === '') return
        setDockOpen(true)
        setDockTab('chat')
        if (job.target && job.target !== 'lead') {
          const memberKey = job.target.startsWith('member:') ? job.target.slice(7) : undefined
          const roleId = job.target.startsWith('role:') ? job.target.slice(5) : undefined
          const res = await api({
            op: 'squad.chat',
            member: memberKey,
            role: roleId,
            engagement: engagement ? engagement.id : undefined,
            text,
          })
          if (res && res.ok && res.member && roleId !== undefined) setChatTarget(`member:${res.member.key}`)
          if (!res || !res.ok) setToolLines((prev) => [...prev.slice(-40), { id: `e${Date.now()}`, kind: 'error', text: res && res.error ? res.error : '发送失败' }])
          return
        }
        const res = await api({
          op: 'chat.send',
          text,
          tier: job.tier || chat.tier,
          images: job.images || [],
          attachments: job.attachments || [],
          interrupt: job.interrupt === true,
          engagement: engagement ? engagement.id : undefined,
        })
        if (!res || !res.ok) setToolLines((prev) => [...prev.slice(-40), { id: `e${Date.now()}`, kind: 'error', text: res && res.error ? res.error : '发送失败' }])
      }, [chat.tier, engagement])

      const queuePush = useCallback((job) => {
        setChatQueue((prev) => prev.concat([{ ...job, id: `q_${Date.now().toString(36)}_${prev.length}` }]))
        setQueueOpen(true)
      }, [])

      /* 队列项「插入发送」：打断正在跑的这轮，立刻发 */
      const queueInterrupt = useCallback(async (item) => {
        setChatQueue((prev) => prev.filter((row) => row.id !== item.id))
        if (engagement !== null) await api({ op: 'chat.stop', engagement: engagement.id })
        await deliver({ ...item, interrupt: true })
      }, [deliver, engagement])

      const sendText = useCallback(async (text) => {
        const message = String(text || '').trim()
        if (message === '') return
        setDockOpen(true)
        setDockTab('chat')
        const res = await api({ op: 'chat.send', text: message, tier: chat.tier, engagement: engagement ? engagement.id : undefined })
        if (!res || !res.ok) setToolLines((prev) => [...prev.slice(-40), { id: `e${Date.now()}`, kind: 'error', text: res && res.error ? res.error : '发送失败' }])
      }, [chat.tier, engagement])

      const sendChat = useCallback(async () => {
        const text = draft.trim()
        const hasFiles = files.length > 0
        if (text === '' && !hasFiles && shots.length === 0) return

        const job = {
          text: text !== ''
            ? text
            : `我上传了 ${files.length} 个文件，请先读取内容（路径已在附件清单里），再判断它们能说明什么、该往图谱里落什么。`,
          target: chatTarget,
          tier: shots.length > 0 ? 'vision' : chat.tier,
          images: chatTarget === 'lead' ? shots.map((shot) => ({ mediaType: shot.mediaType, name: shot.name, base64: shot.base64 })) : [],
          attachments: chatTarget === 'lead' ? files : [],
        }
        setDraft('')
        setFiles([])
        if (shots.length > 0 && chatTarget === 'lead') setShots([])
        if (chatTarget !== 'lead') setMemberStream({ text: '', reasoning: '' })

        /* 队列模式（默认）：正在跑或队列里还有没发完的，就排到队尾 */
        if (targetBusy || chatQueue.length > 0) {
          queuePush(job)
          return
        }
        await deliver(job)
      }, [targetBusy, chat.tier, chatQueue.length, chatTarget, deliver, draft, files, queuePush, shots])

      /* 运行状态：按钮和顶部 chip 都靠它；暂停/继续之后会立刻重拉，不等 30 秒轮询 */
      const loadRunner = useCallback(async () => {
        if (engagement === null) {
          setRunnerInfo({ phase: 'idle', running: 0, checkpoint: null })
          return null
        }
        const res = await api({ op: 'runner.status', engagement: engagement.id })
        if (!res || !res.ok) return null
        const next = { phase: res.phase || 'idle', running: res.running || 0, checkpoint: res.checkpoint || null }
        setRunnerInfo(next)
        return next
      }, [engagement])

      useEffect(() => {
        let alive = true
        const load = async () => { if (alive) await loadRunner() }
        void load()
        const timer = setInterval(() => { void load() }, 30000)
        return () => { alive = false; clearInterval(timer) }
      }, [loadRunner])

      useEffect(() => {
        if (runnerInfo.phase !== 'pausing') return undefined
        const timer = setInterval(() => { void loadRunner() }, 1000)
        return () => clearInterval(timer)
      }, [runnerInfo.phase, loadRunner])

      const pauseRunner = useCallback(async () => {
        if (engagement === null) return
        setPausing(true)
        const res = await api({ op: 'runner.pause', engagement: engagement.id, reason: 'manual' })
        if (!res || !res.ok) {
          setPausing(false)
          void uiAlert('中断失败', res && res.error ? res.error : '未知错误')
          return
        }
        /* 先拉到真实状态（phase 变 paused → 按钮切到「继续」），再收起 busy，文案不会串位 */
        const fresh = await loadRunner()
        if (fresh === null) setRunnerInfo((prev) => ({ ...prev, phase: 'paused', running: 0, checkpoint: res.checkpoint || prev.checkpoint }))
        setPausing(false)
        void refresh(engagement.id)
      }, [engagement, loadRunner])

      const resumeRunner = useCallback(async () => {
        if (engagement === null) return
        setResuming(true)
        const res = await api({ op: 'runner.resume', engagement: engagement.id })
        if (!res || !res.ok) {
          setResuming(false)
          void uiAlert('继续失败', res && res.error ? res.error : '未知错误')
          return
        }
        const fresh = await loadRunner()
        if (fresh === null) setRunnerInfo((prev) => ({ ...prev, phase: 'running' }))
        setResuming(false)
        void refresh(engagement.id)
        setDockTab('board')
      }, [engagement, loadRunner])

      useEffect(() => {
        if (engagement === null) { setMeetingInfo({ round: 0, reviewActive: false, reviewMinutes: 5 }); return }
        let alive = true
        const load = async () => {
          const res = await api({ op: 'meeting.status', engagement: engagement.id })
          if (!alive || !res || !res.ok) return
          const meeting = res.meeting || {}
          setMeetingInfo({
            round: meeting.round || 0,
            reviewActive: meeting.reviewActive === true,
            reviewMinutes: Number(meeting.reviewMinutes) || 5,
          })
        }
        void load()
        const timer = setInterval(() => { void load() }, 45000)
        return () => { alive = false; clearInterval(timer) }
      }, [engagement === null ? '' : engagement.id])

      const stopChat = useCallback(async () => {
        if (engagement === null) return
        await api({ op: 'chat.stop', engagement: engagement.id })
      }, [engagement])

      const exportJson = useCallback(() => {
        if (engagement === null) return
        const payload = {
          engagement: { id: engagement.id, name: engagement.name, scope: engagement.scope },
          stats, nodes, edges, vulns,
          commands: commands.map((c) => ({ id: c.id, command: c.command, exitCode: c.exitCode, startedAt: c.startedAt, source: c.source })),
        }
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `recon-${engagement.name}-${Date.now()}.json`
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
        setTimeout(() => URL.revokeObjectURL(url), 2000)
      }, [commands, edges, engagement, nodes, stats, vulns])

      /* ── 派生数据 ── */
      const needle = query.trim().toLowerCase()
      const filteredNodes = useMemo(() => {
        const pool = showArchived ? nodes : nodes.filter((n) => n.archived !== true)
        const list = needle === ''
          ? pool
          : pool.filter((n) => `${n.value} ${n.label} ${n.ip || ''} ${n.port || ''} ${(n.tech || []).join(' ')} ${(n.tags || []).join(' ')} ${n.note || ''}`.toLowerCase().includes(needle))
        return list.slice(0, 60)
      }, [needle, nodes, showArchived])

      const feedVulns = useMemo(() => {
        const active = new Set(nodes.filter((n) => showArchived || n.archived !== true).map((n) => n.id))
        return vulns.filter((v) => active.has(v.nodeId))
          .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
          .slice(0, 300)
      }, [nodes, showArchived, vulns])

      const selectedNode = selection !== null && selection.type === 'node' ? (nodes.find((n) => n.id === selection.id) ?? null) : null
      const selectedVuln = selection !== null && selection.type === 'vuln' ? (vulns.find((v) => v.id === selection.id) ?? null) : null
      const selectedCommand = selection !== null && selection.type === 'command'
        ? (commands.find((c) => c.id === selection.id)
          ?? (commandText && commandText.command ? { id: selection.id, command: commandText.command, source: 'history' } : null))
        : null

      /* 多根 + 全路径高亮：把「所有根 → 选中节点」的路径并集算出来
         - roots：kind=root，或入度为 0 的节点（可能有多个根）
         - 祖先集：从选中节点沿边反向 BFS
         - 高亮边：两端都在祖先集内，且方向在「祖先 → 选中」的子图上 */
      const pathHighlight = useMemo(() => {
        if (selectedNode === null) return null
        const incoming = new Map()
        const outgoing = new Map()
        for (const edge of edges) {
          if (edge === null || edge === undefined) continue
          if (!outgoing.has(edge.from)) outgoing.set(edge.from, [])
          outgoing.get(edge.from).push(edge.to)
          if (!incoming.has(edge.to)) incoming.set(edge.to, [])
          incoming.get(edge.to).push(edge.from)
        }
        const nodeIds = new Set(nodes.map((node) => node.id))
        const roots = nodes.filter((node) => node.kind === 'root' || !(incoming.get(node.id) || []).length).map((node) => node.id)
        /* 反向可达：所有祖先 */
        const ancestors = new Set([selectedNode.id])
        const queue = [selectedNode.id]
        while (queue.length > 0) {
          const current = queue.shift()
          for (const prev of incoming.get(current) || []) {
            if (!nodeIds.has(prev) || ancestors.has(prev)) continue
            ancestors.add(prev)
            queue.push(prev)
          }
        }
        /* 只在「根可达 且 能到选中」的子图上保留边：正向从根 BFS 标记 */
        const reachableFromRoot = new Set()
        const fq = roots.filter((id) => ancestors.has(id))
        for (const id of fq) reachableFromRoot.add(id)
        while (fq.length > 0) {
          const current = fq.shift()
          for (const next of outgoing.get(current) || []) {
            if (!ancestors.has(next) || reachableFromRoot.has(next)) continue
            reachableFromRoot.add(next)
            fq.push(next)
          }
        }
        const pathEdges = new Set()
        for (const edge of edges) {
          if (edge === null || edge === undefined) continue
          if (reachableFromRoot.has(edge.from) && ancestors.has(edge.to)) pathEdges.add(edge.id)
        }
        /* 选中节点的直接子树：从它的每个直接子节点往下整棵收（下游） */
        const descendants = new Set()
        const downQueue = [...(outgoing.get(selectedNode.id) || [])]
        while (downQueue.length > 0) {
          const current = downQueue.shift()
          if (descendants.has(current)) continue
          descendants.add(current)
          for (const next of outgoing.get(current) || []) downQueue.push(next)
        }
        const downstream = new Set()
        for (const edge of edges) {
          if (edge === null || edge === undefined) continue
          const fromSelected = edge.from === selectedNode.id
          const insideTree = descendants.has(edge.from) && descendants.has(edge.to)
          if (fromSelected && descendants.has(edge.to)) downstream.add(edge.id)
          else if (insideTree) downstream.add(edge.id)
        }
        return {
          nodes: new Set([...reachableFromRoot, ...descendants]),
          edges: new Set([...pathEdges, ...downstream]),
          downstream,
          roots,
          rootCount: roots.length,
          depth: (() => {
            /* 选中节点的最短根距离，用于详情卡显示 */
            let level = 0
            let layer = new Set([selectedNode.id])
            const seen = new Set([selectedNode.id])
            while (layer.size > 0 && level < 40) {
              const next = new Set()
              for (const id of layer) {
                for (const prev of incoming.get(id) || []) {
                  if (seen.has(prev)) continue
                  seen.add(prev)
                  if (roots.includes(prev)) return level + 1
                  next.add(prev)
                }
              }
              if (next.size === 0) break
              layer = next
              level += 1
            }
            return level
          })(),
        }
      }, [edges, nodes, selectedNode])
      /* ── 图例固定高亮：命中的节点亮，其余变暗；点「全部」才取消 ── */
      const legendNodeIds = (() => {
        if (legendFocus === null) return null
        if (legendFocus.vuln === true) {
          const hit = new Set()
          for (const node of nodes) {
            if (showArchived !== true && node.archived === true) continue
            const has = (node.vulnIds || []).length > 0
              || vulns.some((vuln) => vuln.nodeId === node.id)
            if (has) hit.add(node.id)
          }
          return hit
        }
        const wanted = String(legendFocus.kind || '')
        const hit = new Set()
        for (const node of nodes) {
          if (showArchived !== true && node.archived === true) continue
          if (String(node.kind || 'note') === wanted) hit.add(node.id)
        }
        return hit
      })()
      const neighborIds = legendNodeIds !== null
        ? legendNodeIds
        : (pathHighlight === null ? null : pathHighlight.nodes)

      const vulnSpots = (() => {
        const map = new Map()
        if (!showVulns) return map
        const byNode = new Map()
        const visibleIdSet = new Set(visibleNodes.map((node) => node.id))
        for (const vuln of vulns) {
          if (!visibleIdSet.has(vuln.nodeId)) continue
          if (!byNode.has(vuln.nodeId)) byNode.set(vuln.nodeId, [])
          byNode.get(vuln.nodeId).push(vuln)
        }
        for (const [nodeId, list] of byNode) {
          const base = positions.current.get(nodeId)
          if (base === undefined) continue
          list.forEach((vuln, index) => {
            const angle = -Math.PI / 2 + (index - (list.length - 1) / 2) * 0.72
            map.set(vuln.id, { x: base.x + Math.cos(angle) * 64, y: base.y + Math.sin(angle) * 64, host: nodeId })
          })
        }
        return map
      })()

      const radiusOf = (node) => 10 + Math.min(9, Math.sqrt(degreeMap.get(node.id) || node.degree || 0) * 3.2) + (node.seed ? 4 : 0)

      /* ── SVG ── */
      const edgeEls = []
      const visibleIds = new Set(visibleNodes.map((node) => node.id))
      for (const edge of visibleEdges) {
        if (!visibleIds.has(edge.from) || !visibleIds.has(edge.to)) continue
        const a = positions.current.get(edge.from)
        const b = positions.current.get(edge.to)
        if (a === undefined || b === undefined) continue
        const na = nodes.find((n) => n.id === edge.from)
        const nb = nodes.find((n) => n.id === edge.to)
        const ra = na ? radiusOf(na) : 10
        const rb = nb ? radiusOf(nb) : 10
        const dx = b.x - a.x
        const dy = b.y - a.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const x1 = a.x + (dx / dist) * ra
        const y1 = a.y + (dy / dist) * ra
        const x2 = b.x - (dx / dist) * (rb + 5)
        const y2 = b.y - (dy / dist) * (rb + 5)
        const onPath = pathHighlight !== null && pathHighlight.edges.has(edge.id)
        const isDownstream = pathHighlight !== null && pathHighlight.downstream.has(edge.id)
        const dim = legendNodeIds !== null
          ? !(legendNodeIds.has(edge.from) && legendNodeIds.has(edge.to))
          : (pathHighlight !== null && !onPath)
        edgeEls.push(h('line', {
          key: `e-${edge.id}`, x1, y1, x2, y2,
          stroke: dim ? 'var(--dsw-alias-border-l1)'
            : (legendNodeIds !== null ? 'color-mix(in srgb, var(--rc-accent) 52%, transparent)'
              : (isDownstream ? 'color-mix(in srgb, #34d399 62%, transparent)' : 'color-mix(in srgb, var(--rc-accent) 46%, transparent)')),
          'stroke-width': dim ? 0.7 : (isDownstream ? 1.15 : 1.35),
          'stroke-dasharray': DASH_EDGES.has(edge.type) ? '4 4' : undefined,
          'marker-end': `url(#${arrowId})`,
          opacity: dim ? 0.28 : 0.9,
        }))
        if (view.k > 0.95) {
          edgeEls.push(h('text', {
            key: `el-${edge.id}`, x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 3,
            'text-anchor': 'middle', 'font-size': 8.6 / Math.max(0.35, view.k),
            fill: 'var(--dsw-alias-label-secondary)', opacity: dim ? 0.2 : 0.8,
            style: { pointerEvents: 'none' },
          }, edge.label || edge.type))
        }
      }
      for (const [vulnId, spot] of vulnSpots) {
        const base = positions.current.get(spot.host)
        if (base === undefined) continue
        const vuln = vulns.find((v) => v.id === vulnId)
        if (vuln === undefined) continue
        edgeEls.push(h('line', {
          key: `ve-${vulnId}`, x1: base.x, y1: base.y, x2: spot.x, y2: spot.y,
          stroke: SEV_COLOR[vuln.severity] || SEV_COLOR.info, 'stroke-width': 1,
          'stroke-dasharray': '2 3', opacity: 0.65,
        }))
      }

      const nodeEls = []
      for (const node of visibleNodes) {
        const pos = positions.current.get(node.id)
        if (pos === undefined) continue
        const r = radiusOf(node)
        const color = colorOfKind(node.kind)
        const selected = selectedNode !== null && selectedNode.id === node.id
        const dim = neighborIds !== null && !neighborIds.has(node.id)
        const nodeVulns = showVulns ? vulns.filter((v) => v.nodeId === node.id) : []
        const isCollapsed = ownsFold(node.id)
        const childCount = collapsedCounts.get(node.id) || 0
        nodeEls.push(h('g', {
          key: `n-${node.id}`,
          'data-node-id': node.id,
          className: 'rc2-node',
          opacity: dim ? 0.32 : 1,
          onContextMenu: (event) => {
            event.preventDefault()
            event.stopPropagation()
            setSelection({ type: 'node', id: node.id })
            setMenu({ x: event.clientX, y: event.clientY, id: node.id })
          },
          /* 双击节点 = 折叠/展开子树（原生 dblclick 不受 pointer capture 影响） */
          onDoubleClick: (event) => {
            event.stopPropagation()
            toggleCollapse(node.id)
          },
        },
          selected ? h('circle', { cx: pos.x, cy: pos.y, r: r + 7, fill: 'none', stroke: 'var(--rc-accent)', 'stroke-width': 1, opacity: 0.55 })
            : null,
          h('circle', {
            cx: pos.x, cy: pos.y, r,
            fill: color,
            'fill-opacity': node.kind === 'note' ? 0.7 : 0.9,
            stroke: selected ? 'var(--rc-accent)' : (node.seed ? '#e2e8f0' : 'transparent'),
            'stroke-width': selected ? 2.6 : (node.seed ? 1.5 : 0),
            style: { filter: selected ? 'drop-shadow(0 0 10px var(--rc-accent))' : undefined },
          }),
          h('text', {
            x: pos.x, y: pos.y + r + 12 / Math.max(0.35, view.k),
            'text-anchor': 'middle', 'font-size': 10.5 / Math.max(0.35, view.k),
            fill: 'var(--dsw-alias-label-primary)', opacity: view.k > 0.26 ? 1 : 0,
          }, shortText(node.label || node.value, view.k > 0.9 ? 32 : 18)),
          nodeVulns.length > 0 ? h('circle', {
            cx: pos.x + r * 0.8, cy: pos.y - r * 0.8,
            r: 3.6 + Math.min(2.4, nodeVulns.length * 0.5),
            fill: SEV_COLOR[nodeVulns.slice().sort((x, y) => (SEV_ORDER[x.severity] ?? 9) - (SEV_ORDER[y.severity] ?? 9))[0].severity] || SEV_COLOR.info,
            stroke: 'var(--dsw-alias-bg-base)', 'stroke-width': 1,
          }) : null,
          isCollapsed ? h('g', null,
            h('circle', { cx: pos.x + r + 6, cy: pos.y, r: 7, fill: 'var(--rc-accent)', opacity: 0.9 }),
            h('text', { x: pos.x + r + 6, y: pos.y + 3.4, 'text-anchor': 'middle', 'font-size': 9, fill: '#04121a', style: { fontWeight: 700 } }, `+${childCount}`)) : null))
      }
      for (const [vulnId, spot] of vulnSpots) {
        const vuln = vulns.find((v) => v.id === vulnId)
        if (vuln === undefined) continue
        const selected = selectedVuln !== null && selectedVuln.id === vuln.id
        const color = SEV_COLOR[vuln.severity] || SEV_COLOR.info
        nodeEls.push(h('g', { key: `vn-${vuln.id}`, 'data-node-id': `vuln:${vuln.id}`, className: 'rc2-node' },
          h('rect', {
            x: spot.x - 6.5, y: spot.y - 6.5, width: 13, height: 13, rx: 2,
            transform: `rotate(45 ${spot.x} ${spot.y})`, fill: color,
            stroke: selected ? 'var(--rc-accent)' : 'var(--dsw-alias-bg-base)', 'stroke-width': selected ? 2.2 : 1.1,
          })))
      }

      /* ── 顶部栏 ── */
      const topbar = h('div', { className: 'rc2-top' },
        h('div', { className: 'rc2-brand' },
          h('span', { className: 'rc2-logo' }, h(ReconIcon, { size: 22, active: true })),
          h('div', null,
            h('h1', null, t('title')),
            h('small', null, engagement !== null ? `${t('cockpit')} · ${engagement.name}` : t('subtitle')))),
        h('div', { className: 'rc2-projects' },
          h('span', { className: 'rc2-meta' }, '项目'),
          h('select', {
            className: 'rc2-select',
            value: engagement === null ? '' : engagement.id,
            title: '切换项目',
            onChange: async (event) => {
              const res = await api({ op: 'select', engagement: event.target.value })
              if (res && res.ok) {
                positions.current.clear(); inited.current = false
                setSelection(null); setFoldOwners(new Map()); setTraceSel(null); setChatTarget('lead')
                const fresh = await refresh(res.activeId || event.target.value)
                const freshNodes = fresh && fresh.engagement ? (fresh.engagement.nodes || []) : []
                if (freshNodes.length > 0) {
                  ensurePositions(positions.current, freshNodes, fresh.engagement.edges || [])
                  inited.current = true
                  startSimulation(0.9)
                  requestAnimationFrame(() => fit())
                }
              }
            },
          },
          engagement === null ? h('option', { value: '' }, '（无项目）') : null,
          engagements.map((row) => h('option', { key: row.id, value: row.id },
            `${row.name} · ${row.stats.nodes}资产/${row.stats.vulns}漏洞/${row.stats.commands}命令`))),
          h('button', {
            className: 'rc2-btn on',
            title: '新建一个完全空白的项目',
            onClick: async () => {
              const name = await uiPrompt({
                title: '新建项目',
                detail: '空白项目，不继承任何资产 / 命令 / 对话',
                value: `项目-${new Date().toLocaleDateString('zh-CN').replace(/\//g, '')}`,
                okText: '下一步',
              })
              if (name === null || name.trim() === '') return
              const scopeText = await uiPrompt({ title: '授权范围', detail: '可留空，多个用逗号分隔', value: '', okText: '创建' })
              if (scopeText === null) return
              const scope = scopeText.split(',').map((x) => x.trim()).filter(Boolean)
              const res = await api({ op: 'create', name: name.trim(), scope })
              if (res && res.ok) {
                positions.current.clear(); inited.current = false
                setSelection(null); setFoldOwners(new Map()); setTraceSel(null)
                /* 新项目默认就是跟总指挥对话 */
                setChatTarget('lead')
                setMemberStream({ text: '', reasoning: '' })
                void refresh(res.activeId)
                setDockOpen(true); setDockTab('chat')
              }
            },
          }, '＋ 新项目'),
        engagement !== null && runnerInfo.phase !== 'paused'
          ? h('button', {
            className: 'rc2-btn ghost',
            title: '等待当前模型输出和工具执行结束后冻结，不再发起下一步模型请求',
            disabled: pausing || resuming || runnerInfo.phase === 'pausing',
            onClick: () => void pauseRunner(),
          }, (pausing || runnerInfo.phase === 'pausing')
            ? h('span', { className: 'rc2-busy' }, '◌ 等待当前步骤结束…')
            : '⏸ 中断')
          : null,
        engagement !== null && runnerInfo.phase === 'paused'
          ? h('button', {
            className: 'rc2-btn on',
            title: runnerInfo.checkpoint
              ? `断点：${new Date(runnerInfo.checkpoint.savedAt).toLocaleString('zh-CN')} · 未完成 ${runnerInfo.checkpoint.pending} 条`
              : '从断点继续',
            disabled: pausing || resuming,
            onClick: () => void resumeRunner(),
          }, resuming ? h('span', { className: 'rc2-busy' }, '◌ 启动中…') : '▶ 继续')
          : null,
        h('button', {
          className: 'rc2-btn ghost',
          title: engagement === null ? '先选中一个项目' : `删除项目「${engagement.name}」`,
          disabled: engagement === null,
          onClick: async () => {
            if (engagement === null) return
            const ok = await uiConfirm(
              `删除项目「${engagement.name}」`,
              '会连同它的资产、关系、漏洞、命令日志、看板、任务、轨迹、截图与对话一起删除，不可恢复。',
            )
            if (!ok) return
            const res = await api({ op: 'delete', engagement: engagement.id })
            if (!res || !res.ok) {
              void uiAlert('删除失败', res && res.error ? res.error : '未知错误')
              return
            }
            positions.current.clear(); inited.current = false
            setSelection(null); setFoldOwners(new Map()); setTraceSel(null); setPanelSpot(null); setSpot(null)
            await refresh(res.activeId || undefined)
            if ((res.engagements || []).length === 0) void uiAlert('已删除', '最后一个项目已删除，点「＋ 新项目」重新开始')
          },
        }, '🗑 删除项目'),
        h('button', {
          className: 'rc2-btn ghost danger',
          title: engagements.length === 0 ? '当前没有项目' : `清空全部 ${engagements.length} 个项目`,
          disabled: engagements.length === 0,
          onClick: async () => {
            const first = await uiConfirm(
              `清空全部 ${engagements.length} 个项目`,
              '所有项目的资产、漏洞、命令、看板、任务、轨迹、截图、对话都会被删除；配置与密钥保留。',
            )
            if (!first) return
            const typed = await uiPrompt({
              title: '确认清空',
              detail: '这是不可恢复的操作，请输入「清空」两个字确认',
              value: '', placeholder: '清空', okText: '确认清空',
            })
            if (typed === null || typed.trim() !== '清空') return
            const res = await api({ op: 'deleteAll', confirm: true })
            if (!res || !res.ok) {
              void uiAlert('清空失败', res && res.error ? res.error : '未知错误')
              return
            }
            positions.current.clear(); inited.current = false
            setSelection(null); setFoldOwners(new Map()); setTraceSel(null); setPanelSpot(null); setSpot(null)
            void refresh()
            void uiAlert('已清空', `删除了 ${res.removed} 个项目`)
          },
        }, '⌫ 清空全部')),
        h('span', { className: 'rc2-spacer' }),
        stats !== null ? h('span', { className: 'rc2-chip' }, t('assets'), h('b', null, stats.nodes)) : null,
        stats !== null ? h('span', { className: 'rc2-chip' }, 'links', h('b', null, stats.edges)) : null,
        stats !== null ? h('span', { className: 'rc2-chip warn' }, t('vulns'), h('b', null, stats.vulns)) : null,
        delegation !== null && delegation.total > 0
          ? h('span', {
            className: 'rc2-chip',
            title: `命令由谁执行：成员 ${delegation.delegated} 条 / 总指挥自己 ${delegation.own} 条`,
          }, '下派 ', h('b', null, `${delegation.delegated}/${delegation.total}`))
          : null,
        stats !== null ? h('span', { className: 'rc2-chip' }, t('commands'), h('b', null, stats.commands)) : null,
        usage.total > 0 ? h('span', { className: 'rc2-chip', title: `输入 ${usage.input} · 输出 ${usage.output} · ${usage.turns} 段` }, 'tokens ', h('b', null, usage.total)) : null,
        h('span', { className: 'rc2-chip' },
          h('span', { className: `rc2-dot${conn === 'live' ? ' pulse' : ''}`, style: conn === 'live' ? undefined : { background: 'var(--dsw-alias-state-idle-primary)', boxShadow: 'none' } }),
          conn === 'live' ? t('connected') : (conn === 'connecting' ? t('connecting') : t('offline'))),
        h('button', { className: 'rc2-btn ghost', onClick: exportJson, disabled: engagement === null }, t('exportJson')),
        h('button', {
          className: `rc2-btn ghost${mdOn ? ' on' : ''}`,
          title: mdOn ? '对话 / 看板 / 汇报 正在按 Markdown 渲染；点一下显示原始文本' : '当前显示原始文本；点一下恢复 Markdown 渲染',
          onClick: () => toggleMd(),
        }, mdOn ? 'MD 渲染' : '原文'),
        h('button', { className: `rc2-btn${settingsOpen ? ' on' : ''}`, onClick: () => setSettingsOpen(true) }, '⚙ ' + t('settings')))

      /* ── 左：命令流 ── */
      /* ── 左：轨迹（谁在什么时候做了什么） ── */
      const TRACE_KINDS = {
        task: { label: '拆任务', color: '#22d3ee' },
        verdict: { label: '验收', color: '#facc15' },
        dispatch: { label: '派活', color: '#38bdf8' },
        member: { label: '队员', color: '#a78bfa' },
        skill: { label: '技能', color: '#f472b6' },
        tool: { label: '工具', color: '#94a3b8' },
        command: { label: '命令', color: '#34d399' },
        graph: { label: '图谱', color: '#fb923c' },
        chat: { label: '对话', color: '#cbd5e1' },
        nudge: { label: '催办', color: '#f43f5e' },
        plan: { label: '方案', color: '#a3e635' },
        result: { label: '结果', color: '#7dd3fc' },
      }
      const ACTOR_COLOR = {
        commander: '#22d3ee', lead: '#22d3ee', staff: '#38bdf8', scout: '#34d399',
        web: '#fb923c', hunter: '#fb923c', browser: '#c084fc', reverser: '#c084fc',
        intranet: '#f472b6', qa: '#facc15', analyst: '#38bdf8', system: '#94a3b8', user: '#e2e8f0',
      }
      const traceFiltered = traceEvents
        .filter((row) => (traceNoBash ? !(row.kind === 'command' && (row.actor || {}).name === 'bash') : true))
        .filter((row) => (traceKind === 'all' ? true : row.kind === traceKind))
        .filter((row) => {
          const needle = traceQuery.trim().toLowerCase()
          if (needle === '') return true
          const actor = row.actor || {}
          return `${row.title || ''} ${row.detail || ''} ${actor.name || ''} ${row.kind}`.toLowerCase().includes(needle)
        })

      const traceRow = (row) => {
        const meta = TRACE_KINDS[row.kind] || { label: row.kind, color: '#64748b' }
        const actor = row.actor || {}
        const refs = row.refs || {}
        const open = traceOpen[row.id] === true
        const hasDetail = String(row.detail || '').trim() !== ''
        const chips = []
        if (typeof refs.commandId === 'string' && refs.commandId !== '') {
          chips.push(h('button', {
            key: 'c', className: 'rc2-refchip',
            onClick: (event) => { event.stopPropagation(); openSpot('command', refs.commandId) },
          }, `命令 ${refs.commandId}`))
        }
        if (typeof refs.taskId === 'string' && refs.taskId !== '') {
          chips.push(h('button', {
            key: 't', className: 'rc2-refchip',
            onClick: (event) => { event.stopPropagation(); setDockOpen(true); setDockTab('task') },
          }, `任务 ${refs.taskId}`))
        }
        if (Array.isArray(refs.vulnIds) && refs.vulnIds.length > 0) {
          chips.push(h('button', {
            key: 'v', className: 'rc2-refchip',
            onClick: (event) => { event.stopPropagation(); setSelection({ type: 'vuln', id: refs.vulnIds[0] }) },
          }, `漏洞 ${refs.vulnIds[0]}`))
        }
        if (Array.isArray(refs.nodeIds) && refs.nodeIds.length > 0) {
          chips.push(h('button', {
            key: 'n', className: 'rc2-refchip',
            onClick: (event) => { event.stopPropagation(); focusNode(refs.nodeIds[0]) },
          }, `节点 ${refs.nodeIds[0]}`))
        }
        return h('div', {
          key: row.id,
          className: `rc2-trace${open ? ' open' : ''}`,
          onClick: () => setTraceOpen((prev) => ({ ...prev, [row.id]: !prev[row.id] })),
        },
        h('div', { className: 'rc2-trace-head' },
          h('span', { className: 'rc2-tk', style: { background: `${meta.color}22`, color: meta.color, borderColor: `${meta.color}55` } }, meta.label),
          h('span', { className: 'rc2-trace-actor', style: { color: ACTOR_COLOR[actor.role] || '#94a3b8' } }, actor.name || actor.role || '-'),
          h('span', { className: 'rc2-meta' }, fmtTime(new Date(row.ts).toISOString())),
          h('span', { className: 'rc2-spacer' }),
          hasDetail ? h('span', { className: 'rc2-meta' }, open ? '▾' : '▸') : null),
        h('div', { className: 'rc2-trace-title' }, row.title || ''),
        hasDetail ? h('div', { className: 'rc2-trace-detail' }, row.detail) : null,
        chips.length > 0 ? h('div', { className: 'rc2-trace-refs' }, chips) : null)
      }

      /* ── 左：轨迹树（时间桶并行带 + 泳道） ── */
      const ROW_H = 46
      const PAD_TOP = 10
      const treeRows = traceFiltered.slice(-400)
      const laneOf = new Map()
      const laneKeys = []
      const laneKeyOf = (row) => {
        const actor = row.actor || {}
        /* 只认名字：内部 ID 不再作为身份参与分组 */
        if (typeof actor.name === 'string' && actor.name !== '') return `${actor.role || 'member'}:${actor.name}`
        return `${actor.role || 'system'}:${actor.name || '系统'}`
      }
      for (const row of treeRows) {
        const key = laneKeyOf(row)
        if (!laneOf.has(key)) { laneOf.set(key, laneKeys.length); laneKeys.push(key) }
      }
      const leadIdx = laneKeys.findIndex((key) => key.startsWith('lead:') || key.startsWith('commander:'))
      if (leadIdx > 0) {
        const [leadKey] = laneKeys.splice(leadIdx, 1)
        laneKeys.unshift(leadKey)
        laneKeys.forEach((key, index) => laneOf.set(key, index))
      }
      const laneCount = Math.max(1, laneKeys.length)
      const laneBand = Math.min(leftWidth * 0.34, Math.max(30, laneCount * 22))
      const LANE_GAP = Math.max(15, laneBand / laneCount)
      const nodeXRight = Math.max(96, leftWidth - 16)
      const laneX = (index) => nodeXRight - index * LANE_GAP
      const labelRight = (laneKeys.length > 0 ? laneX(laneKeys.length - 1) : nodeXRight) - 12
      const laneColorOf = (key) => ACTOR_COLOR[key.split(':')[0]] || '#64748b'

      /* 并行带：相邻动作间隔 ≤6s 且出现 ≥2 个执行者 → 视为多 Agent 并行推进 */
      const BURST_GAP_MS = 6000
      const bursts = []
      for (const row of treeRows) {
        const last = bursts[bursts.length - 1]
        if (last === undefined || row.ts - last.rows[last.rows.length - 1].ts > BURST_GAP_MS) {
          bursts.push({ rows: [row] })
        } else {
          last.rows.push(row)
        }
      }
      for (const burst of bursts) {
        burst.actors = Array.from(new Set(burst.rows.map((row) => laneKeyOf(row))))
        burst.parallel = burst.actors.length > 1 && burst.rows.length > 1
      }
      let cursorY = PAD_TOP
      const layout = new Map()
      const burstTop = new Map()
      for (const burst of bursts) {
        const top = cursorY
        if (burst.parallel) cursorY += 14
        for (const row of burst.rows) {
          layout.set(row.id, { y: cursorY + ROW_H / 2 })
          cursorY += ROW_H
        }
        burstTop.set(burst, top)
        cursorY += burst.parallel ? 16 : 6
      }
      const treeHeight = cursorY + PAD_TOP
      const yOf = (row) => (layout.get(row.id) || { y: 0 }).y

      const textWidth = (text, size) => {
        let width = 0
        for (const ch of String(text || '')) width += ch.charCodeAt(0) > 0x2e80 ? size : size * 0.56
        return width
      }
      const fitText = (text, maxPx, size) => {
        const source = String(text || '').replace(/\s+/g, ' ').trim()
        if (source === '') return ''
        let used = 0
        let out = ''
        for (const ch of source) {
          const w = ch.charCodeAt(0) > 0x2e80 ? size : size * 0.56
          if (used + w > maxPx) return out + '…'
          out += ch
          used += w
        }
        return out
      }

      const lastInLane = new Map()
      const links = []
      const taskIndex = new Map()
      const memberIndex = new Map()
      for (const row of treeRows) {
        const key = laneKeyOf(row)
        const lane = laneOf.get(key)
        const y = yOf(row)
        const prev = lastInLane.get(key)
        if (prev !== undefined) {
          links.push({ kind: 'lane', x1: laneX(prev.lane), y1: prev.y, x2: laneX(lane), y2: y, color: laneColorOf(key) })
        }
        lastInLane.set(key, { lane, y })
        const refs = row.refs || {}
        if (typeof refs.taskId === 'string') taskIndex.set(refs.taskId, { lane, y, index: treeRows.indexOf(row) })
        if (row.kind === 'member' && typeof refs.memberKey === 'string') memberIndex.set(refs.memberKey, { lane, y })
      }
      for (const row of treeRows) {
        const refs = row.refs || {}
        const lane = laneOf.get(laneKeyOf(row))
        if (row.kind === 'dispatch' && typeof refs.memberKey === 'string') {
          const target = memberIndex.get(refs.memberKey)
          if (target !== undefined && target.y > yOf(row)) {
            links.push({ kind: 'cross', x1: laneX(lane), y1: yOf(row), x2: laneX(target.lane), y2: target.y, color: '#38bdf8' })
          }
        }
        if (row.kind === 'verdict' && typeof refs.taskId === 'string') {
          const origin = taskIndex.get(refs.taskId)
          if (origin !== undefined && origin.y < yOf(row)) {
            links.push({ kind: 'cross', x1: laneX(origin.lane), y1: origin.y, x2: laneX(lane), y2: yOf(row), color: '#facc15' })
          }
        }
      }

      const treeSvg = treeRows.length === 0 ? null : h('svg', {
        width: leftWidth, height: treeHeight, viewBox: `0 0 ${leftWidth} ${treeHeight}`, style: { display: 'block' },
      },
      h('defs', null,
        h('filter', { id: 'rc2glow', x: '-60%', y: '-60%', width: '220%', height: '220%' },
          h('feGaussianBlur', { stdDeviation: '2.4', result: 'blur' }),
          h('feMerge', null, h('feMergeNode', { in: 'blur' }), h('feMergeNode', { in: 'source' })))),
      bursts.filter((burst) => burst.parallel).map((burst, index) => {
        const top = burstTop.get(burst)
        const height = burst.rows.length * ROW_H
        const lanes = burst.rows.map((row) => laneOf.get(laneKeyOf(row)))
        const minX = laneX(Math.max(...lanes))
        const maxX = laneX(Math.min(...lanes))
        return h('g', { key: `b${index}` },
          h('rect', {
            x: 4, y: top, width: leftWidth - 8, height, rx: 7,
            fill: 'rgba(34,211,238,.05)', stroke: 'rgba(34,211,238,.22)', strokeWidth: 1, strokeDasharray: '6 4',
          }),
          h('text', { x: 10, y: top + 12, fontSize: 8.6, fill: '#67e8f9', fillOpacity: 0.95 },
            `⇄ ${burst.actors.length} Agent 并行 · ${burst.rows.length} 步`),
          h('line', {
            x1: minX - 6, y1: top + 6, x2: maxX + 6, y2: top + 6,
            stroke: '#22d3ee', strokeOpacity: 0.4, strokeWidth: 1.6, strokeDasharray: '5 3',
          }))
      }),
      links.map((link, index) => (link.kind === 'lane'
        ? h('line', {
          key: `l${index}`, x1: link.x1, y1: link.y1, x2: link.x2, y2: link.y2,
          stroke: link.color, strokeWidth: 2.2, strokeOpacity: 0.5, strokeLinecap: 'round',
        })
        : h('path', {
          key: `c${index}`,
          d: `M ${link.x1} ${link.y1} C ${link.x1} ${(link.y1 + link.y2) / 2}, ${link.x2} ${(link.y1 + link.y2) / 2}, ${link.x2} ${link.y2}`,
          fill: 'none', stroke: link.color, strokeWidth: 1.6, strokeOpacity: 0.55, strokeDasharray: '4 4',
        }))),
      treeRows.map((row) => {
        const key = laneKeyOf(row)
        const lane = laneOf.get(key)
        const meta = TRACE_KINDS[row.kind] || { label: row.kind, color: '#64748b' }
        const x = laneX(lane)
        const y = yOf(row)
        const selected = traceSel === row.id
        const actor = row.actor || {}
        const actorColor = ACTOR_COLOR[actor.role] || '#94a3b8'
        const label = fitText(row.title || '', Math.max(60, labelRight - 12), 11)
        const identityLine = fitText(`${actor.name || actor.role || '-'} · ${meta.label}`, 152, 9.4)
        const identityWidth = Math.min(200, textWidth(identityLine, 9.4) + 14)
        const ioRaw = (row.meta && (row.meta.out || row.meta.input)) || row.detail || ''
        const ioBudget = Math.max(0, labelRight - identityWidth - 74)
        const ioLine = ioBudget > 34 ? fitText(ioRaw, ioBudget, 9.2) : ''
        return h('g', {
          key: row.id,
          style: { cursor: 'pointer' },
          onClick: () => setTraceSel(selected ? null : row.id),
        },
        h('title', null, `${meta.label} · ${actor.name || ''} · ${row.title || ''}`),
        selected ? h('circle', { cx: x, cy: y, r: 15, fill: meta.color, fillOpacity: 0.16 }) : null,
        h('circle', {
          cx: x, cy: y, r: selected ? 8.6 : 6.6,
          fill: meta.color, stroke: '#04070c', strokeWidth: 1.6,
          filter: selected ? 'url(#rc2glow)' : undefined,
        }),
        h('circle', { cx: x, cy: y, r: selected ? 3 : 2.2, fill: '#04070c', fillOpacity: 0.6 }),
        h('line', {
          x1: labelRight + 3, y1: y - 1, x2: x - (selected ? 10 : 8), y2: y - 1,
          stroke: meta.color, strokeOpacity: selected ? 0.65 : 0.26, strokeWidth: 1.2,
        }),
        /* 第 1 行：动作标题（右对齐到标签列） */
        h('text', {
          x: labelRight, y: y - 6, textAnchor: 'end', fontSize: 11,
          fill: '#e8eef6', fillOpacity: selected ? 1 : 0.96,
        }, label),
        /* 第 2 行：时间 + IO 摘要（左起），身份徽章（右对齐） */
        h('text', {
          x: 8, y: y + 11, fontSize: 9.2, fill: '#94a3b8',
        }, `${fmtTime(new Date(row.ts).toISOString())}${ioLine !== '' ? ` · ${ioLine}` : ''}`),
        h('rect', {
          x: labelRight - identityWidth, y: y + 2.5, width: identityWidth, height: 12.5, rx: 3,
          fill: actorColor, fillOpacity: 0.18, stroke: actorColor, strokeOpacity: 0.5, strokeWidth: 0.8,
        }),
        h('text', {
          x: labelRight - 5, y: y + 11.8, textAnchor: 'end', fontSize: 9.4,
          fill: actorColor, fillOpacity: 1,
        }, identityLine))
      }))

      const traceSelRow = traceSel === null ? null : traceEvents.find((row) => row.id === traceSel)
      const traceDetail = traceSelRow === null || traceSelRow === undefined ? null : h('div', { className: 'rc2-tree-detail' },
        h('div', { className: 'rc2-line' },
          h('span', { className: 'rc2-tk', style: { background: `${(TRACE_KINDS[traceSelRow.kind] || {}).color || '#64748b'}22`, color: (TRACE_KINDS[traceSelRow.kind] || {}).color || '#64748b' } }, (TRACE_KINDS[traceSelRow.kind] || { label: traceSelRow.kind }).label),
          h('span', { className: 'rc2-trace-actor', style: { color: ACTOR_COLOR[(traceSelRow.actor || {}).role] || '#94a3b8' } }, (traceSelRow.actor || {}).name || '-'),
          h('span', { className: 'rc2-meta' }, fmtTime(new Date(traceSelRow.ts).toISOString())),
          h('span', { className: 'rc2-spacer' }),
          h('button', { className: 'rc2-btn ghost', style: { height: 18 }, onClick: () => setTraceSel(null) }, '✕')),
        h('div', { className: 'rc2-trace-title', style: { marginTop: 4 } }, traceSelRow.title || ''),
        traceSelRow.detail ? h('div', { className: 'rc2-trace-detail', style: { marginTop: 4, WebkitLineClamp: 'unset', maxHeight: 160, overflow: 'auto' } }, traceSelRow.detail) : null,
        (traceSelRow.meta && traceSelRow.meta.input)
          ? h('div', { style: { marginTop: 6 } },
            h('div', { className: 'rc2-meta' }, '输入'),
            h('pre', { className: 'rc2-spotlong', style: { fontSize: 11.5, maxHeight: 120, overflow: 'auto' } }, String(traceSelRow.meta.input)))
          : null,
        (traceSelRow.meta && traceSelRow.meta.out)
          ? h('div', { style: { marginTop: 6 } },
            h('div', { className: 'rc2-meta' }, '输出'),
            h('pre', { className: 'rc2-spotlong', style: { fontSize: 11.5, maxHeight: 160, overflow: 'auto' } }, String(traceSelRow.meta.out)))
          : null,
        (() => {
          const refs = traceSelRow.refs || {}
          const chips = []
          if (typeof refs.commandId === 'string' && refs.commandId !== '') {
            chips.push(h('button', { key: 'c', className: 'rc2-refchip', onClick: () => openSpot('command', refs.commandId) }, `命令 ${refs.commandId}`))
          }
          if (typeof refs.taskId === 'string' && refs.taskId !== '') {
            chips.push(h('button', { key: 't', className: 'rc2-refchip', onClick: () => { setDockOpen(true); setDockTab('task') } }, `任务 ${refs.taskId}`))
          }
          if (Array.isArray(refs.vulnIds) && refs.vulnIds.length > 0) {
            chips.push(h('button', { key: 'v', className: 'rc2-refchip', onClick: () => setSelection({ type: 'vuln', id: refs.vulnIds[0] }) }, `漏洞 ${refs.vulnIds[0]}`))
          }
          if (Array.isArray(refs.nodeIds) && refs.nodeIds.length > 0) {
            chips.push(h('button', { key: 'n', className: 'rc2-refchip', onClick: () => focusNode(refs.nodeIds[0]) }, `节点 ${refs.nodeIds[0]}`))
          }
          return chips.length === 0 ? null : h('div', { className: 'rc2-trace-refs', style: { marginTop: 4 } }, chips)
        })())

      /* 队员条：按出场顺序列出当前在岗队员，显示身份+序号（Web 手1 / Web 手2），跑着的点闪烁 */
      const ROLE_LABEL = {
        commander: '总指挥', lead: '总指挥', staff: '参谋', scout: '信息收集',
        web: 'Web 手', hunter: '猎手', browser: '浏览器', reverser: '逆向手',
        intranet: '内网手', qa: '验收', analyst: '分析', system: '系统', user: '你',
      }
      const roleLabelOf = (role) => ROLE_LABEL[role] || (role === undefined || role === '' ? '队员' : role)
      const squadList = (() => {
        const rows = squadMembers
          .filter((m) => m !== null && m !== undefined && m.key !== undefined)
          .slice()
          .sort((a, b) => Number(a.startedAt || 0) - Number(b.startedAt || 0))
        const byRole = new Map()
        for (const row of rows) {
          const role = row.role || 'member'
          if (!byRole.has(role)) byRole.set(role, [])
          byRole.get(role).push(row)
        }
        return rows.map((row) => {
          const role = row.role || 'member'
          const group = byRole.get(role) || [row]
          const index = group.findIndex((item) => item.key === row.key) + 1
          const beat = Number(row.lastAt || 0)
          /* 总指挥这一席就是主 agent 本体：它跑起来（chat.busy）灯就得亮 */
          const isCommanderSeat = role === 'commander'
          const running = row.status === 'running' || row.status === 'starting'
            || (isCommanderSeat && chat.busy === true)
          /* 常设席位永远在岗：灯常亮；跑起来时改成闪烁 */
          const alive = running || row.core === true || (beat > 0 && Date.now() - beat < 90000)
          return {
            key: row.key,
            role,
            index,
            total: group.length,
            alive,
            running,
            status: row.status || '',
            original: row.name || '',
            /* 优先用真实代号（Web 手#20）；没有代号才退回「角色+序号」 */
            label: (row.name === undefined || row.name === null ? '' : String(row.name).trim()) || (group.length > 1 ? `${roleLabelOf(role)}${index}` : roleLabelOf(role)),
            core: row.core === true,
            task: row.task || '',
            color: laneColorOf(`${role}:${row.name || '?'}`),
          }
        })
      })()
      const laneLegend = h('div', { className: 'rc2-lanelegend', title: '当前在岗队员（按出场顺序）；闪烁=正在执行' },
        squadList.length === 0
          ? h('span', { className: 'rc2-meta' }, '无队员在岗')
          : squadList.map((row) => h('span', {
            key: row.key,
            className: `rc2-lanetag${row.alive ? ' live' : ''}`,
            title: [`${row.label}${row.original !== '' && row.original !== row.label ? `（${row.original}）` : ''}${row.core ? ' · 常驻' : ''}`,
              row.running ? '状态：执行中'
                : (row.core ? '状态：在岗待命（常驻席位）' : `状态：${row.status || '待机'}`),
              row.task !== '' ? `任务：${row.task}` : ''].filter((line) => line !== '').join('\n'),
          },
          h('i', { className: row.running ? 'pulse' : '', style: { background: row.color } }),
          row.label)))

      const splitterBar = h('div', {
        className: 'rc2-splitter',
        title: '拖动调整轨迹栏宽度',
        onMouseDown: (event) => {
          event.preventDefault()
          const startX = event.clientX
          const startWidth = leftWidth
          let width = startWidth
          const onMove = (moveEvent) => {
            width = Math.min(620, Math.max(200, startWidth + (moveEvent.clientX - startX)))
            setLeftWidth(width)
          }
          const onUp = () => {
            window.removeEventListener('mousemove', onMove)
            window.removeEventListener('mouseup', onUp)
            try { window.localStorage.setItem('rc2.leftWidth', String(Math.round(width))) } catch { /* 忽略 */ }
          }
          window.addEventListener('mousemove', onMove)
          window.addEventListener('mouseup', onUp)
        },
      })

      const splitterRight = h('div', {
        className: 'rc2-splitter',
        title: '拖动调整右侧栏宽度',
        onMouseDown: (event) => {
          event.preventDefault()
          const startX = event.clientX
          const startWidth = rightWidth
          let width = startWidth
          const onMove = (moveEvent) => {
            width = Math.min(720, Math.max(260, startWidth - (moveEvent.clientX - startX)))
            setRightWidth(width)
          }
          const onUp = () => {
            window.removeEventListener('mousemove', onMove)
            window.removeEventListener('mouseup', onUp)
            try { window.localStorage.setItem('rc2.rightWidth', String(Math.round(width))) } catch { /* 忽略 */ }
          }
          window.addEventListener('mousemove', onMove)
          window.addEventListener('mouseup', onUp)
        },
      })

      useEffect(() => {
        const timer = setTimeout(() => {
          const node = treeRef.current
          if (node === null || node === undefined) return
          node.scrollTop = node.scrollHeight
        }, 80)
        return () => clearTimeout(timer)
      }, [traceEvents.length, leftWidth, traceKind, traceQuery, traceNoBash])

      const commandFeed = h('div', { className: 'rc2-rail left', style: { flex: `0 0 ${leftWidth}px` } },
        h('div', { className: 'rc2-railhead' },
          h('span', { className: `rc2-dot${conn === 'live' ? ' pulse' : ''}` }),
          h('span', null, '轨迹'),
          h('b', null, traceEvents.length),
          h('span', { className: 'rc2-spacer' }),
          h('span', { className: 'rc2-meta' }, conn === 'live' ? t('live') : t('streamPaused')),
          h('button', { className: 'rc2-zoom', style: { opacity: 1 }, title: '轨迹放大到中央', onClick: () => setPanelSpot('trace') }, '⤢')),
        h('div', { className: 'rc2-filterbar' },
          h('input', {
            className: 'rc2-search', style: { width: 96, height: 22 },
            value: traceQuery, placeholder: '搜轨迹…',
            onChange: (event) => setTraceQuery(event.target.value),
          }),
          [['all', '全部'], ['task', '调度'], ['dispatch', '派活'], ['member', '队员'], ['skill', '技能'],
            ['command', '命令'], ['graph', '图谱'], ['chat', '对话'], ['verdict', '验收']].map(([key, label]) => h('button', {
            key, className: `rc2-fchip${traceKind === key ? ' on' : ''}`,
            onClick: () => setTraceKind(key),
          }, label)),
          h('button', {
            className: `rc2-fchip${traceNoBash ? ' on' : ''}`,
            title: '隐藏本机 bash 的开发命令',
            onClick: () => setTraceNoBash((v) => !v),
          }, '屏蔽 bash')),
        laneLegend,
        h('div', { className: 'rc2-tree', ref: treeRef },
          treeSvg === null
            ? h('div', { className: 'rc2-empty', style: { padding: 20 } }, h('p', null, '还没有轨迹。说一句话或让总指挥开工，这里会画出每个 Agent 的动作树。'))
            : treeSvg),
        traceDetail)

      /* ── 右：漏洞列表 ── */
      const vulnRailHead = h('div', { className: 'rc2-railhead' },
        h('span', { className: 'rc2-dot' }),
        h('span', null, t('vulnFeed')),
        h('b', null, stats !== null ? stats.vulns : 0),
        h('span', { className: 'rc2-spacer' }),
        h('span', { className: 'rc2-meta' }, stats !== null ? `crit ${stats.bySeverity.critical} / high ${stats.bySeverity.high}` : ''),
        h('button', { className: 'rc2-zoom', style: { opacity: 1 }, title: '漏洞面板放大到中央', onClick: () => setPanelSpot('vulns') }, '⤢'))

      const vulnRailRows = h('div', { className: 'rc2-feed', style: { flex: '1 1 auto', minHeight: 0 } },
        feedVulns.length === 0
          ? h('div', { className: 'rc2-empty', style: { padding: '16px 8px' } }, h('p', null, t('noOutput')))
          : feedVulns.map((v) => {
            const node = nodes.find((n) => n.id === v.nodeId)
            return h('div', {
              key: v.id,
              className: `rc2-item rc2-vulnrow${selection !== null && selection.type === 'vuln' && selection.id === v.id ? ' sel' : ''}`,
              onClick: () => { setSelection({ type: 'vuln', id: v.id }); if (node) focusNode(node.id) },
            },
            h('div', { className: 'rc2-line' },
              h('span', { className: 'rc2-sev', style: { background: SEV_COLOR[v.severity] || SEV_COLOR.info } }, v.severity || 'info'),
              h('span', { className: 'rc2-mono', title: v.title }, shortText(v.title, 64)),
              h('span', { className: 'rc2-spacer' }),
              h('span', { className: 'rc2-meta', title: node ? node.value : v.nodeId }, node ? shortText(node.value, 14) : v.nodeId),
              v.status !== 'open' ? h('span', { className: 'rc2-meta', style: { color: 'var(--rc-accent)' } }, v.status) : null,
              h('button', {
                className: 'rc2-zoom', title: '放大到中央',
                onClick: (event) => { event.stopPropagation(); openSpot('vuln', v.id) },
              }, '⤢')))
          }))

      /* ── 画布 + HUD ── */
      /* 类型图例：完全由当前图谱里实际出现的 kind 生成（任意自定义类型都会自动出现） */
      const kindStats = (() => {
        const map = new Map()
        for (const node of nodes) {
          if (showArchived !== true && node.archived === true) continue
          const key = node.kind || 'note'
          map.set(key, (map.get(key) || 0) + 1)
        }
        return Array.from(map.entries()).map(([kind, count]) => ({ kind, count })).sort((a, b) => b.count - a.count)
      })()
      const legendRow = (row) => {
        const active = legendFocus !== null && legendFocus.kind === row.kind
        return h('button', {
          key: row.kind,
          className: `rc2-legend${active ? ' on' : ''}${hiddenKinds.has(row.kind) ? ' off' : ''}`,
          title: `${row.kind} · ${row.count} 个（点击固定高亮，右键隐藏/显示这类节点）`,
          onClick: () => setLegendFocus(active ? null : { kind: row.kind }),
          onContextMenu: (event) => {
            event.preventDefault()
            event.stopPropagation()
            setHiddenKinds((prev) => {
              const next = new Set(prev)
              if (next.has(row.kind)) next.delete(row.kind)
              else next.add(row.kind)
              return next
            })
          },
        }, h('i', { style: { background: colorOfKind(row.kind) } }), `${row.kind} ${row.count}`)
      }

      const vulnFocus = legendFocus !== null && legendFocus.vuln === true
      const moreCount = Math.max(0, kindStats.length - 14)
      const legend = h('div', { className: `rc2-hud bl${legendExpanded ? ' wide' : ''}` },
        /* 可横向滚动的类型区（折叠时只有一行） */
        h('div', { className: 'rc2-legscroll' },
          h('button', {
            key: 'all',
            className: `rc2-legend all${legendFocus === null ? ' on' : ''}`,
            title: '取消所有类别高亮，回到全部显示',
            onClick: () => { setLegendFocus(null); setHiddenKinds(new Set()) },
          }, '全部'),
          (legendExpanded ? kindStats : kindStats.slice(0, 14)).map(legendRow)),
        /* 固定在右侧、永远可见：展开与漏洞 */
        h('div', { className: 'rc2-legtail' },
          moreCount > 0
            ? h('button', {
              key: 'more',
              className: `rc2-legend${legendExpanded ? ' on' : ''}`,
              title: legendExpanded ? '收起多余类型' : `展开其余 ${moreCount} 个类型`,
              onClick: () => setLegendExpanded((v) => !v),
            }, legendExpanded ? '收起' : `+${moreCount}`)
            : null,
          h('button', {
            key: 'vuln',
            className: `rc2-legend${vulnFocus ? ' on' : ''}`,
            title: '固定高亮所有带漏洞的节点，再点一次取消',
            onClick: () => setLegendFocus(vulnFocus ? null : { vuln: true }),
          }, h('i', { style: { background: SEV_COLOR.critical, borderRadius: 2 } }), t('vulns'))),
        /* 缩放控件并入这一行最右侧：和图例同一条底边，窄画布也不会互相压住 */
        h('div', { className: 'rc2-zoomgroup', title: '滚轮缩放 / 双击画布适应' },
          h('span', { className: 'rc2-zoomval' }, `${Math.round(view.k * 100)}%`),
          h('button', { className: 'rc2-btn', onClick: () => setView((v) => ({ ...v, k: clamp(v.k * 1.15, 0.12, 3.4) })) }, '+'),
          h('button', { className: 'rc2-btn', onClick: () => setView((v) => ({ ...v, k: clamp(v.k / 1.15, 0.12, 3.4) })) }, '−'),
          h('button', { className: 'rc2-btn', title: '适应画布（双击也能用）', onClick: () => fit() }, '⤢')))

      const kv = (key, value) => (value === undefined || value === null || value === '' ? null
        : h('div', { className: 'rc2-kv' }, h('span', { className: 'k' }, key), h('span', { className: 'v' }, String(value))))

      const detailCard = (() => {
        if (selectedNode !== null) {
          const nodeVulns = vulns.filter((v) => v.nodeId === selectedNode.id)
          const provCommands = provenance !== null && provenance.node && provenance.node.id === selectedNode.id ? provenance.commands : []
          return h('div', { className: 'rc2-hud tr', onWheel: (event) => event.stopPropagation() },
            h('div', { className: 'rc2-sect' }, t('nodeDetail')),
            h('div', { style: { fontWeight: 650, fontSize: 12.5, wordBreak: 'break-word' } }, selectedNode.label || selectedNode.value),
            kv(t('status'), selectedNode.kind),
            kv(t('value'), selectedNode.value),
            kv('IP', selectedNode.ip),
            kv('port', selectedNode.port),
            kv(t('tech'), (selectedNode.tech || []).join(', ')),
            kv(t('tags'), (selectedNode.tags || []).join(', ')),
            kv(t('degree'), degreeMap.get(selectedNode.id) || 0),
            kv(t('note'), selectedNode.note),
            h('div', { className: 'rc2-row', style: { marginTop: 8 } },
              h('button', { className: 'rc2-btn', onClick: () => focusNode(selectedNode.id) }, t('fit')),
              h('button', { className: 'rc2-btn', onClick: () => toggleCollapse(selectedNode.id) },
                ownsFold(selectedNode.id) ? t('expand') : t('collapse')),
              h('button', {
                className: 'rc2-btn',
                onClick: async () => {
                  if (selectedNode.archived === true) {
                    const res = await api({
                      op: 'archiveNode',
                      nodeId: selectedNode.id,
                      mode: 'restore',
                      reason: '',
                    })
                    if (res && res.ok) void refresh(engagement ? engagement.id : undefined)
                    return
                  }
                  const reason = await uiPrompt({ title: t('archiveReason'), value: '', okText: '归档' })
                  if (reason === null) return
                  const res = await api({
                    op: 'archiveNode',
                    nodeId: selectedNode.id,
                    mode: 'archive',
                    reason: reason || '',
                  })
                  if (res && res.ok) void refresh(engagement ? engagement.id : undefined)
                },
              }, selectedNode.archived ? t('restore') : t('archive')),
              h('button', {
                className: 'rc2-btn danger',
                onClick: async () => {
                  if (!await uiConfirm(t('confirmDelete'), '节点会连同它的边与漏洞一起删除，不可恢复')) return
                  const res = await api({ op: 'deleteNode', nodeId: selectedNode.id, engagement: engagement ? engagement.id : undefined })
                  if (res && res.ok) { setSelection(null); void refresh(engagement ? engagement.id : undefined) }
                },
              }, t('delete'))),
            h('div', { className: 'rc2-sect' }, `${t('provenance')} (${provCommands.length})`),
            provCommands.length === 0
              ? h('div', { className: 'rc2-note', style: { margin: 0 } }, t('noProvenance'))
              : provCommands.map((c) => h('div', {
                key: c.id, className: 'rc2-cmd',
                onClick: () => setSelection({ type: 'command', id: c.id }),
              },
              h('span', { className: `rc2-exit ${c.exitCode === 0 ? 'ok' : 'bad'}` }, c.exitCode === null ? '…' : String(c.exitCode)),
              h('span', { title: c.command }, shortText(c.command, 44)),
              h('span', { style: { marginLeft: 'auto', color: 'var(--rc-accent)', fontSize: 10 } }, t('viewOutput')))),
            nodeVulns.length > 0 ? h('div', null,
              h('div', { className: 'rc2-sect' }, `${t('vulns')} (${nodeVulns.length})`),
              nodeVulns.map((v) => h('div', {
                key: v.id, className: 'rc2-cmd',
                onClick: () => setSelection({ type: 'vuln', id: v.id }),
              },
              h('span', { className: 'rc2-sev', style: { background: SEV_COLOR[v.severity] || SEV_COLOR.info } }, v.severity),
              h('span', null, shortText(v.title, 40))))) : null)
        }
        if (selectedVuln !== null) {
          const node = nodes.find((n) => n.id === selectedVuln.nodeId)
          const actions = [['verified', t('markVerified')], ['false-positive', t('markFalse')], ['open', t('markOpen')], ['fixed', t('markFixed')]]
          return h('div', { className: 'rc2-hud tr', onWheel: (event) => event.stopPropagation() },
            h('div', { className: 'rc2-sect' }, t('vulnDetail')),
            h('div', { className: 'rc2-line', style: { alignItems: 'flex-start' } },
              h('span', { className: 'rc2-sev', style: { background: SEV_COLOR[selectedVuln.severity] || SEV_COLOR.info, marginTop: 3 } }, selectedVuln.severity || 'info'),
              h('div', { style: { fontWeight: 650, fontSize: 12.5, whiteSpace: 'normal' } }, selectedVuln.title)),
            kv(t('status'), selectedVuln.status),
            kv(t('endpoint'), selectedVuln.endpoint),
            kv(t('param'), selectedVuln.param),
            kv(t('payload'), selectedVuln.payload),
            kv('CVE', selectedVuln.cve),
            kv(t('node'), node ? node.value : selectedVuln.nodeId),
            selectedVuln.description ? h('div', { className: 'rc2-pre', style: { marginTop: 6 } }, selectedVuln.description) : null,
            selectedVuln.commandId ? h('div', {
              className: 'rc2-cmd', style: { marginTop: 6 },
              onClick: () => setSelection({ type: 'command', id: selectedVuln.commandId }),
            }, h('span', { className: 'rc2-meta' }, t('evidence')), h('span', null, selectedVuln.commandId)) : null,
            h('div', { className: 'rc2-row', style: { marginTop: 8, flexWrap: 'wrap' } },
              ...actions.map(([status, label]) => h('button', {
                key: status, className: `rc2-btn${selectedVuln.status === status ? ' on' : ''}`,
                onClick: async () => {
                  const res = await api({ op: 'setVulnStatus', vulnId: selectedVuln.id, status, engagement: engagement ? engagement.id : undefined })
                  if (res && res.ok) void refresh(engagement ? engagement.id : undefined)
                },
              }, label)),
              h('button', {
                className: 'rc2-btn danger',
                onClick: async () => {
                  if (!await uiConfirm(t('confirmDelete'), '这条漏洞记录会被删除')) return
                  const res = await api({ op: 'deleteVuln', vulnId: selectedVuln.id, engagement: engagement ? engagement.id : undefined })
                  if (res && res.ok) { setSelection(null); void refresh(engagement ? engagement.id : undefined) }
                },
              }, t('delete'))))
        }
        if (selectedCommand !== null) {
          const text = commandText !== null ? commandText.text : null
          return h('div', { className: 'rc2-hud tr', style: { width: 420, maxHeight: '76%' }, onWheel: (event) => event.stopPropagation() },
            h('div', { className: 'rc2-sect' }, t('commands')),
            h('div', { className: 'rc2-pre', style: { maxHeight: 90 } }, selectedCommand.command),
            h('div', { className: 'rc2-row', style: { marginTop: 6 } },
              h('button', {
                className: 'rc2-btn',
                onClick: async () => {
                  const res = await api({ op: 'command.rerun', commandId: selectedCommand.id, engagement: engagement ? engagement.id : undefined })
                  if (res && res.ok) {
                    setSelection({ type: 'command', id: res.commandId })
                    void refresh(engagement ? engagement.id : undefined)
                  }
                },
              }, '↻ 重跑'),
              h('button', {
                className: 'rc2-btn ghost',
                onClick: () => { void navigator.clipboard?.writeText(selectedCommand.command) },
              }, '复制')),
            kv(t('exitCode'), selectedCommand.exitCode),
            kv(t('duration'), `${selectedCommand.durationMs || 0} ms`),
            kv(t('source'), selectedCommand.source === 'bash' ? 'bash' : 'recon_run'),
            kv(t('cwd'), selectedCommand.cwd),
            kv(t('purpose'), selectedCommand.purpose),
            kv('env', (selectedCommand.envKeys || []).join(', ')),
            kv(t('startedAt'), selectedCommand.startedAt ? fmtTime(selectedCommand.startedAt) : ''),
            h('div', { className: 'rc2-sect' }, 'stdout'),
            h('div', { className: 'rc2-pre tall' }, text === null ? '…' : (text || t('noOutput'))))
        }
        return null
      })()

      const dialogNode = dialogState === null ? null : h('div', {
        className: 'rc2-modal-mask',
        onMouseDown: (event) => {
          if (event.target !== event.currentTarget) return
          closeDialog(dialogState.kind === 'prompt' ? null : false)
        },
      },
      h('div', { className: 'rc2-modal', role: 'dialog', 'aria-modal': 'true' },
        h('div', { className: 'rc2-modal-title' }, dialogState.title),
        dialogState.detail ? h('div', { className: 'rc2-modal-detail' }, dialogState.detail) : null,
        dialogState.kind === 'prompt'
          ? (dialogState.multiline === true
            ? h('textarea', {
              className: 'rc2-modal-input', rows: 4, autoFocus: true, value: dialogInput,
              placeholder: dialogState.placeholder || '',
              onChange: (event) => setDialogInput(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Escape') { event.preventDefault(); closeDialog(null) }
                if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) { event.preventDefault(); closeDialog(dialogInput) }
              },
            })
            : h('input', {
              className: 'rc2-modal-input', autoFocus: true, value: dialogInput,
              placeholder: dialogState.placeholder || '',
              onChange: (event) => setDialogInput(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Escape') { event.preventDefault(); closeDialog(null) }
                if (event.key === 'Enter') { event.preventDefault(); closeDialog(dialogInput) }
              },
            }))
          : null,
        h('div', { className: 'rc2-modal-actions' },
          dialogState.kind === 'alert' ? null : h('button', {
            className: 'rc2-btn ghost',
            onClick: () => closeDialog(dialogState.kind === 'prompt' ? null : false),
          }, dialogState.cancelText || '取消'),
          h('button', {
            className: 'rc2-btn on',
            onClick: () => closeDialog(dialogState.kind === 'prompt' ? dialogInput : true),
          }, dialogState.okText || (dialogState.kind === 'alert' ? '知道了' : '确定')))))

      const browserStack = browserPanes.length === 0 ? null : h('div', { className: 'rc2-browsers', style: { left: 10 } },
        browserPanes.slice(0, 4).map((pane) => h('div', {
          key: pane.key, className: `rc2-bpane ${pane.status}`,
          title: `${pane.name} · ${pane.status === 'running' ? '正在操作' : pane.status === 'error' ? '失败' : '空闲'}\n${pane.url || ''}`,
          onClick: () => {
            setSpot({
              kind: 'browser', title: `${pane.name} · ${pane.url || pane.title || '浏览器画面'}`,
              body: pane.shot ? `![${pane.name}](${apiUrl(`/recon/asset?p=${encodeURIComponent(pane.shot)}`)})` : '暂无画面',
              meta: [`状态：${pane.status}`, pane.error ? `错误：${pane.error}` : '', pane.url ? `URL：${pane.url}` : ''].filter((x) => x !== ''),
              shot: pane.shot || null,
            })
          },
        },
        h('div', { className: 'rc2-bpane-head' },
          h('span', { className: `rc2-dot ${pane.status}` }),
          h('span', { className: 'rc2-bpane-name' }, pane.name),
          h('span', { className: 'rc2-bpane-state' }, pane.status === 'running' ? '操作中' : pane.status === 'error' ? '失败' : '待命')),
        pane.shot
          ? h('img', { className: 'rc2-bpane-shot', src: apiUrl(`/recon/asset?p=${encodeURIComponent(pane.shot)}`), alt: pane.name, loading: 'lazy' })
          : h('div', { className: 'rc2-bpane-empty' }, pane.status === 'running' ? '正在加载页面…' : '无画面'),
        h('div', { className: 'rc2-bpane-url' }, pane.url || pane.title || '—'))))

      const canvas = h('div', { className: 'rc2-canvas', ref: attachCanvas },
        h('svg', {
          onPointerDown, onPointerMove, onPointerUp, onPointerCancel: onPointerUp,
          onDoubleClick: (event) => {
            const nodeEl = event.target && typeof event.target.closest === 'function' ? event.target.closest('[data-node-id]') : null
            if (nodeEl !== null && nodeEl !== undefined) return   // 节点折叠由 mousedown 计数处理，避免双触发
            fit()
          },
        },
        h('defs', null,
          h('marker', {
            id: arrowId, viewBox: '0 0 10 10', refX: 8, refY: 5, markerWidth: 5, markerHeight: 5, orient: 'auto-start-reverse',
          }, h('path', { d: 'M 0 0 L 10 5 L 0 10 z', fill: 'color-mix(in srgb, var(--rc-accent) 45%, transparent)' }))),
        h('g', { transform: `translate(${view.x}, ${view.y}) scale(${view.k})` }, edgeEls, nodeEls)),
        hudOpen === false
          ? h('div', { className: 'rc2-hud tl rc2-hud-min' },
            h('button', {
              className: 'rc2-hud-toggle', title: '展开搜索 / 筛选',
              onClick: () => toggleHud(true),
            }, '🔍'),
            query !== '' || kindFilter.size > 0
              ? h('span', { className: 'rc2-hud-badge' }, `${query !== '' ? '1' : '0'}·${kindFilter.size}`)
              : null)
          : h('div', { className: 'rc2-hud tl' },
          h('div', { className: 'rc2-row', style: { marginBottom: 6 } },
            h('input', {
              className: 'rc2-search', value: query, placeholder: t('search'),
              onChange: (event) => setQuery(event.target.value),
            }),
            h('button', {
              className: 'rc2-btn ghost rc2-hud-collapse', title: '收起（不占图谱显示区域）',
              onClick: () => toggleHud(false),
            }, '▴'),
            h('button', {
              className: 'rc2-btn ghost',
              onClick: () => {
                /* 全部折叠：每个有子节点的父节点各折叠一次（多父时同一子节点会被多家折叠） */
                setFoldOwners(() => {
                  const next = new Map()
                  for (const node of nodes) {
                    const kids = childrenMap.get(node.id) || []
                    if (kids.length === 0) continue
                    for (const kid of kids) {
                      const owners = next.get(kid) || new Set()
                      owners.add(node.id)
                      next.set(kid, owners)
                    }
                  }
                  return next
                })
              },
            }, t('collapseAll')),
            h('button', { className: 'rc2-btn ghost', onClick: () => setFoldOwners(new Map()) }, t('expandAll')),
            h('button', {
              className: `rc2-btn ghost${showVulns ? ' on' : ''}`,
              title: '显示 / 隐藏图中的漏洞菱形',
              onClick: () => setShowVulns((v) => !v),
            }, t('showVulns')),
            h('button', {
              className: `rc2-btn ghost${showArchived ? ' on' : ''}`,
              title: '显示 / 隐藏已归档节点',
              onClick: () => setShowArchived((v) => !v),
            }, showArchived ? '隐藏归档' : '显示归档')),
          h('div', { className: 'rc2-kindfilter' },
            kindStats.slice(0, 16).map((row) => h('button', {
              key: row.kind,
              className: `rc2-fchip${kindFilter.has(row.kind) ? ' on' : ''}`,
              style: kindFilter.has(row.kind) ? { borderColor: colorOfKind(row.kind), color: colorOfKind(row.kind) } : undefined,
              onClick: () => setKindFilter((prev) => {
                const next = new Set(prev)
                if (next.has(row.kind)) next.delete(row.kind)
                else next.add(row.kind)
                return next
              }),
            }, `${row.kind} ${row.count}`)),
            kindFilter.size > 0 ? h('button', { className: 'rc2-fchip', onClick: () => setKindFilter(new Set()) }, '✕') : null),
          h('div', { style: { display: 'flex', flexWrap: 'wrap', gap: 4, maxHeight: 96, overflow: 'auto' } },
            filteredNodes.slice(0, 24).map((node) => h('button', {
              key: node.id, className: 'rc2-btn ghost', style: { height: 22, fontSize: 10.5 },
              onClick: () => { setSelection({ type: 'node', id: node.id }); focusNode(node.id) },
            },
            h('span', { className: 'rc2-dot', style: { background: colorOfKind(node.kind), boxShadow: 'none', width: 5, height: 5 } }),
            shortText(node.label || node.value, 22))))),
        detailCard,
        legend)

      /* ── 驾驶舱对话 ── */
      const reasoningLine = (chat.streaming.reasoning || '').trim().split('\n').filter((line) => line.trim() !== '').slice(-1)[0] || ''
      const chatRows = []
      if (chatTarget !== 'lead') {
        for (const message of memberMsgs) {
          const isUser = message.role === 'user'
          chatRows.push(h('div', { key: message.id, className: `rc2-msg ${isUser ? 'user' : 'ai'}` },
            h('div', { className: 'who' }, `${isUser ? t('userLabel') : (message.author || chatTarget)}${message.ts ? ` · ${fmtTime(new Date(message.ts).toISOString())}` : ''}`),
            h('div', { className: `body${mdOn ? ' rc2-md' : ''}` }, message.text ? mdOrText(message.text, message.id, mdOn) : ''),
            !isUser && showThinking && message.reasoning ? h('div', { className: 'rc2-reason' }, message.reasoning) : null))
        }
        if (memberStream.text !== '' || memberStream.reasoning !== '') {
          chatRows.push(h('div', { key: 'member-stream', className: 'rc2-msg ai' },
            h('div', { className: 'who' }, chatTarget),
            memberStream.text !== '' ? h('div', { className: `body${mdOn ? ' rc2-md' : ''}` }, mdOrText(memberStream.text, 'mstream', mdOn), h('span', { className: 'rc2-caret' })) : null,
            showThinking && memberStream.reasoning !== '' ? h('div', { className: 'rc2-reason' }, memberStream.reasoning) : null))
        }
      }
      const leadMsgs = chatTarget === 'lead' ? chat.messages : []
      for (let mi = 0; mi < leadMsgs.length; mi += 1) {
        const message = leadMsgs[mi]
        const isSystem = message.system === true
        const isUser = message.role === 'user' && isSystem === false
        const silent = isUser === false && isSystem === false && (message.text || '').trim() === ''
        if (silent) {
          /* 连续「只有思维链」的轮次合成一个可展开的块 */
          const group = []
          let gi = mi
          while (gi < leadMsgs.length) {
            const row = leadMsgs[gi]
            if (row.role === 'user' || (row.text || '').trim() !== '') break
            group.push(row)
            gi += 1
          }
          mi = gi - 1
          const gid = `silent-${group[0].id}`
          const open = openSilent[gid] === true || showThinking
          chatRows.push(h('div', { key: gid, className: 'rc2-silent' },
            h('button', {
              className: 'rc2-silentbtn',
              onClick: () => setOpenSilent((prev) => ({ ...prev, [gid]: open === false })),
            }, `${open ? '▾' : '▸'} ${group.length} 轮内部思考（这几轮只调了工具，没有正文）`),
            open
              ? h('div', { className: 'rc2-silentbody' }, group.map((row, index) => h('div', { key: row.id, className: 'rc2-silentrow' },
                h('span', { className: 'rc2-meta' }, `${index + 1}. ${row.ts ? fmtTime(new Date(row.ts).toISOString()) : ''}`),
                h('div', { className: 'rc2-reason', style: { marginTop: 2 } }, (row.reasoning || '').trim() === '' ? '（本轮无思维链输出）' : row.reasoning))))
              : null))
          continue
        }
        chatRows.push(h('div', { key: message.id, className: `rc2-msg ${isUser ? 'user' : 'ai'}` },
          h('div', { className: 'who' }, `${isSystem ? '调度台' : (isUser ? t('userLabel') : t('aiLabel'))}${message.model ? ` · ${message.model}` : (message.tier ? ` · ${message.tier}` : '')}${message.ts ? ` · ${fmtTime(new Date(message.ts).toISOString())}` : ''}`),
          h('div', { className: `body${mdOn ? ' rc2-md' : ''}` }, message.text ? mdOrText(message.text, message.id, mdOn) : ''),
          message.images ? h('div', { className: 'rc2-meta', style: { marginTop: 3 } }, `🖼 × ${message.images}`) : null,
          Array.isArray(message.attachments) && message.attachments.length > 0
            ? h('div', { className: 'rc2-attachbar', style: { padding: '4px 0 0' } }, message.attachments.map((file) => h('a', {
              key: file.path, className: 'rc2-attach', href: apiUrl(`/recon/asset?p=${encodeURIComponent(file.path)}`),
              target: '_blank', rel: 'noreferrer', title: file.path,
            }, '📎 ', h('span', null, file.name), ` ${Math.round((file.bytes || 0) / 1024)}KB`)))
            : null,
          !isUser && showThinking && message.reasoning ? h('div', { className: 'rc2-reason' }, message.reasoning) : null))
      }
      for (const line of (chatTarget === 'lead' ? toolLines : [])) {
        chatRows.push(h('div', {
          key: line.id,
          className: 'rc2-tool',
          style: line.kind === 'error' ? { color: 'var(--rc-danger)' } : (line.kind === 'result' ? { opacity: 0.72 } : undefined),
        }, line.kind === 'call' ? `▸ ${line.name || 'tool'} ${line.text || ''}` : (line.kind === 'error' ? `✗ ${line.text}` : `✓ ${line.text || ''}`)))
      }
      if (chatTarget === 'lead' && (chat.busy || chat.streaming.text !== '' || chat.streaming.reasoning !== '')) {
        chatRows.push(h('div', { key: 'streaming', className: 'rc2-msg ai' },
          h('div', { className: 'who' }, `${t('aiLabel')} · ${chat.busy ? '…' : ''}`),
          chat.streaming.text !== '' ? h('div', { className: `body${mdOn ? ' rc2-md' : ''}` }, mdOrText(chat.streaming.text, 'lstream', mdOn), h('span', { className: 'rc2-caret' })) : null,
          showThinking && chat.streaming.reasoning !== ''
            ? h('div', { className: 'rc2-reason' }, chat.streaming.reasoning)
            : (chat.busy ? h('div', { className: 'rc2-reason' }, t('thinkingEmpty')) : null)))
      }

      const postBoard = useCallback(async () => {
        const text = boardDraft.trim()
        if (text === '' || engagement === null) return
        setBoardDraft('')
        await api({ op: 'board.post', engagement: engagement.id, kind: boardKind, text })
      }, [boardDraft, boardKind, engagement])

      const spawnMember = useCallback(async () => {
        const task = spawnTask.trim()
        if (task === '' || engagement === null) return
        setSpawnTask('')
        const res = await api({
          op: 'squad.spawn', engagement: engagement.id, role: spawnRole, tier: spawnTier, task,
          name: spawnName.trim(),
          skills: spawnSkills.split(',').map((x) => x.trim()).filter(Boolean),
          prompt: spawnPrompt.trim(),
        })
        if (res && res.ok && res.member) {
          setSquadMembers((prev) => [res.member, ...prev.filter((row) => row.key !== res.member.key)])
        }
      }, [engagement, spawnName, spawnPrompt, spawnRole, spawnSkills, spawnTask, spawnTier])

      const stopMember = useCallback(async (name) => { await api({ op: 'squad.stop', member: name, engagement: engagement ? engagement.id : undefined }) }, [engagement])
      const removeMember = useCallback(async (name) => { await api({ op: 'squad.remove', member: name, engagement: engagement ? engagement.id : undefined }) }, [engagement])
      const addMemberTask = useCallback(async (member) => {
        const text = await uiPrompt({ title: t('squadAsk'), detail: `发给 ${member.name}`, multiline: true, okText: '派发' })
        if (text === null || text.trim() === '') return
        await api({ op: 'squad.task', member: member.name, task: text.trim(), engagement: engagement ? engagement.id : undefined })
      }, [engagement, t, uiPrompt])

      const ROLE_COLOR = {
        lead: '#22d3ee', commander: '#22d3ee', staff: '#38bdf8', scout: '#34d399',
        web: '#fb923c', reverser: '#c084fc', intranet: '#f472b6', qa: '#facc15',
        hunter: '#fb923c', browser: '#c084fc', analyst: '#38bdf8',
        system: '#64748b', user: '#94a3b8',
      }
      const kindLabel = (kind) => t(kind === 'finding' ? 'kindFinding' : (kind === 'hypothesis' ? 'kindHypothesis' : (kind === 'task' ? 'kindTask' : (kind === 'conclusion' ? 'kindConclusion' : 'kindNote'))))

      /* 压缩摘要里按角色记了计数与样本：展开后可逐人查看，并可一键「只看他」 */
      const mergedAuthorsBlock = (entry) => {
        const merged = entry.refs && entry.refs.merged
        const list = merged && Array.isArray(merged.authors) ? merged.authors : []
        if (list.length === 0) return null
        const open = mergedDetailOpen[entry.id] === true
        return h('div', { className: 'rc2-merged-authors' },
          h('button', {
            className: 'rc2-merged-toggle',
            onClick: () => setMergedDetailOpen((prev) => ({ ...prev, [entry.id]: !open })),
          }, `${open ? '▾' : '▸'} 按角色查看（${list.length} 人）`),
          open ? h('div', { className: 'rc2-merged-authorlist' }, list.map((row) => h('div', {
            key: `${row.role || ''}:${row.name}`,
            className: 'rc2-merged-authorrow',
          },
          h('span', { className: 'rc2-author', style: { color: ROLE_COLOR[row.role] || '#94a3b8', borderColor: ROLE_COLOR[row.role] || '#94a3b8' } }, row.name),
          h('span', { className: 'rc2-meta' }, `${Number(row.count) || 0} 条`),
          h('span', { className: 'rc2-spacer' }),
          h('button', { className: 'rc2-fchip', onClick: () => setBoardAuthor(row.name) }, '只看他')))) : null)
      }

      /* 选中某个队员时，把他被压缩掉的发言单独收成一个可展开的小卡片 */
      const mergedByAuthor = (author) => {
        if (author === 'all' || author === '') return null
        const summaries = boardEntries.filter((entry) => {
          const merged = entry.refs && entry.refs.merged
          return merged && Array.isArray(merged.authors) && merged.authors.some((row) => row.name === author)
        })
        if (summaries.length === 0) return null
        const total = summaries.reduce((sum, entry) => {
          const row = entry.refs.merged.authors.find((item) => item.name === author)
          return sum + (Number(row && row.count) || 0)
        }, 0)
        const open = mergedBlockOpen[author] === true
        return h('div', { className: 'rc2-merged' },
          h('button', {
            className: 'rc2-merged-head',
            onClick: () => setMergedBlockOpen((prev) => ({ ...prev, [author]: !open })),
          }, `${open ? '▾' : '▸'} 📦 已压缩 ${total} 条 · ${author}`),
          open ? h('div', { className: 'rc2-merged-body' }, summaries.slice().reverse().map((entry) => {
            const row = entry.refs.merged.authors.find((item) => item.name === author)
            return h('div', { key: entry.id, className: 'rc2-merged-item' },
              h('div', { className: 'rc2-meta' },
                `${fmtTime(new Date(Number(entry.ts) || Date.now()).toISOString())} · 该段 ${Number(row && row.count) || 0} 条`),
              (Array.isArray(row && row.samples) ? row.samples : []).map((sample, index) => h('div', {
                key: index, className: 'rc2-merged-sample',
              }, sample)),
              h('div', { className: 'rc2-meta', style: { opacity: 0.7 } }, '完整正文已随压缩移出，这里保留摘要样本'))
          })) : null)
      }

      const boardIsUserEntry = (entry) => Boolean(entry && entry.author && entry.author.role === 'user')
      const boardEntrySummary = (entry) => {
        if (boardIsUserEntry(entry)) return ''
        const explicit = String(entry.summary || '').replace(/\s+/g, ' ').trim()
        if (entry.refs && entry.refs.merged) return explicit || '📦 已压缩条目摘要'
        if (explicit === '') return '（未提供有效概括，点“看正文”）'
        return explicit
      }
      const boardRow = (entry) => {
        const authorRole = entry.author && entry.author.role ? entry.author.role : 'system'
        const isUserEntry = boardIsUserEntry(entry)
        const displayText = isUserEntry ? entry.text : boardEntrySummary(entry)
        const refs = entry.refs || {}
        const refButtons = []
        for (const nodeId of Array.isArray(refs.nodeIds) ? refs.nodeIds : []) {
          refButtons.push(h('button', {
            key: `rn-${nodeId}`, className: 'rc2-refchip',
            onClick: () => { setSelection({ type: 'node', id: nodeId }); focusNode(nodeId) },
          }, `${t('boardRefNode')} ${nodeId}`))
        }
        for (const vulnId of Array.isArray(refs.vulnIds) ? refs.vulnIds : []) {
          refButtons.push(h('button', {
            key: `rv-${vulnId}`, className: 'rc2-refchip',
            onClick: () => setSelection({ type: 'vuln', id: vulnId }),
          }, `${t('boardRefVuln')} ${vulnId}`))
        }
        for (const commandId of Array.isArray(refs.commandIds) ? refs.commandIds : []) {
          refButtons.push(h('button', {
            key: `rc-${commandId}`, className: 'rc2-refchip',
            onClick: () => setSelection({ type: 'command', id: commandId }),
          }, `${t('boardRefCmd')} ${commandId}`))
        }
        return h('div', { key: entry.id, className: 'rc2-boarditem' },
          h('div', { className: 'rc2-boardhead' },
            h('span', { className: 'rc2-author', style: { color: ROLE_COLOR[authorRole] || '#94a3b8', borderColor: ROLE_COLOR[authorRole] || '#94a3b8' } },
              (entry.author && entry.author.name) || '?'),
            h('span', { className: `rc2-kind k-${entry.kind}` }, kindLabel(entry.kind)),
            h('span', { className: 'rc2-meta' }, entry.ts ? fmtTime(new Date(entry.ts).toISOString()) : ''),
            h('span', { className: 'rc2-spacer' }),
            !isUserEntry ? h('button', {
              className: 'rc2-fchip', title: '用模型根据正文生成真正的概括',
              onClick: (event) => { event.stopPropagation(); void summarizeBoardEntry(entry) },
            }, '生成概括') : null,
            h('button', {
              className: 'rc2-fchip', title: '查看完整正文',
              onClick: (event) => { event.stopPropagation(); openSpot('board', entry.id) },
            }, '看正文'),
            h('button', {
              className: 'rc2-fchip',
              onClick: () => { void navigator.clipboard?.writeText(entry.text || '') },
            }, '复制'),
            h('button', {
              className: 'rc2-fchip',
              title: '编辑这条看板',
              onClick: async () => {
                const next = await uiPrompt({ title: '编辑看板', detail: '改正文（支持 Markdown）', value: entry.text || '', multiline: true, okText: '保存' })
                if (next === null) return
                await api({ op: 'board.edit', id: entry.id, text: next, engagement: engagement ? engagement.id : undefined })
                void refresh(engagement ? engagement.id : undefined)
              },
            }, '改'),
            h('button', {
              className: 'rc2-fchip danger',
              title: '删除这条看板',
              onClick: async () => {
                const ok = await uiConfirm({ title: '删除看板', detail: (entry.text || '').slice(0, 80), okText: '删除' })
                if (!ok) return
                await api({ op: 'board.remove', id: entry.id, engagement: engagement ? engagement.id : undefined })
                void refresh(engagement ? engagement.id : undefined)
              },
            }, '删')),
          h('div', { className: 'rc2-meta', style: { marginTop: 4 } }, isUserEntry ? '正文' : '概括'),
          h('div', { className: `rc2-boardtext${mdOn ? ' rc2-md' : ''}` }, displayText ? mdOrText(displayText, entry.id, mdOn) : ''),
          mergedAuthorsBlock(entry),
          refButtons.length > 0 ? h('div', { className: 'rc2-refs' }, refButtons) : null,
          Array.isArray(entry.shots) && entry.shots.length > 0
            ? h('div', { className: 'rc2-thumbs' }, entry.shots.map((shot) => h('a', {
              key: shot, href: apiUrl(`/recon/asset?p=${encodeURIComponent(shot)}`), target: '_blank', rel: 'noreferrer',
              className: 'rc2-thumb', title: shot,
            }, h('img', { src: apiUrl(`/recon/asset?p=${encodeURIComponent(shot)}`), alt: shot }))))
            : null)
      }

      /* 每个作者在看板里的条数：live=还没被压缩的，merged=压缩摘要里记下的 */
      const boardAuthorStats = new Map()
      const bumpAuthor = (name, field, count) => {
        if (name === '' || name === '?') return
        const rec = boardAuthorStats.get(name) || { live: 0, merged: 0 }
        rec[field] += count
        boardAuthorStats.set(name, rec)
      }
      for (const entry of boardEntries) {
        bumpAuthor((entry.author && entry.author.name) || '?', 'live', 1)
        const merged = entry.refs && entry.refs.merged
        if (merged && Array.isArray(merged.authors)) {
          for (const row of merged.authors) if (row && row.name) bumpAuthor(row.name, 'merged', Number(row.count) || 0)
        }
      }
      const boardAuthorTotal = (name) => {
        const rec = boardAuthorStats.get(name)
        return rec ? rec.live + rec.merged : 0
      }
      /* 「你」永远是下拉框第一项（即使还没发过言）；其余按发言量从多到少 */
      const boardAuthorNames = Array.from(boardAuthorStats.keys())
        .filter((name) => name !== '你')
        .sort((a, b) => boardAuthorTotal(b) - boardAuthorTotal(a))
      const boardAuthors = ['你', ...boardAuthorNames].slice(0, 30)
      /* 当前选中的队员即使已经没有未压缩发言，也要留在下拉框里，方便看他的压缩块 */
      const boardAuthorOptions = boardAuthor !== 'all' && boardAuthors.includes(boardAuthor) === false
        ? [...boardAuthors, boardAuthor]
        : boardAuthors
      /* 「你」的条数以服务端全量为准（不受显示切片影响）；其它作者按当前看板统计 */
      const boardUserPosts = Math.max(Number(boardUserCount) || 0, boardAuthorTotal('你'))
      const boardAuthorCountOf = (name) => (name === '你' ? boardUserPosts : boardAuthorTotal(name))
      /* 下拉框后面显示：选中谁 + 他在看板里一共多少条；选「全部」时显示「你 · N 条」 */
      const boardAuthorLabel = boardAuthor === 'all'
        ? `你 · ${boardUserPosts} 条`
        : `${boardAuthor} · ${boardAuthorCountOf(boardAuthor)} 条`
      const manualCompactBoard = async () => {
        if (engagement === null || engagement === undefined) return
        const count = Math.max(1, Math.min(100000, Math.floor(Number(boardCompressCount) || 0)))
        const res = await api({ op: 'board.compact', engagement: engagement.id, count })
        if (!res || !res.ok) {
          void uiAlert('手动压缩失败', res && res.error ? res.error : '未知错误')
          return
        }
        if (res.merged === null) {
          void uiAlert('没有可压缩的条目', res.note || '当前没有 agent 看板条目')
          return
        }
        await refresh(engagement.id)
      }
      const summarizeBoardEntry = async (entry) => {
        if (engagement === null || engagement === undefined) return
        const res = await api({ op: 'board.summarize', engagement: engagement.id, id: entry.id })
        if (!res || !res.ok) {
          void uiAlert('生成概括失败', res && res.error ? res.error : '未知错误')
          return
        }
        await refresh(engagement.id)
      }
      const boardCompactControls = h('div', { className: 'rc2-row', style: { gap: 4, flex: '0 0 auto' } },
        h('input', {
          className: 'rc2-search',
          type: 'number', min: 1, max: 100000, step: 1,
          style: { width: 62 },
          value: boardCompressCount,
          title: '手动压缩最早的 N 条 agent 看板，用户发言不会被压缩',
          onChange: (event) => setBoardCompressCount(Math.max(1, Math.min(100000, Number(event.target.value) || 1))),
        }),
        h('button', {
          className: 'rc2-btn ghost',
          onClick: () => { void manualCompactBoard() },
          title: '把输入数量的最早 agent 看板条目压成一条摘要；用户发言不会被压缩',
        }, '手动压缩'))
      const boardFilterBar = h('div', { className: 'rc2-filterbar', style: { borderBottom: '1px solid var(--dsw-alias-border-l1)' } },
        h('input', {
          className: 'rc2-search', style: { width: 160, height: 22 },
          value: boardQuery, placeholder: '搜索看板…',
          onChange: (event) => setBoardQuery(event.target.value),
        }),
        h('select', { className: 'rc2-select', style: { height: 22, fontSize: 11 }, value: boardKindFilter, onChange: (e) => setBoardKindFilter(e.target.value) },
          [['all', '全部类型'], ['finding', '发现'], ['hypothesis', '猜想'], ['task', '任务'], ['conclusion', '结论'], ['note', '备注']]
            .map(([value, label]) => h('option', { key: value, value }, label))),
        h('select', { className: 'rc2-select', style: { height: 22, fontSize: 11 }, value: boardAuthor, onChange: (e) => setBoardAuthor(e.target.value) },
          h('option', { value: 'all' }, '全部发言'),
          boardAuthorOptions.map((name) => h('option', { key: name, value: name }, name))),
        h('span', {
          className: 'rc2-boardwho',
          title: boardAuthor === 'all' ? `当前：全部发言（你的发言 ${boardUserPosts} 条）` : `当前只看：${boardAuthor}，共 ${boardAuthorCountOf(boardAuthor)} 条`,
        }, boardAuthorLabel),
        h('button', {
          className: 'rc2-btn ghost', style: { height: 22 },
          onClick: async () => {
            const res = await api({ op: 'board.export', engagement: engagement ? engagement.id : undefined })
            if (!res || !res.ok) return
            const blob = new Blob([res.markdown], { type: 'text/markdown' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = `board-${engagement ? engagement.name : 'eng'}.md`
            document.body.appendChild(link); link.click(); document.body.removeChild(link)
            setTimeout(() => URL.revokeObjectURL(url), 2000)
          },
        }, '导出'))

      const TASK_STATUS = {
        open: { label: '待派', color: '#94a3b8' },
        doing: { label: '进行中', color: '#38bdf8' },
        passed: { label: '已验收', color: '#34d399' },
        failed: { label: '驳回', color: '#f43f5e' },
        blocked: { label: '受阻', color: '#fbbf24' },
      }
      const roleNameOf = (id) => {
        const hit = roleList.find((role) => role.id === id)
        return hit ? hit.name : id
      }
      const missionBar = h('div', { className: 'rc2-missionbar' },
        h('span', { className: 'rc2-kind', style: { background: mission && mission.status === 'done' ? '#34d39922' : '#22d3ee22', color: mission && mission.status === 'done' ? '#34d399' : '#22d3ee' } },
          mission === null ? '未登记目标' : (mission.status === 'done' ? '已完成' : '进行中')),
        h('span', { className: 'rc2-mono', style: { flex: '1 1 auto', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, title: mission ? mission.goal : '' },
          mission !== null && mission.goal !== '' ? mission.goal : '点右侧「登记目标」写下这轮要达成什么'),
        missionProgress !== null
          ? h('span', { className: 'rc2-meta' }, `通过 ${missionProgress.passed}/${missionProgress.total}${missionProgress.failed > 0 ? ` · 驳回 ${missionProgress.failed}` : ''}`)
          : null,
        h('button', {
          className: 'rc2-btn ghost', style: { height: 20 },
          onClick: async () => {
            const goal = await uiPrompt({ title: '本轮作战目标', value: mission !== null ? mission.goal : '', okText: '下一步' })
            if (goal === null || goal.trim() === '') return
            const done = await uiPrompt({ title: '完成判据', detail: '什么样算完成（谁看都能判）', value: mission !== null ? (mission.done || '') : '', okText: '保存' })
            if (done === null) return
            const res = await api({ op: 'mission.set', goal: goal.trim(), done: done === null ? '' : done.trim(), engagement: engagement ? engagement.id : undefined })
            if (!res || res.ok === false) {
              await uiAlert('不能登记目标', `${res && res.error ? res.error : '未知错误'}${res && res.hint ? `\n\n${res.hint}` : ''}`)
              return
            }
            void refresh(engagement ? engagement.id : undefined)
          },
        }, mission === null ? '登记目标' : '改目标'),
        h('button', {
          className: 'rc2-btn on', style: { height: 20 },
          title: '全部任务通过 QA 验收后由总指挥宣布结束，并自动停止/回收非核心队员',
          onClick: async () => {
            const res = await api({ op: 'mission.close', engagement: engagement ? engagement.id : undefined })
            if (res && res.ok === false) {
              await uiAlert('还不能宣布完成', `${res.error}${Array.isArray(res.pending) ? `\n\n${res.pending.join('\n')}` : ''}`)
              return
            }
            if (res && res.ok) {
              await uiAlert('已宣布完成', `回收 ${Array.isArray(res.reclaimed) ? res.reclaimed.length : 0} 名空闲队员`)
            }
            void refresh(engagement ? engagement.id : undefined)
          },
        }, '宣布完成'))

      const meetingBar = h('div', { className: 'rc2-meetingbar' },
        h('span', { className: 'rc2-mb-label' }, '全员会议'),
        h('span', { className: 'rc2-mb-state' },
          runnerInfo.phase === 'paused' || runnerInfo.phase === 'pausing'
            ? '项目已暂停 · 周期审查暂停'
            : meetingInfo.reviewActive
              ? `周期审查中 · 每 ${meetingInfo.reviewMinutes} 分钟`
              : (meetingInfo.round > 0 ? `已召开 ${meetingInfo.round} 轮` : '未触发')),
        h('span', { className: 'rc2-spacer' }),
        h('button', {
          className: 'rc2-btn on',
          title: '让所有角色各自诊断原因、出 1-3 条新方案，总指挥汇总成新一轮任务',
          disabled: engagement === null || meetingBusy,
          onClick: async () => {
            if (engagement === null) return
            setMeetingBusy(true)
            const res = await api({ op: 'meeting.convene', engagement: engagement.id, reason: '指挥席手动召开' })
            setMeetingBusy(false)
            if (!res || !res.ok) { void uiAlert('召开失败', res && res.error ? res.error : '未知错误'); return }
            void refresh(engagement.id)
            setDockTab('board')
          },
        }, meetingBusy ? '召开中…' : '召开全员会议'))

      const taskPane = h('div', { className: 'rc2-board' },
        meetingBar,
        missionBar,
        h('div', { className: 'rc2-filterbar', style: { borderBottom: '1px solid var(--dsw-alias-border-l1)' } },
          h('span', { className: 'rc2-meta' }, `任务 ${taskStats.total}`),
          h('span', { className: 'rc2-fchip' }, `待派 ${taskStats.open}`),
          h('span', { className: 'rc2-fchip' }, `进行中 ${taskStats.doing}`),
          h('span', { className: 'rc2-fchip' }, `受阻 ${taskStats.blocked || 0}`),
          h('span', { className: 'rc2-fchip' }, `已验收 ${taskStats.passed}`),
          h('span', { className: 'rc2-fchip' }, `驳回 ${taskStats.failed}`),
          h('span', { className: 'rc2-spacer' }),
          h('select', {
            className: 'rc2-select', style: { height: 22, fontSize: 11, maxWidth: 130 },
            value: taskRole,
            title: '新任务负责角色',
            onChange: (event) => setTaskRole(event.target.value),
          }, (roleList.length > 0 ? roleList : [{ id: 'web', name: 'Web 手' }])
            .filter((role) => role.core !== true && role.id !== 'commander' && role.id !== 'staff')
            .map((role) => h('option', { key: role.id, value: role.id }, role.name || role.id))),
          h('button', {
            className: 'rc2-btn ghost', style: { height: 22 },
            onClick: async () => {
              const title = await uiPrompt({ title: '新建任务', detail: '任务标题', value: '', okText: '下一步' })
              if (title === null || title.trim() === '') return
              const goal = await uiPrompt({ title: '任务目标', detail: '具体到资产 / 接口', value: '', okText: '下一步' })
              if (goal === null) return
              const acceptance = await uiPrompt({ title: '验收标准', detail: '怎样算完成', value: '', okText: '创建' })
              if (acceptance === null) return
              await api({ op: 'task.create', title: title.trim(), goal, acceptance, role: taskRole, engagement: engagement ? engagement.id : undefined })
              void refresh(engagement ? engagement.id : undefined)
            },
          }, '＋ 新任务')),
        taskItems.length === 0
          ? h('div', { className: 'rc2-note', style: { padding: '10px 4px' } }, '还没有任务。让总指挥拆任务，或点右上「＋ 新任务」。')
          : taskItems.slice().reverse().map((task) => {
            const st = TASK_STATUS[task.status] || TASK_STATUS.open
            return h('div', { key: task.id, className: 'rc2-boarditem' },
              h('div', { className: 'rc2-boardhead' },
                h('span', { className: 'rc2-kind', style: { background: `${st.color}22`, color: st.color } }, st.label),
                h('span', { className: 'rc2-author', style: { color: 'var(--rc-accent)', borderColor: 'var(--rc-accent)' } }, roleNameOf(task.role)),
                h('span', { className: 'rc2-meta' }, task.id),
                h('span', { className: 'rc2-meta' }, task.assignee || '未指派'),
                h('span', { className: 'rc2-meta' }, task.verifiedBy && task.verifiedBy.role === 'qa' ? `QA ${task.verifiedBy.name || '已验收'}` : '待 QA'),
                h('span', { className: 'rc2-spacer' }),
                h('button', {
                  className: 'rc2-btn ghost', style: { height: 20 },
                  onClick: async () => {
                    const note = (await uiPrompt({ title: '验收通过', detail: '通过备注 / 证据说明', value: '', okText: '通过' })) || ''
                    await api({ op: 'task.accept', id: task.id, note, engagement: engagement ? engagement.id : undefined })
                    void refresh(engagement ? engagement.id : undefined)
                  },
                }, '验收通过'),
                h('button', {
                  className: 'rc2-btn ghost danger', style: { height: 20 },
                  onClick: async () => {
                    const note = await uiPrompt({ title: '验收驳回', detail: '缺什么 / 要补什么', value: '', okText: '驳回' })
                    if (note === null) return
                    await api({ op: 'task.reject', id: task.id, note, engagement: engagement ? engagement.id : undefined })
                    void refresh(engagement ? engagement.id : undefined)
                  },
                }, '驳回')),
              h('div', { className: 'rc2-boardtext' }, task.title),
              task.goal ? h('div', { className: 'rc2-meta', style: { marginTop: 4 } }, `🎯 ${task.goal}`) : null,
              task.acceptance ? h('div', { className: 'rc2-meta', style: { marginTop: 2 } }, `✅ 验收：${task.acceptance}`) : null,
              task.note ? h('div', { className: 'rc2-meta', style: { marginTop: 2, color: 'var(--rc-danger)' } }, `📝 ${task.note}`) : null
            )
          }))

      const paneMerged = mergedByAuthor(boardAuthor)
      const boardPane = h('div', { className: 'rc2-board' },
        boardFilterBar,
        paneMerged,
        boardEntries.length === 0 && paneMerged === null ? h('div', { className: 'rc2-note', style: { padding: '10px 4px' } }, t('boardEmpty')) : null,
        boardEntries.slice().reverse()
          .filter((entry) => (boardKindFilter === 'all' ? true : entry.kind === boardKindFilter))
          .filter((entry) => (boardAuthor === 'all' ? true : ((entry.author && entry.author.name) || '') === boardAuthor))
          .filter((entry) => {
            const needleBoard = boardQuery.trim().toLowerCase()
            if (needleBoard === '') return true
            return `${entry.text || ''} ${entry.summary || ''} ${(entry.author && entry.author.name) || ''} ${entry.kind}`.toLowerCase().includes(needleBoard)
          })
          .map(boardRow))

      /* 给某个在岗成员配置专属 MCP：一行一个，支持两种写法
         name = command args      （stdio）
         name = https://host/mcp  （streamable-http） */
      const editMemberMcp = async (member) => {
        const current = (Array.isArray(member.mcp) ? member.mcp : []).map(mcpLineOf).join('\n')
        const text = await uiPrompt({
          title: `${member.name} 的专属 MCP`,
          detail: '一行一个：name = command args（stdio），或 name = https://host/mcp（http）。留空表示不挂 MCP，只靠本机命令干活。',
          value: current,
          multiline: true,
        })
        if (text === null) return
        const rows = parseMcpLines(text)
        const res = await api({ op: 'squad.mcp', engagement: engagement ? engagement.id : undefined, member: member.key, mcp: rows })
        if (!res || !res.ok) { await uiAlert('MCP 保存失败', res && res.error ? res.error : '未知错误'); return }
        void refresh(engagement ? engagement.id : undefined)
      }

      const squadRow = (member) => {
        const head = h('div', { className: 'rc2-sqrow' },
          h('span', {
            className: `rc2-dot${member.status === 'running' || member.status === 'waiting' ? ' pulse' : ''}`,
            style: member.status === 'running' || member.status === 'waiting' ? undefined : { boxShadow: 'none', background: 'var(--dsw-alias-state-idle-primary)' },
          }),
          h('span', { className: 'rc2-sqid' },
            h('span', { className: 'rc2-author', style: { color: ROLE_COLOR[member.role] || '#94a3b8', borderColor: ROLE_COLOR[member.role] || '#94a3b8' } }, member.name),
            h('span', { className: 'rc2-meta' }, roleNameOf(member.role)),
            h('span', { className: 'rc2-meta' }, member.tier),
            Array.isArray(member.skills) && member.skills.length > 0
              ? h('span', { className: 'rc2-meta', title: member.skills.join(', '), style: { color: 'var(--rc-accent)' } }, `⚡${member.skills.length}`)
              : null,
            member.promptExtra ? h('span', { className: 'rc2-meta', title: member.promptExtra, style: { color: '#a3e635' } }, '📌') : null,
            Array.isArray(member.mcp) && member.mcp.length > 0
              ? h('span', { className: 'rc2-meta', title: member.mcp.map((row) => row.name).join(', '), style: { color: '#38bdf8' } }, `🔌${member.mcp.length}`)
              : h('span', { className: 'rc2-meta', style: { opacity: 0.6 }, title: '未挂专属 MCP：直接用本机命令干活' }, 'Shell'),
            member.groupId ? h('span', { className: 'rc2-meta', title: `协作小组 ${member.groupId}${member.waitingFor ? `；等待 ${member.waitingFor}` : ''}`, style: { color: '#c084fc' } }, '👥组') : null),
          h('span', { className: 'rc2-sqstate' },
            h('span', { className: `rc2-sqpill ${member.status}` },
              member.status === 'running' ? t('runningAgents')
                : member.status === 'waiting' ? '等待协作'
                  : member.status === 'starting' ? t('agentStarting')
                    : member.status === 'done' ? t('agentDone') : t('agentIdle')),
            member.idleSince ? h('span', { className: 'rc2-meta' }, `${Math.max(0, Math.round((Date.now() - member.idleSince) / 60000))}m`) : null),
          h('span', { className: 'rc2-sqtask', title: member.task || '' }, member.task ? `▸ ${member.task}` : '—'),
          h('span', { className: 'rc2-sqacts' },
            h('button', { className: 'rc2-btn ghost', title: '配置这名队员的专属 MCP', onClick: () => void editMemberMcp(member) }, 'MCP'),
            h('button', { className: 'rc2-btn ghost', onClick: () => void addMemberTask(member) }, t('squadAsk')),
            (member.core === true || member.role === 'commander' || member.role === 'staff')
              ? null
              : h('button', { className: 'rc2-btn ghost', onClick: () => void stopMember(member.name) }, t('squadStop')),
            (member.core === true || member.role === 'commander' || member.role === 'staff')
              ? h('span', { className: 'rc2-meta', title: '常设席位：每靶标各一个，不会被释放', style: { color: '#fbbf24' } }, '常设')
              : h('button', { className: 'rc2-btn ghost danger', onClick: () => void removeMember(member.name) }, t('squadRemove'))))

        const hasOut = Boolean(member.lastTool || member.lastText)
        const out = hasOut
          ? h('div', { className: 'rc2-sqout', title: `${member.lastTool || ''} ${member.lastText || ''}` },
            member.lastTool ? h('span', { className: 'rc2-sqtool' }, `⚙ ${shortText(member.lastTool, 40)}`) : null,
            member.lastText ? h('span', { className: 'rc2-sqtext' }, member.lastText) : null)
          : null

        return h('div', { key: member.key, className: 'rc2-sqcard' }, head, out)
      }

      const squadPane = h('div', { className: 'rc2-board rc2-squadlist' },
        squadMembers.length === 0 ? h('div', { className: 'rc2-note', style: { padding: '10px 4px' } }, t('squadEmpty')) : null,
        squadMembers.map(squadRow))

      const tabBtn = (id, label, badge) => h('button', {
        key: id,
        className: `rc2-docktab${dockTab === id ? ' on' : ''}`,
        onClick: () => { setDockTab(id); setDockOpen(true) },
      }, label, badge ? h('span', { className: 'n' }, badge) : null)

      const chatControls = [
        h('button', {
          key: 'export',
          className: 'rc2-btn ghost',
          onClick: async () => {
            const res = await api({ op: 'chat.export', engagement: engagement ? engagement.id : undefined })
            if (!res || !res.ok) return
            const blob = new Blob([res.markdown], { type: 'text/markdown' })
            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = `chat-${engagement ? engagement.name : 'eng'}.md`
            document.body.appendChild(link); link.click(); document.body.removeChild(link)
            setTimeout(() => URL.revokeObjectURL(url), 2000)
          },
        }, '导出'),
        h('button', { key: 'think', className: `rc2-btn ghost${showThinking ? ' on' : ''}`, onClick: () => setShowThinking((v) => !v) }, t('showThinking')),
        h('button', {
          key: 'clear',
          className: 'rc2-btn ghost',
          onClick: async () => {
            if (engagement === null) return
            await api({ op: 'chat.clear', engagement: engagement.id })
            setChat((prev) => ({ ...prev, messages: [] }))
            setToolLines([])
          },
        }, '⌫'),
      ]

      /* 右栏：上=漏洞列表，下=看板（并列常驻，避免左侧刷屏时右侧太空） */
      const rightBoardRows = boardEntries.slice().reverse()
        .filter((entry) => (boardKindFilter === 'all' ? true : entry.kind === boardKindFilter))
        .filter((entry) => (boardAuthor === 'all' ? true : ((entry.author && entry.author.name) || '') === boardAuthor))
        .filter((entry) => {
          const needleBoard = boardQuery.trim().toLowerCase()
          if (needleBoard === '') return true
          return `${entry.text || ''} ${(entry.author && entry.author.name) || ''} ${entry.kind}`.toLowerCase().includes(needleBoard)
        })
        .slice(0, 60)

      const vulnSplitter = h('div', {
        className: 'rc2-hsplitter rc2-hsplit-labelled',
        title: `拖动调整漏洞 / 看板高度（当前 漏洞 ${Math.round(vulnRatio * 100)}% · 看板 ${100 - Math.round(vulnRatio * 100)}%）`,
        onMouseDown: (event) => {
          event.preventDefault()
          const rail = event.currentTarget.parentElement
          const box = rail.getBoundingClientRect()
          let ratio = vulnRatio
          const onMove = (moveEvent) => {
            ratio = Math.min(0.88, Math.max(0.12, (moveEvent.clientY - box.top) / Math.max(1, box.height)))
            setVulnRatio(ratio)
          }
          const onUp = () => {
            window.removeEventListener('mousemove', onMove)
            window.removeEventListener('mouseup', onUp)
            try { window.localStorage.setItem('rc2.vulnRatio', String(Number(ratio.toFixed(3)))) } catch { /* 忽略 */ }
          }
          window.addEventListener('mousemove', onMove)
          window.addEventListener('mouseup', onUp)
        },
      }, h('span', { className: 'rc2-hsplit-tag' },
        `${Math.round(vulnRatio * 100)}% / ${100 - Math.round(vulnRatio * 100)}%`))

      const railMerged = mergedByAuthor(boardAuthor)
      const vulnFeed = h('div', { className: 'rc2-rail right', style: { flex: `0 0 ${rightWidth}px` } },
        vulnRailHead,
        h('div', { style: { flex: `0 0 ${Math.round(vulnRatio * 100)}%`, display: 'flex', minHeight: 0 } }, vulnRailRows),
        vulnSplitter,
        h('div', { className: 'rc2-railhead' },
          h('span', { className: 'rc2-dot', style: { background: '#38bdf8', boxShadow: '0 0 8px #38bdf8' } }),
          h('span', { className: 'rc2-railhead-title' }, t('dockBoard')),
          h('b', { title: `共 ${Math.max(boardTotal, boardEntries.length)} 条：agent ${boardAgentCount}（上限 ${boardLimit}，超限合并）· 你 ${boardUserCount}（无上限、永不压缩）` },
            `${Math.max(boardTotal, boardEntries.length)}/${boardLimit}`),
          h('span', { className: 'rc2-spacer' }),
          h('button', { className: 'rc2-zoom', style: { opacity: 1 }, title: '看板放大到中央', onClick: () => setPanelSpot('board') }, '⤢'),
          h('button', {
            className: 'rc2-btn ghost', style: { height: 20 },
            onClick: async () => {
              const res = await api({ op: 'board.export', engagement: engagement ? engagement.id : undefined })
              if (!res || !res.ok) return
              const blob = new Blob([res.markdown], { type: 'text/markdown' })
              const url = URL.createObjectURL(blob)
              const link = document.createElement('a')
              link.href = url
              link.download = `board-${engagement ? engagement.name : 'eng'}.md`
              document.body.appendChild(link); link.click(); document.body.removeChild(link)
              setTimeout(() => URL.revokeObjectURL(url), 2000)
            },
          }, '↓')),
        h('div', { className: 'rc2-boardbar' },
          h('select', {
            className: 'rc2-select', title: '只看某个队员的发言',
            style: { height: 22, fontSize: 11, maxWidth: 110 },
            value: boardAuthor,
            onChange: (event) => setBoardAuthor(event.target.value),
          }, [h('option', { key: 'all', value: 'all' }, '全部发言'),
            ...boardAuthorOptions.map((name) => h('option', { key: name, value: name }, name))]),
          h('span', {
            className: 'rc2-boardwho',
            title: boardAuthor === 'all' ? `当前：全部发言（你的发言 ${boardUserPosts} 条）` : `当前只看：${boardAuthor}，共 ${boardAuthorCountOf(boardAuthor)} 条`,
          }, boardAuthorLabel),
          h('span', { className: 'rc2-spacer' }),
          h('div', { className: 'rc2-boardbar-actions' },
            h('input', {
              className: 'rc2-search', style: { width: 96, fontSize: 10.5 },
              value: boardQuery, placeholder: '搜索…',
              onChange: (event) => setBoardQuery(event.target.value),
            }),
            boardCompactControls)),
        h('div', { className: 'rc2-feed rc2-feed-grow', style: { flex: '1 1 auto', minHeight: 0 } },
          railMerged,
          rightBoardRows.length === 0 && railMerged === null
            ? h('div', { className: 'rc2-empty', style: { padding: '16px 8px' } }, h('p', null, t('boardEmpty')))
            : rightBoardRows.map(boardRow)))


      /* ── 总结汇报：只读聚合视图（资产拓扑 + 漏洞列表 + 看板 + 队员状态）
         不调用任何写接口、不派活、不改图，纯展示，保证不干扰任何流程 ── */
      const briefReport = (() => {
        const verified = (vulns || []).filter((v) => v.status === 'verified').length
        const passRate = taskStats.total === 0 ? 0 : Math.round((taskStats.passed / taskStats.total) * 100)
        const running = squadMembers.filter((m) => m.status === 'running').length
        const k = mission && mission.goal ? `目标：${mission.goal}` : '尚未登记作战目标'
        return `当前进度 · ${engagement !== null ? engagement.name : '未命名项目'}\n`
          + `${k}\n`
          + `资产 ${nodes.length} · 关系 ${(edges || []).length} · 漏洞 ${(vulns || []).length}（已验证 ${verified}）\n`
          + `命令 ${stats !== null ? stats.commands : 0} · 下派 ${delegation !== null ? delegation.delegated + '/' + delegation.total : '0/0'}\n`
          + `任务 ${taskStats.total}（通过 ${taskStats.passed}，通过率 ${passRate}%）· 在岗 ${squadMembers.length}（在跑 ${running}）`
      })()

      const briefAnswer = (question) => {
        const q = String(question || '').toLowerCase()
        const verified = (vulns || []).filter((v) => v.status === 'verified').length
        const running = squadMembers.filter((m) => m.status === 'running').length

        if (/队员|成员|人员|谁|状态|在岗|在跑/.test(q)) {
          if (squadMembers.length === 0) return '当前没有队员在岗。需要干活时可在「队伍」页签招募，或让总指挥派活。'
          return '队员状态：\n' + squadMembers.map((m) => {
            const state = m.status === 'running' ? '在跑' : (m.status === 'starting' ? '启动中' : '待命')
            return `· ${m.name}（${roleNameOf(m.role)}）${state}`
              + (m.task ? `\n  任务：${m.task}` : '')
              + (m.lastTool ? `\n  最近：${shortText(m.lastTool, 60)}` : '')
          }).join('\n') + `\n共 ${squadMembers.length} 人，在跑 ${running} 人。`
        }

        if (/漏洞|风险|结果|verified|验证/.test(q)) {
          if ((vulns || []).length === 0) return '还没有登记漏洞。'
          const top = (vulns || []).slice()
            .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
            .slice(0, 6)
          return `漏洞 ${(vulns || []).length} 条（已验证 ${verified}）：\n` + top.map((v) =>
            `· [${String(v.severity).toUpperCase()}] ${v.title}`
            + (v.status === 'verified' ? ' — 已验证' : (v.status === 'false-positive' ? ' — 误报' : ''))).join('\n')
        }

        if (/任务|验收|驳回|返工/.test(q)) {
          const open = taskItems.filter((t2) => t2.status === 'open').length
          const doing = taskItems.filter((t2) => t2.status === 'doing').length
          const failed = taskItems.filter((t2) => t2.status === 'failed').length
          const recent = taskItems.slice(-4).reverse().map((t2) =>
            `· [${t2.status}] ${t2.title}`)
          return `任务 ${taskStats.total}：待派 ${open} · 进行中 ${doing} · 通过 ${taskStats.passed} · 驳回 ${failed}\n`
            + (recent.length > 0 ? `最近：\n${recent.join('\n')}` : '暂无任务记录。')
        }

        if (/资产|拓扑|节点|面|范围/.test(q)) {
          const kinds = new Map()
          for (const node of nodes || []) kinds.set(node.kind || 'note', (kinds.get(node.kind || 'note') || 0) + 1)
          const top = Array.from(kinds.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8)
          return `资产 ${nodes.length} 个节点、${(edges || []).length} 条关系。\n`
            + `类型分布：${top.map(([kind, count]) => `${kind} ${count}`).join(' · ')}\n`
            + '完整拓扑按类型着色显示在中间图谱里。'
        }

        if (/看板|发现|结论|留言/.test(q)) {
          const recent = (boardEntries || []).slice(-5).reverse()
          if (recent.length === 0) return '看板还没有内容。'
          return '最近看板：\n' + recent.map((entry) =>
            `· [${entry.kind}] ${entry.text || ''}`).join('\n')
        }

        if (/命令|执行|跑了|留痕/.test(q)) {
          return `命令 ${stats !== null ? stats.commands : 0} 条，其中下派给队员 ${delegation !== null ? delegation.delegated : 0} 条、`
            + `总指挥自己执行 ${delegation !== null ? delegation.own : 0} 条。每条命令的原始输出都在左侧轨迹里可点开。`
        }

        if (/进度|总体|现在|情况|怎么样|如何|汇报|总结/.test(q)) {
          return briefReport
        }

        return '我可以汇报：进度总览、队员状态、漏洞清单、任务情况、资产分布、看板与命令留痕。\n'
          + '换个问法也行，例如「现在什么进度」「谁在跑」「有多少已验证漏洞」。\n\n' + briefReport
      }

      /* 提问分两路：local 只做本地速览（不花钱、瞬间出结果），agent 真的把问题发给总指挥并调模型 */
      const askBrief = (mode = 'agent') => {
        const question = briefDraft.trim()
        if (question === '') return
        setBriefDraft('')
        if (mode === 'agent') {
          void (async () => {
            setBriefBusy(true)
            setBriefStream('')
            const res = await api({
              op: 'brief.chat',
              question,
              engagement: engagement ? engagement.id : undefined,
            })
            if (!res || !res.ok) {
              setBriefBusy(false)
              setBriefMsgs((prev) => prev.concat([{ id: `be_${Date.now()}`, role: 'assistant', text: `汇报席没能回答：${res && res.error ? res.error : '未知错误'}` }]))
            }
          })()
          return
        }
        let answer = ''
        try {
          answer = briefAnswer(question)
        } catch (error) {
          answer = `本地速览生成失败：${error && error.message ? error.message : String(error)}。改用「问总指挥」让模型回答。`
        }
        setBriefMsgs((prev) => prev.concat([
          { role: 'user', text: question },
          { role: 'bot', text: answer },
        ]))
      }

      useEffect(() => {
        const node = briefRef.current
        if (node !== null) node.scrollTop = node.scrollHeight
      }, [briefMsgs, briefStream, briefBusy])

      /* 队列任务：上一轮结束后自动发下一条（只在空闲时出队，不打断任何进行中的工作） */
      useEffect(() => {
        if (targetBusy) return
        if (chatQueue.length === 0) return
        const next = chatQueue[0]
        setChatQueue((prev) => prev.slice(1))
        void deliver(next)
      }, [targetBusy, chatQueue, deliver])

      const briefRows = briefMsgs.map((message, index) => h('div', {
        key: message.id ? `bf-${message.id}` : `bf-${index}`,
        className: `rc2-msg ${message.role === 'user' ? 'user' : 'ai'}`,
      }, message.role === 'user'
        ? message.text
        : h('div', { className: mdOn ? 'rc2-md' : '' }, mdOrText(message.text, `bf${index}`, mdOn))))
        .concat(briefStream !== '' || briefBusy
          ? [h('div', { key: 'bf-stream', className: 'rc2-msg ai' },
            briefStream !== ''
              ? h('div', { className: mdOn ? 'rc2-md' : '' }, mdOrText(briefStream, 'bfstream', mdOn))
              : h('span', { className: 'rc2-briefwaiting' }, '汇报席正在读当前战况…'))]
          : [])

      const briefPane = h('div', { className: 'rc2-briefwrap' },
        h('div', { className: 'rc2-chat', ref: briefRef }, briefRows),
        h('div', { className: 'rc2-briefhint' },
          briefBusy ? '汇报席正在读当前战况…' : '独立对话（fork 自总指挥，只读）· 每轮都带最新战况 · 不污染对话上下文'),
        h('div', { className: 'rc2-row', style: { padding: '2px 10px 0', gap: 6, flexWrap: 'wrap' } },
          ['现在进度如何', '还差什么才能收官', '谁在跑', '有没有新漏洞'].map((label) => h('button', {
            key: label,
            className: 'rc2-chip',
            onClick: () => {
              void (async () => {
                setBriefBusy(true)
                setBriefStream('')
                const res = await api({
                  op: 'brief.chat',
                  question: label,
                  engagement: engagement ? engagement.id : undefined,
                })
                if (!res || !res.ok) {
                  setBriefBusy(false)
                  setBriefMsgs((prev) => prev.concat([{ id: `be_${Date.now()}`, role: 'assistant', text: `汇报席没能回答：${res && res.error ? res.error : '未知错误'}` }]))
                }
              })()
            },
          }, label))),
        h('div', { className: 'rc2-composer rc2-briefinput' },
          h('textarea', {
            className: 'rc2-input rc2-grow',
            rows: 1,
            value: briefDraft,
            placeholder: '直接问总指挥：进度如何、谁在跑、还差什么…（Enter 发送）',
            onChange: (event) => setBriefDraft(event.target.value),
            onKeyDown: (event) => {
              if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && !(event.nativeEvent && event.nativeEvent.isComposing)) {
                event.preventDefault()
                askBrief('agent')
              }
            },
          }),
          h('button', {
            className: 'rc2-btn ghost', title: '清空汇报席的历史（不影响总指挥）',
            onClick: async () => {
              const ok = await uiConfirm('清空汇报席', '只清掉这段独立对话的历史，总指挥的上下文和图谱都不动。确定？')
              if (!ok) return
              await api({ op: 'brief.clear', engagement: engagement ? engagement.id : undefined })
              setBriefMsgs([]); setBriefStream(''); setBriefBusy(false)
            },
          }, '清空'),
          h('button', { className: 'rc2-btn ghost', title: '不调用模型，用本地数据拼一份速览', onClick: () => askBrief('local'), disabled: briefDraft.trim() === '' }, '速览'),
          h('button', { className: 'rc2-btn on', onClick: () => askBrief('agent'), disabled: briefDraft.trim() === '' }, '问总指挥'),
          ))

      const dockBody = dockTab === 'chat'
        ? h('div', { className: 'rc2-chat', ref: chatRef }, chatRows)
        : dockTab === 'brief' ? briefPane
          : dockTab === 'board' ? boardPane : dockTab === 'task' ? taskPane : squadPane


      const QUICK_PROMPTS = [
        ['一句话开作战', '在 TARGET 上找一个反序列化漏洞。按完整队伍流程推进：参谋出方案 → 你拆任务 → 按角色派人（信息收集/Web/逆向/内网视需要）→ 验收实测 → 通过后向我汇报结论与证据。不要自己单干，也不要在没验收前就说完成。'],
        ['参谋出方案', '让参谋出一版作战方案：攻击面优先级、最可能的突破点、以及带验收标准的任务拆解建议。只出方案，不执行。'],
        ['新资产 → Web 手', '从现在起，每发现一个新资产（子域/IP/URL/服务/接口），自动派 Web 手去探测它有没有漏洞。用 recon_watch 配好并告诉我规则 id。'],
        ['新漏洞 → 验收', '从现在起，每当登记一个新漏洞（critical/high/medium），自动派验收员独立复现一次，判定 verified 还是误报，并更新状态。用 recon_watch 配好。'],
        ['验收全部漏洞', '列出图谱里所有 status=open 的漏洞，逐条独立复现判定真伪：可复现→verified，误报→false-positive，并写清证据。'],
        ['每 30 分钟巡检', '配置一条定时巡检：每 30 分钟派分析员读图谱与看板，给出下一步 3 条高价值任务。用 recon_watch，on=interval。'],
        ['看当前规则', '列出当前的事件触发规则（recon_watch list），一句话总结每条规则在什么条件下派谁干什么。'],
        ['配 FOFA key', '我要配置 FOFA 的 key，值是：'],
        ['配 GitHub token', '我要配置 GitHub token，值是：'],
      ]
      const quickChips = h('div', { className: 'rc2-quickchips' },
        QUICK_PROMPTS.map(([label, text]) => h('button', {
          key: label,
          className: 'rc2-fchip',
          onClick: () => {
            if (label.startsWith('配 ')) {
              setDraft(text)
              return
            }
            void sendText(text)
          },
        }, label)))

      const attachBar = (files.length + shots.length === 0 && uploading !== true) ? null : h('div', { className: 'rc2-attachbar' },
        files.map((file) => h('span', { key: file.path, className: 'rc2-attach', title: file.path },
          '📎 ', h('span', null, file.name), ` ${Math.round((file.bytes || 0) / 1024)}KB`,
          h('button', { onClick: () => setFiles((prev) => prev.filter((f2) => f2.path !== file.path)) }, '✕'))),
        shots.map((shot) => h('span', { key: shot.id, className: 'rc2-attach' },
          '🖼 ', h('span', null, shot.name),
          h('button', { onClick: () => setShots((prev) => prev.filter((s2) => s2.id !== shot.id)) }, '✕'))),
        uploading ? h('span', { className: 'rc2-meta' }, '上传中…')
          : (files.length + shots.length === 0
            ? null
            : h('span', { className: 'rc2-meta' }, `${files.length + shots.length} 个附件`)))

      /* 总结汇报是纯只读页：不渲染任何输入区（对话输入 / 招募派活），保证不干扰流程 */
      const dockComposer = dockTab === 'brief' ? null : dockTab === 'chat'
        ? h('div', null,
          h('input', {
            ref: fileInputRef,
            type: 'file',
            multiple: true,
            style: { display: 'none' },
            onChange: (event) => { void uploadFiles(event.target.files); event.target.value = '' },
          }),
          quickChips,
          h('div', {
            onDragOver: (event) => { event.preventDefault() },
            onDrop: (event) => { event.preventDefault(); void uploadFiles(event.dataTransfer && event.dataTransfer.files) },
          },
          attachBar),
          shots.length > 0 ? h('div', { className: 'rc2-shots' }, shots.map((shot) => h('div', { key: shot.id, className: 'rc2-shot' },
            h('img', { src: shot.dataUrl, alt: shot.name }),
            h('button', { onClick: () => setShots((prev) => prev.filter((s2) => s2.id !== shot.id)) }, '✕')))) : null,
          h('div', { className: 'rc2-inputrow' },
            h('button', { className: 'rc2-btn', onClick: () => fileInputRef.current && fileInputRef.current.click() }, '📎'),
            h('textarea', {
              className: 'rc2-input',
              value: draft,
              placeholder: t('chatPlaceholder'),
              onChange: (event) => setDraft(event.target.value),
              onPaste: (event) => {
                const files = event.clipboardData && event.clipboardData.files ? Array.from(event.clipboardData.files) : []
                const picks = files.filter((file) => /^image\//.test(file.type)).slice(0, 4)
                const others = files.filter((file) => !/^image\//.test(file.type))
                if (others.length > 0) { event.preventDefault(); void uploadFiles(others) }
                if (picks.length === 0) return
                event.preventDefault()
                for (const file of picks) {
                  const reader = new FileReader()
                  reader.onload = () => {
                    const dataUrl = String(reader.result || '')
                    const base64 = dataUrl.includes(',') ? dataUrl.slice(dataUrl.indexOf(',') + 1) : ''
                    if (base64 === '') return
                    setShots((prev) => [...prev.slice(-3), {
                      id: `shot${Date.now()}${Math.random().toString(36).slice(2, 5)}`,
                      name: file.name || 'clipboard.png',
                      mediaType: file.type || 'image/png',
                      dataUrl,
                      base64,
                    }])
                  }
                  reader.readAsDataURL(file)
                }
              },
              onKeyDown: (event) => {
                if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && !(event.nativeEvent && event.nativeEvent.isComposing)) { event.preventDefault(); void sendChat() }
              },
            }),
            h('button', { className: 'rc2-btn on', onClick: () => void sendChat(), disabled: draft.trim() === '' && files.length === 0 && shots.length === 0 }, t('send')),
            targetBusy ? h('button', {
              className: 'rc2-btn danger',
              onClick: () => {
                if (chatTarget === 'lead') void stopChat()
                else if (chatTargetMember !== null && chatTargetMember !== undefined) {
                  void api({ op: 'squad.stop', member: chatTargetMember.name, engagement: engagement ? engagement.id : undefined })
                }
              },
            }, t('stop')) : null))
        : dockTab === 'task'
          ? h('div', { className: 'rc2-inputrow' },
            h('span', { className: 'rc2-meta' }, '任务由总指挥用 recon_task 拆解；验收员在这里点通过/驳回。'),
            h('button', {
              className: 'rc2-btn ghost',
              onClick: async () => {
                await sendText('作为总指挥，先让参谋出方案，然后拆成带验收标准的任务派给对应角色；派完给我一张任务清单。')
              },
            }, '让总指挥开工'))
          : dockTab === 'board'
          ? h('div', { className: 'rc2-inputrow' },
            h('select', { className: 'rc2-select', value: boardKind, onChange: (event) => setBoardKind(event.target.value) },
              ['finding', 'hypothesis', 'task', 'conclusion', 'note'].map((kind) => h('option', { key: kind, value: kind }, kindLabel(kind)))),
            h('textarea', {
              className: 'rc2-input',
              style: { minHeight: 34 },
              value: boardDraft,
              placeholder: t('boardHint'),
              onChange: (event) => setBoardDraft(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && !(event.nativeEvent && event.nativeEvent.isComposing)) { event.preventDefault(); void postBoard() }
              },
            }),
            h('button', { className: 'rc2-btn on', onClick: () => void postBoard(), disabled: boardDraft.trim() === '' }, t('boardPost')))
          : h('div', null,
            h('div', { className: 'rc2-inputrow' },
            h('select', { className: 'rc2-select', value: spawnRole, onChange: (event) => setSpawnRole(event.target.value) },
              (roleList.length > 0 ? roleList : [
                { id: 'scout', name: '信息收集' }, { id: 'web', name: 'Web 手' }, { id: 'reverser', name: '逆向手' },
                { id: 'intranet', name: '内网手' }, { id: 'qa', name: '验收' },
              ]).filter((role) => role.core !== true && role.id !== 'commander' && role.id !== 'staff')
                .map((role) => h('option', { key: role.id, value: role.id }, `${role.name}（${role.id}）`))),
            h('select', { className: 'rc2-select', value: spawnTier, onChange: (event) => setSpawnTier(event.target.value) },
              MODEL_CHOICES.map((tier) => h('option', { key: tier, value: tier }, TIER_LABEL[tier]))),
            h('input', {
              className: 'rc2-input', style: { width: 120, minHeight: 28 },
              value: spawnName, placeholder: '代号（可选）',
              onChange: (event) => setSpawnName(event.target.value),
            }),
            h('input', {
              className: 'rc2-input', style: { width: 150, minHeight: 28 },
              value: spawnSkills, placeholder: '技能，逗号分隔',
              title: '给这名队员点开的 skills，例如 web-fingerprint,nuclei-scan',
              onChange: (event) => setSpawnSkills(event.target.value),
            }),
            h('textarea', {
              className: 'rc2-input',
              style: { minHeight: 34 },
              value: spawnTask,
              placeholder: t('squadTask') + '…',
              onChange: (event) => setSpawnTask(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && !(event.nativeEvent && event.nativeEvent.isComposing)) { event.preventDefault(); void spawnMember() }
              },
            }),
            h('button', { className: 'rc2-btn on', onClick: () => void spawnMember(), disabled: spawnTask.trim() === '' }, t('squadSpawn'))),
            h('div', { className: 'rc2-inputrow', style: { paddingTop: 0 } },
              h('span', { className: 'rc2-meta' }, '专属指令'),
              h('input', {
                className: 'rc2-input', style: { flex: '1 1 auto', minHeight: 26 },
                value: spawnPrompt, placeholder: '给这名队员的最高优先级指令：目标 / 边界 / 产出 / 禁止事项',
                onChange: (event) => setSpawnPrompt(event.target.value),
              })))

      /* ── 聚光灯：把命令 / 漏洞 / 看板条目放大到网页中央 ── */
      const openSpot = useCallback((kind, id) => {
        setSpot({ kind, id })
        setSpotText('')
        if (kind !== 'command') return
        setSpotBusy(true)
        api({ op: 'command', commandId: id, engagement: engagement ? engagement.id : undefined }).then((res) => {
          setSpotBusy(false)
          if (res && res.ok) setSpotText(String(res.text === undefined || res.text === null ? '' : res.text))
          else setSpotText(res && res.error ? `读取失败：${res.error}` : '读取失败')
        })
      }, [engagement])

      useEffect(() => {
        if (spot === null && panelSpot === null) return undefined
        const onKey = (event) => {
          if (event.key !== 'Escape') return
          if (spot !== null) setSpot(null)
          else setPanelSpot(null)
        }
        window.addEventListener('keydown', onKey)
        return () => window.removeEventListener('keydown', onKey)
      }, [spot, panelSpot])

      /* ── 面板级放大：轨迹 / 漏洞 / 看板 / 对话 整块放到屏幕中央 ── */
      const panelSpotOverlay = panelSpot === null ? null : (() => {
        const titles = { trace: '轨迹', vulns: '漏洞面板', board: '看板', chat: '对话' }
        let rows = null
        if (panelSpot === 'trace') {
          rows = h('div', { className: 'rc2-feed', style: { flex: '1 1 auto' } },
            traceFiltered.slice(-traceLimit).map(traceRow))
        } else if (panelSpot === 'vulns') {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
          const list = vulns.slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9))
          rows = h('div', { className: 'rc2-feed', style: { flex: '1 1 auto' } },
            list.length === 0
              ? h('div', { className: 'rc2-empty', style: { padding: 20 } }, h('p', null, t('noOutput')))
              : list.map((v) => {
                const node = nodes.find((n) => n.id === v.nodeId)
                return h('div', {
                  key: v.id, className: 'rc2-item rc2-vulnrow',
                  onClick: () => { setSelection({ type: 'vuln', id: v.id }); if (node) focusNode(node.id) },
                },
                h('div', { className: 'rc2-line' },
                  h('span', { className: 'rc2-sev', style: { background: SEV_COLOR[v.severity] || SEV_COLOR.info } }, v.severity || 'info'),
                  h('span', { className: 'rc2-mono', style: { fontSize: 12.5 } }, v.title),
                  h('span', { className: 'rc2-spacer' }),
                  h('span', { className: 'rc2-meta' }, node ? node.value : v.nodeId),
                  v.status !== 'open' ? h('span', { className: 'rc2-meta', style: { color: 'var(--rc-accent)' } }, v.status) : null,
                  h('button', {
                    className: 'rc2-zoom', style: { opacity: 1 }, title: '单条放大',
                    onClick: (event) => { event.stopPropagation(); openSpot('vuln', v.id) },
                  }, '⤢')))
              }))
        } else if (panelSpot === 'board') {
          const spotMerged = mergedByAuthor(boardAuthor)
          const spotRows = boardEntries.slice().reverse()
            .filter((entry) => (boardKindFilter === 'all' ? true : entry.kind === boardKindFilter))
            .filter((entry) => (boardAuthor === 'all' ? true : ((entry.author && entry.author.name) || '') === boardAuthor))
            .filter((entry) => {
              const needleBoard = boardQuery.trim().toLowerCase()
              if (needleBoard === '') return true
              return `${entry.text || ''} ${(entry.author && entry.author.name) || ''} ${entry.kind}`.toLowerCase().includes(needleBoard)
            })
          rows = h('div', { className: 'rc2-feed', style: { flex: '1 1 auto' } },
            spotMerged,
            spotRows.map(boardRow))
        } else {
          rows = h('div', { className: 'rc2-chat', style: { flex: '1 1 auto' } }, chatRows)
        }
        return h('div', { className: 'rc2-panelspot rc2-panelspot-' + panelSpot, onClick: () => setPanelSpot(null) },
          h('div', { className: 'rc2-panelspotcard', onClick: (event) => event.stopPropagation() },
            h('div', { className: 'rc2-panelspothead' },
              h('span', { className: 'rc2-dot pulse' }),
              h('span', { className: 'rc2-zoom-title' }, titles[panelSpot]),
              h('span', { className: 'rc2-zoom-sub' },
                panelSpot === 'trace' ? `${traceFiltered.length} 条事件`
                  : panelSpot === 'vulns' ? `${vulns.length} 条漏洞`
                    : panelSpot === 'board' ? `${boardEntries.length} 条看板`
                      : `${chat.messages.length} 条消息`),
              h('span', { className: 'rc2-spacer' }),
              panelSpot === 'trace' ? h('input', {
                className: 'rc2-search', style: { width: 160, height: 22 },
                value: traceQuery, placeholder: '搜轨迹…',
                onChange: (event) => setTraceQuery(event.target.value),
              }) : null,
              panelSpot === 'trace' ? h('button', {
                className: `rc2-fchip${traceNoBash ? ' on' : ''}`,
                onClick: () => setTraceNoBash((v) => !v),
              }, '屏蔽 bash') : null,
              h('button', { className: 'rc2-zoomclose', title: '关闭（Esc）', onClick: () => setPanelSpot(null) }, '✕')),
            h('div', { className: 'rc2-panelspotbody' }, rows)))
      })()

      const spotOverlay = spot === null ? null : (() => {
        const kindLabel2 = spot.kind === 'command' ? '命令' : spot.kind === 'vuln' ? '漏洞' : '看板'
        const cmd = spot.kind === 'command' ? commands.find((c) => c.id === spot.id) : undefined
        const vul = spot.kind === 'vuln' ? vulns.find((v) => v.id === spot.id) : undefined
        const brd = spot.kind === 'board' ? boardEntries.find((e) => e.id === spot.id) : undefined
        const historyCommand = spot.kind === 'command' && cmd === undefined
        if (cmd === undefined && vul === undefined && brd === undefined && historyCommand === false) return null
        const title = cmd ? cmd.command : vul ? vul.title : brd ? (brd.text || '') : `命令 ${spot.id}`
        const kvs = []
        if (cmd) {
          kvs.push(['退出码', cmd.exitCode === null || cmd.exitCode === undefined ? '…' : String(cmd.exitCode)])
          kvs.push(['耗时', `${cmd.durationMs ?? '-'} ms`])
          kvs.push(['来源', cmd.source || '-'])
          if (cmd.startedAt) kvs.push(['时间', fmtTime(cmd.startedAt)])
          if (cmd.purpose) kvs.push(['目的', cmd.purpose])
          if (cmd.cwd) kvs.push(['cwd', cmd.cwd])
          if (Array.isArray(cmd.envKeys) && cmd.envKeys.length > 0) kvs.push(['env', cmd.envKeys.join(', ')])
          if (cmd.outputPath) kvs.push(['日志', cmd.outputPath])
          if (Array.isArray(cmd.nodeIds) && cmd.nodeIds.length > 0) kvs.push(['节点', cmd.nodeIds.join(', ')])
        }
        if (vul) {
          kvs.push(['等级', vul.severity || 'info'])
          kvs.push(['状态', vul.status || 'open'])
          if (vul.type) kvs.push(['类型', vul.type])
          if (vul.endpoint) kvs.push(['位置', vul.endpoint])
          if (vul.param) kvs.push(['参数', vul.param])
          if (vul.cve) kvs.push(['编号', vul.cve])
          if (vul.cvss) kvs.push(['CVSS', vul.cvss])
          if (vul.commandId) kvs.push(['命令', vul.commandId])
          if (vul.nodeId) kvs.push(['节点', vul.nodeId])
        }
        if (brd) {
          kvs.push(['作者', (brd.author && brd.author.name) || '-'])
          kvs.push(['类型', kindLabel(brd.kind)])
          if (brd.ts) kvs.push(['时间', fmtTime(new Date(brd.ts).toISOString())])
          const refs = brd.refs || {}
          for (const key of ['nodeIds', 'vulnIds', 'commandIds']) {
            if (Array.isArray(refs[key]) && refs[key].length > 0) kvs.push([key, refs[key].join(', ')])
          }
        }
        const related = []
        if (brd !== undefined) {
          const ids = Array.from(new Set(String(brd.text || '').match(/\bt[0-9a-z]{5,7}\b/g) || []))
          if (ids.length > 0) {
            for (const other of boardEntries) {
              if (other.id === brd.id) continue
              const text = String(other.text || '')
              if (!ids.some((id) => text.includes(id))) continue
              related.push(other)
              if (related.length >= 6) break
            }
          }
        }
        if (vul !== undefined) {
          for (const other of boardEntries) {
            const refs2 = other.refs || {}
            if (!Array.isArray(refs2.vulnIds) || !refs2.vulnIds.includes(vul.id)) continue
            related.push(other)
            if (related.length >= 6) break
          }
        }
        const bodySize = cmd === undefined ? 'normal' : 'command'
        return h('div', { className: 'rc2-spot', onClick: () => setSpot(null) },
          h('div', {
            className: 'rc2-spotcard',
            style: { minHeight: spot.kind === 'command' ? '56vh' : (spot.kind === 'vuln' ? '50vh' : '46vh') },
            onClick: (event) => event.stopPropagation(),
          },
            h('div', { className: 'rc2-spothead' },
              h('span', { className: 'rc2-kind' }, kindLabel2),
              h('span', { className: 'rc2-mono', style: { flex: '1 1 auto', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 13.5 } }, title),
              cmd ? h('button', {
                className: 'rc2-btn ghost',
                onClick: () => { try { void navigator.clipboard.writeText(cmd.command) } catch { /* 忽略 */ } },
              }, '复制命令') : null,
              vul ? h('button', {
                className: 'rc2-btn ghost',
                onClick: () => { setSpot(null); setSelection({ type: 'vuln', id: vul.id }) },
              }, '在图中定位') : null,
              brd ? h('button', {
                className: 'rc2-btn ghost',
                onClick: () => { setSpot(null); setDockOpen(true); setDockTab('board') },
              }, '打开看板') : null,
              h('button', { className: 'rc2-zoomclose', title: '关闭（Esc）', onClick: () => setSpot(null) }, '✕')),
            h('div', { className: 'rc2-spotbody' },
              h('div', { className: 'rc2-spotmeta' },
                kvs.map(([key, value], index) => h('span', { key: index, className: 'rc2-spotkv' },
                  `${key}: `, h('b', null, shortText(String(value), 90))))),
              bodySize === 'command'
                ? h('pre', null, spotBusy && spotText === '' ? `${cmd ? cmd.command : '读取命令…'}\n\n[读取输出…]` : `${cmd ? cmd.command : ''}\n\n${spotText}`)
                : null,
              vul ? h('pre', { className: 'rc2-spotlong' }, [
                vul.description ? vul.description : '（没有描述）',
                vul.payload ? `payload: ${vul.payload}` : '',
                vul.endpoint ? `endpoint: ${vul.endpoint}` : '',
              ].filter((line) => line !== '').join('\n\n')) : null,
              brd ? h('div', { className: `rc2-boardtext${mdOn ? ' rc2-md' : ''}`, style: { display: 'block', flex: '1 1 auto' } }, mdOrText(brd.text || '', brd.id, mdOn)) : null,
              brd ? (() => {
                const refs = brd.refs || {}
                const chips = []
                for (const nodeId of Array.isArray(refs.nodeIds) ? refs.nodeIds : []) {
                  const node = nodes.find((n) => n.id === nodeId)
                  chips.push(h('button', {
                    key: `sn-${nodeId}`, className: 'rc2-refchip',
                    onClick: () => { setSpot(null); setSelection({ type: 'node', id: nodeId }); focusNode(nodeId) },
                  }, `节点 ${node ? shortText(node.value, 22) : nodeId}`))
                }
                for (const vulnId of Array.isArray(refs.vulnIds) ? refs.vulnIds : []) {
                  chips.push(h('button', {
                    key: `sv-${vulnId}`, className: 'rc2-refchip',
                    onClick: () => { setSpot(null); setSelection({ type: 'vuln', id: vulnId }) },
                  }, `漏洞 ${vulnId}`))
                }
                for (const commandId of Array.isArray(refs.commandIds) ? refs.commandIds : []) {
                  chips.push(h('button', {
                    key: `sc-${commandId}`, className: 'rc2-refchip',
                    onClick: () => { setSpot(null); openSpot('command', commandId) },
                  }, `命令 ${commandId}`))
                }
                return chips.length === 0 ? null : h('div', { className: 'rc2-row', style: { flexWrap: 'wrap', marginTop: 4 } }, chips)
              })() : null,
              related.length === 0 ? null : h('div', { className: 'rc2-spotrel' },
                h('div', { className: 'rc2-meta', style: { marginBottom: 4 } }, brd === undefined ? '引用这条漏洞的看板条目' : '相关条目（按任务号串联）'),
                related.map((other) => h('button', {
                  key: other.id, className: 'rc2-relrow',
                  onClick: () => openSpot('board', other.id),
                },
                h('span', { className: 'rc2-kind k-' + other.kind }, kindLabel(other.kind)),
                h('span', { className: 'rc2-meta' }, (other.author && other.author.name) || '-'),
                h('span', { className: 'rc2-reltext' }, shortText(other.text || '', 90))))),
              brd && Array.isArray(brd.shots) && brd.shots.length > 0
                ? h('div', { className: 'rc2-spotmeta' }, brd.shots.map((shot) => h('a', {
                  key: shot, href: apiUrl(`/recon/asset?p=${encodeURIComponent(shot)}`), target: '_blank', rel: 'noreferrer',
                }, h('img', { src: apiUrl(`/recon/asset?p=${encodeURIComponent(shot)}`), style: { maxWidth: 320, borderRadius: 6, border: '1px solid var(--dsw-alias-border-l1)' } }))))
                : null)))
      })()

      const menuNode = menu === null ? null : nodes.find((n) => n.id === menu.id)
      const contextMenu = menu === null || menuNode === undefined ? null : h('div', {
        className: 'rc2-menubox',
        style: { left: Math.min(menu.x, (typeof window !== 'undefined' ? window.innerWidth : 1200) - 180), top: menu.y },
        onClick: (event) => event.stopPropagation(),
      },
      h('div', { className: 'rc2-meta', style: { padding: '3px 8px' } }, `${menuNode.kind}:${shortText(menuNode.value, 26)}`),
      h('button', { onClick: () => { focusNode(menuNode.id); setMenu(null) } }, '定位到节点'),
      h('button', { onClick: () => { setBoardTabFromMenu(menuNode); setMenu(null) } }, '写入看板'),
      h('button', {
        onClick: async () => {
          setMenu(null)
          await api({ op: 'squad.spawn', role: 'web', tier: 'deep', task: `针对节点 ${menuNode.kind}:${menuNode.value}（${menuNode.id}）做一轮漏洞探测，结论写进看板。`, engagement: engagement ? engagement.id : undefined })
          void refresh(engagement ? engagement.id : undefined)
        },
      }, '派猎手打这个节点'),
      h('button', {
        onClick: async () => {
          setMenu(null)
          await api({ op: 'archiveNode', nodeId: menuNode.id, mode: menuNode.archived ? 'restore' : 'archive', reason: '右键归档', engagement: engagement ? engagement.id : undefined })
          void refresh(engagement ? engagement.id : undefined)
        },
      }, menuNode.archived ? '恢复节点' : '归档节点'),
      h('button', {
        onClick: async () => {
          setMenu(null)
          if (!await uiConfirm(t('confirmDelete'), '节点会连同它的边与漏洞一起删除，不可恢复')) return
          await api({ op: 'deleteNode', nodeId: menuNode.id, engagement: engagement ? engagement.id : undefined })
          setSelection(null)
          void refresh(engagement ? engagement.id : undefined)
        },
      }, '删除节点'),
      h('button', { onClick: () => { void navigator.clipboard?.writeText(menuNode.value); setMenu(null) } }, '复制标识'))

      const setBoardTabFromMenu = (node) => {
        setDockTab('board')
        setDockOpen(true)
        setBoardKind('hypothesis')
        setBoardDraft(`关于 ${node.kind}:${node.value}（${node.id}）：`)
      }

      useEffect(() => {
        if (menu === null) return undefined
        const close = () => setMenu(null)
        document.addEventListener('click', close)
        document.addEventListener('contextmenu', close)
        return () => {
          document.removeEventListener('click', close)
          document.removeEventListener('contextmenu', close)
        }
      }, [menu])

      const dockSplitter = dockOpen ? h('div', {
        className: 'rc2-hsplitter dock-split',
        title: '拖动调整对话区高度',
        onMouseDown: (event) => {
          event.preventDefault()
          const startY = event.clientY
          const startHeight = dockHeight
          let height = startHeight
          const onMove = (moveEvent) => {
            height = Math.min(620, Math.max(140, startHeight - (moveEvent.clientY - startY)))
            setDockHeight(height)
          }
          const onUp = () => {
            window.removeEventListener('mousemove', onMove)
            window.removeEventListener('mouseup', onUp)
            try { window.localStorage.setItem('rc2.dockHeight', String(Math.round(height))) } catch { /* 忽略 */ }
          }
          window.addEventListener('mousemove', onMove)
          window.addEventListener('mouseup', onUp)
        },
      }) : null

      /* ── 队列条：可折叠，每项可改 / 删 / 插入发送 ── */
      const queueItemRow = (item, index) => h('div', { key: item.id, className: 'rc2-queueitem' },
        h('span', { className: 'rc2-queueidx' }, String(index + 1)),
        h('span', { className: 'rc2-queuetext', title: item.text }, item.text),
        h('span', { className: 'rc2-queuetarget' }, item.target === 'lead'
          ? '总指挥'
          : (item.target.startsWith('member:') ? item.target.slice(7) : roleNameOf(item.target.slice(5)))),
        h('button', {
          className: 'rc2-qbtn', title: '修改这条队列消息',
          onClick: async () => {
            const edited = await uiPrompt({ title: '修改队列消息', value: item.text, okText: '保存' })
            if (edited === null) return
            const next = edited.trim()
            if (next === '') return
            setChatQueue((prev) => prev.map((row) => (row.id === item.id ? { ...row, text: next } : row)))
          },
        }, '改'),
        h('button', {
          className: 'rc2-qbtn', title: '从队列删除',
          onClick: () => setChatQueue((prev) => prev.filter((row) => row.id !== item.id)),
        }, '删'),
        h('button', {
          className: 'rc2-qbtn go', title: '打断当前任务，立刻发送这条',
          onClick: () => void queueInterrupt(item),
        }, '插入发送'))

      const queueBar = dockTab === 'chat' && chatQueue.length > 0
        ? h('div', { className: 'rc2-queue' },
          h('div', { className: 'rc2-queuehead', onClick: () => setQueueOpen((v) => !v) },
            h('span', { className: 'rc2-queuebadge' }, `队列 ${chatQueue.length}`),
            h('span', { className: 'rc2-queuetip' }, targetBusy ? '当前轮结束后按顺序发送' : '空闲中，马上发送'),
            h('span', { className: 'rc2-queuetoggle' }, queueOpen ? '▾' : '▸')),
          queueOpen ? h('div', { className: 'rc2-queuelist' }, chatQueue.map(queueItemRow)) : null)
        : null

      const dock = h('div', { className: `rc2-dock${dockOpen ? ' expanded' : ''}`, style: dockOpen ? { height: dockHeight } : undefined },
        h('div', { className: 'rc2-dockhead' },
          h('div', { className: 'rc2-docktabs' },
            tabBtn('chat', t('dockChat'), null),
            tabBtn('brief', '总结汇报', null),
            tabBtn('board', t('dockBoard'), boardEntries.length),
            tabBtn('squad', t('dockSquad'), squadMembers.length),
            tabBtn('task', '任务', taskStats.total)),
          h('span', { className: 'rc2-spacer' }),
          dockTab === 'chat' ? h('select', {
            className: 'rc2-select rc2-chattarget',
            value: chatTarget,
            onChange: (event) => { setChatTarget(event.target.value); setMemberStream({ text: '', reasoning: '' }) },
          },
          h('option', { value: 'lead' }, '与总指挥对话'),
          squadMembers.filter((member) => member.role !== 'commander').length > 0
            ? h('optgroup', { label: '在岗队员' },
              /* 总指挥就是 lead 本尊，不在列表里重复出现一次 */
              squadMembers.filter((member) => member.role !== 'commander').map((member) => h('option', { key: member.key, value: `member:${member.key}` },
                `${member.name}（${roleNameOf(member.role)}${member.status === 'running' ? ' · 在跑' : ''}）`)))
            : null,
          h('optgroup', { label: '按角色对话（不在岗会自动招募）' },
            roleList.filter((role) => role.core !== true && role.id !== 'commander' && role.id !== 'staff')
              .map((role) => h('option', { key: role.id, value: `role:${role.id}` }, roleNameOf(role.id))))) : null,
          dockTab === 'chat' ? h('span', { className: 'rc2-meta' }, chatTarget === 'lead' && chat.busy ? `${t('thinking')}…` : '') : null,
          h('button', {
            className: 'rc2-zoom', style: { opacity: 1 }, title: '放大到中央',
            onClick: () => setPanelSpot('chat'),
          }, '⤢'),
          dockTab === 'squad' ? h('span', { className: 'rc2-meta' }, `${t('runningAgents')} ${squadRunning}`) : null,
          dockTab === 'squad' ? h('button', {
            className: 'rc2-btn ghost',
            onClick: async () => {
              await api({ op: 'squad.stopAll', engagement: engagement ? engagement.id : undefined })
              void refresh(engagement ? engagement.id : undefined)
            },
          }, '全部停止') : null,
          dockTab === 'squad' ? h('button', {
            className: 'rc2-btn ghost',
            onClick: async () => {
              await api({ op: 'squad.prune', ttlMs: 0, engagement: engagement ? engagement.id : undefined })
              void refresh(engagement ? engagement.id : undefined)
            },
          }, '回收空闲') : null,
          ...(dockTab === 'chat' ? chatControls : []),
          h('button', { className: 'rc2-btn ghost', onClick: () => setDockOpen((v) => !v) }, dockOpen ? '▾' : '▴')),
        dockTab === 'chat' && dockOpen && showThinking
          ? h('div', {
            className: 'rc2-thinkrow',
            title: showThinking
              ? (reasoningLine || chat.streaming.text)
              : t('thinkingCollapsed'),
          },
          h('span', { className: 'rc2-thinklabel' }, '主 agent 输出'),
          h('span', { className: 'rc2-thinkpeek' }, reasoningLine || chat.streaming.text))
          : null,
        dockOpen ? dockBody : null,
        queueBar,
        dockComposer)

      /* 总结汇报需要一屏看全：切过去时把驾驶舱拉到够高（只在偏矮时提升，不改用户手动拉的高度） */
      useEffect(() => {
        if (dockTab !== 'brief') return
        setDockHeight((height) => (height >= 430 ? height : 430))
        const node = briefRef.current
        if (node !== null) node.scrollTop = 0
        /* 已经显示过消息就保留当前视图；首次进入时优先恢复服务端历史。 */
        if (briefMsgs.length > 0) return
        let cancelled = false
        void (async () => {
          const res = await api({ op: 'brief.history', engagement: engagement ? engagement.id : undefined })
          if (cancelled) return
          const rows = res && res.ok && Array.isArray(res.messages) ? res.messages : []
          setBriefMsgs(rows.length > 0 ? rows : [{ id: `brief-report-${Date.now()}`, role: 'bot', text: briefReport }])
        })()
        return () => { cancelled = true }
      }, [dockTab, engagement === null ? '' : engagement.id])

      useEffect(() => {
        if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight
      }, [chat.messages.length, chat.streaming.text, chat.streaming.reasoning, toolLines.length, dockOpen])

      /* ── 空态 ── */
      if (loading) {
        return h('div', { className: rootClass, 'data-accent': accent }, topbar, h('div', { className: 'rc2-center' }, t('loading')))
      }
      if (engagement === null) {
        return h('div', { className: rootClass, 'data-accent': accent },
          topbar,
          error !== null ? h('div', { className: 'rc2-err' }, error) : null,
          contextMenu,
          h('div', { className: 'rc2-empty' },
            h('h3', null, t('empty')),
            h('p', null, t('emptyHint')),
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn on',
                onClick: async () => {
                  const name = await uiPrompt({ title: t('newEngagementName'), value: '', okText: '创建' })
                  if (name === null || name.trim() === '') return
                  const res = await api({ op: 'create', name: name.trim() })
                  if (res && res.ok) { inited.current = false; positions.current.clear(); void refresh(res.activeId) }
                },
              }, t('newEngagement')),
              h('button', { className: 'rc2-btn', onClick: () => void refresh() }, t('refresh')))),
          dock,
          dockSplitter,
          dialogNode,
        panelSpotOverlay,
        spotOverlay,
        settingsOpen ? h(SettingsPanel, {
            t,
            onClose: () => setSettingsOpen(false),
            onSaved: () => void refresh(engagement ? engagement.id : undefined),
          }) : null)
      }

      return h('div', { className: rootClass, 'data-accent': accent },
        uiCfg.scanlines !== false ? h('div', { className: 'rc2-scan' }) : null,
        topbar,
        error !== null ? h('div', { className: 'rc2-err' }, error) : null,
        h('div', { className: 'rc2-main' }, commandFeed, splitterBar,
          h('div', { className: 'rc2-canvas-host' }, canvas, browserStack), splitterRight, vulnFeed),
        dockSplitter,
        contextMenu,
        dialogNode,
        dock,
        panelSpotOverlay,
        spotOverlay,
        settingsOpen ? h(SettingsPanel, {
          t,
          onClose: () => setSettingsOpen(false),
          onSaved: () => void refresh(engagement ? engagement.id : undefined),
        }) : null)
    }

    /* ───────────────────────── 控制台（配置） ───────────────────────── */
    const KEY_FIELDS = [
      'github', 'fofa', 'fofaEmail', 'shodan', 'virustotal', 'hunter', 'quake',
      'censysId', 'censysSecret', 'securitytrails', 'hunterhow', 'daybreak', 'gitlab', 'telegram',
    ]
    const ACCENTS = ['cyan', 'violet', 'lime', 'amber']

    function setIn(object, path, value) {
      const keys = path.split('.')
      const next = Array.isArray(object) ? object.slice() : { ...object }
      let cursor = next
      for (let i = 0; i < keys.length - 1; i += 1) {
        const key = keys[i]
        const child = cursor[key]
        cursor[key] = Array.isArray(child) ? child.slice() : { ...(child && typeof child === 'object' ? child : {}) }
        cursor = cursor[key]
      }
      cursor[keys[keys.length - 1]] = value
      return next
    }

    function SettingsPanel(props) {
      const t = props.t
      const [tab, setTab] = useState('models')
      const [cfg, setCfg] = useState(null)
      const [keys, setKeys] = useState({})
      const [presence, setPresence] = useState({})
      const [skills, setSkills] = useState([])
      const [mcpStatus, setMcpStatus] = useState(null)
      const [autoCfg, setAutoCfg] = useState(null)
      const [autoStatus, setAutoStatus] = useState(null)
      const [meetCfg, setMeetCfg] = useState({ reviewMinutes: 5, maxRounds: 3 })
      const [handCfg, setHandCfg] = useState({ enabled: true, timeoutMs: 90000, keepSkill: true })
      const [modelChoices, setModelChoices] = useState({})
      const [manualModelRows, setManualModelRows] = useState({})
      const [modelActionStatus, setModelActionStatus] = useState({})
      const [boardCfg, setBoardCfg] = useState(() => {
        try {
          const saved = JSON.parse(window.localStorage.getItem('rc2.boardCfg') || 'null')
          if (saved && typeof saved === 'object') return { limit: 100, mergeCount: 50, mergeMode: 'deterministic', mergeModel: 'fast', ...saved }
        } catch { /* 忽略损坏的本地缓存 */ }
        return { limit: 100, mergeCount: 50, mergeMode: 'deterministic', mergeModel: 'fast' }
      })
      const [traceCfg, setTraceCfg] = useState({ limit: 500 })
      const [traceMode, setTraceMode] = useState('500')
      const [rolesEdit, setRolesEdit] = useState(null)
      const [coreEdit, setCoreEdit] = useState(null)
      const [recruitTier, setRecruitTier] = useState('auto')
      const [coreSupported, setCoreSupported] = useState(false)
      const [autoRoles, setAutoRoles] = useState([])
      const [saving, setSaving] = useState(false)
      const [notice, setNotice] = useState('')

      useEffect(() => {
        let cancelled = false
        ;(async () => {
          const [conf, skillRes, mcpRes, autoRes] = await Promise.all([
            api({ op: 'config.get' }),
            api({ op: 'skills' }),
            api({ op: 'mcp.list' }),
            api({ op: 'automation.get' }),
          ])
          if (autoRes && autoRes.ok) { setAutoCfg(autoRes.config); setAutoRoles(autoRes.roles || []); setAutoStatus(autoRes.status || null) }
          const roleRes = await api({ op: 'roles.get' })
          if (roleRes && roleRes.ok) {
            const supported = Array.isArray(roleRes.core)
            const rows = roleRes.roles || []
            const legacyCore = rows.filter((role) => role.id === 'commander' || role.id === 'staff')
            /* 旧宿主不返回 core：从 roles 里把总指挥/参谋提出来当常设席位显示；
               保存时再合并回 roles，避免重载前编辑丢失。 */
            setCoreSupported(supported)
            setCoreEdit(supported ? roleRes.core : legacyCore)
            setRolesEdit(supported ? rows.filter((role) => role.id !== 'commander' && role.id !== 'staff') : rows)
            setRecruitTier(['auto', ...TIERS].includes(roleRes.recruitTier) ? roleRes.recruitTier : 'auto')
          }
          if (cancelled) return
          if (conf && conf.ok) {
            if (conf.config) conf.config.memory = normalizeMemoryList(conf.config.memory)
            setCfg(conf.config)
            setPresence(conf.keys || {})
            if (conf.config && conf.config.meeting) setMeetCfg({ ...{ reviewMinutes: 5, maxRounds: 3 }, ...conf.config.meeting })
            if (conf.config && conf.config.board) setBoardCfg((prev) => ({ ...prev, ...conf.config.board }))
            if (conf.config && conf.config.handover) setHandCfg({ ...{ enabled: true, timeoutMs: 90000, keepSkill: true }, ...conf.config.handover })
            if (conf.config && conf.config.trace) {
              const limit = [500, 1000, 2000].includes(Number(conf.config.trace.limit)) ? Number(conf.config.trace.limit) : Math.max(100, Math.min(5000, Number(conf.config.trace.limit) || 500))
              setTraceCfg({ limit })
              setTraceMode([500, 1000, 2000].includes(limit) ? String(limit) : 'custom')
            }
          }
          if (skillRes && skillRes.ok) setSkills(skillRes.items || [])
          if (mcpRes && mcpRes.ok) setMcpStatus(mcpRes)
        })()
        return () => { cancelled = true }
      }, [])

      useEffect(() => {
        try { window.localStorage.setItem('rc2.boardCfg', JSON.stringify(boardCfg)) } catch { /* 忽略 */ }
      }, [boardCfg])

      const save = useCallback(async () => {
        if (cfg === null) return
        setSaving(true)
        setNotice(t('saving'))
        const patch = {
          models: cfg.models,
          role: cfg.role,
          prompt: cfg.prompt,
          memory: cfg.memory,
          skills: cfg.skills,
          mcp: cfg.mcp,
          ui: cfg.ui,
          chat: cfg.chat,
          env: typeof cfg.env === 'string' ? String(cfg.env).split('\n') : cfg.env,
          ...(autoCfg !== null ? { automation: autoCfg } : {}),
          meeting: meetCfg,
          board: boardCfg,
          trace: traceCfg,
          handover: handCfg,
        }
        const keyPatch = {}
        for (const [field, value] of Object.entries(keys)) {
          if (typeof value === 'string' && value !== '') keyPatch[field] = value
        }
        if (Object.keys(keyPatch).length > 0) patch.keys = keyPatch
        if (Array.isArray(rolesEdit)) {
          const core = Array.isArray(coreEdit) ? coreEdit : []
          const coreIds = new Set(core.map((role) => role.id))
          const payloadRoles = coreSupported
            ? rolesEdit
            : [...core, ...rolesEdit.filter((role) => !coreIds.has(role.id))]
          const roleSave = await api({
            op: 'roles.set',
            roles: payloadRoles,
            recruitTier,
            ...(coreSupported && Array.isArray(coreEdit) ? { core: coreEdit } : {}),
          })
          if (roleSave && roleSave.ok && ['auto', ...TIERS].includes(roleSave.recruitTier)) setRecruitTier(roleSave.recruitTier)
        }
        const res = await api({ op: 'config.set', patch })
        setSaving(false)
        if (res && res.ok) {
          setNotice(t('saved'))
          setKeys({})
          const [conf, mcpRes, autoRes2] = await Promise.all([api({ op: 'config.get' }), api({ op: 'mcp.list' }), api({ op: 'automation.get' })])
          if (conf && conf.ok) {
            if (conf.config) conf.config.memory = normalizeMemoryList(conf.config.memory)
            setCfg(conf.config)
            setPresence(conf.keys || {})
            if (conf.config && conf.config.meeting) setMeetCfg({ ...{ reviewMinutes: 5, maxRounds: 3 }, ...conf.config.meeting })
            if (conf.config && conf.config.board) setBoardCfg((prev) => ({ ...prev, ...conf.config.board }))
            if (conf.config && conf.config.trace) {
              const limit = [500, 1000, 2000].includes(Number(conf.config.trace.limit)) ? Number(conf.config.trace.limit) : Math.max(100, Math.min(5000, Number(conf.config.trace.limit) || 500))
              setTraceCfg({ limit })
              setTraceMode([500, 1000, 2000].includes(limit) ? String(limit) : 'custom')
            }
            if (conf.config && conf.config.handover) setHandCfg({ ...{ enabled: true, timeoutMs: 90000, keepSkill: true }, ...conf.config.handover })
          }
          if (mcpRes && mcpRes.ok) setMcpStatus(mcpRes)
          if (autoRes2 && autoRes2.ok) { setAutoCfg(autoRes2.config); setAutoRoles(autoRes2.roles || []); setAutoStatus(autoRes2.status || null) }
          props.onSaved && props.onSaved()
        } else {
          setNotice(res && res.error ? res.error : t('errorLabel'))
        }
      }, [autoCfg, boardCfg, cfg, coreEdit, coreSupported, handCfg, keys, meetCfg, props, recruitTier, rolesEdit, t, traceCfg])

      const body = (() => {
        if (cfg === null) return h('div', { className: 'rc2-center' }, t('loading'))

        if (tab === 'models') {
          const customRows = cfg.models && Array.isArray(cfg.models.custom) ? cfg.models.custom : []
          const tierChoices = customRows
            .filter((row) => asTextLike(row.model) !== '')
            .map((row) => ({
              value: JSON.stringify([row.provider, row.model]),
              label: row.name || row.model,
              provider: row.provider,
              model: row.model,
              reasoning: row.reasoning || '',
            }))
          const updateCustom = (index, path, value) => {
            const current = customRows[index]
            const next = customRows.map((row, rowIndex) => (rowIndex === index ? { ...row, [path]: value } : row))
            let nextCfg = setIn(cfg, 'models.custom', next)
            /* 改模型 id / 默认思考深度时，同步引用这个 provider 的档位，避免档位指向旧 model */
            if (path === 'model' || path === 'reasoning') {
              for (const tier of TIERS) {
                const row = (cfg.models && cfg.models[tier]) || {}
                if (row.provider === current.provider) nextCfg = setIn(nextCfg, `models.${tier}.${path}`, value)
              }
            }
            setCfg(nextCfg)
          }
          const noteModelAction = (row, text) => {
            setModelActionStatus((prev) => ({ ...prev, [row.id]: text }))
          }
          const discoverCustomModels = async (index) => {
            const row = customRows[index]
            if (!row) return
            noteModelAction(row, '正在获取模型…')
            const res = await api({
              op: 'customModels.discover',
              baseUrl: row.baseUrl,
              apiKey: row.apiKey,
              keyRef: row.keyRef,
              protocol: row.protocol,
              provider: row.provider,
            })
            if (!res || !res.ok) {
              const msg = res && res.error ? res.error : '未知错误'
              noteModelAction(row, `获取失败：${msg}`)
              void uiAlert('获取模型失败', msg)
              return
            }
            const models = Array.isArray(res.models) ? res.models : []
            setModelChoices((prev) => ({ ...prev, [row.id]: models }))
            setManualModelRows((prev) => ({ ...prev, [row.id]: false }))
            if ((!row.model || row.model.trim() === '') && models.length > 0) updateCustom(index, 'model', models[0].id)
            noteModelAction(row, models.length === 0 ? '没有获取到模型' : `已获取 ${models.length} 个模型：${models.map((item) => item.id).join(', ')}`)
            if (models.length === 0) void uiAlert('没有获取到模型', '端点没有返回 data/models 列表')
          }
          const testCustomModel = async (index) => {
            const row = customRows[index]
            if (!row) return
            noteModelAction(row, '正在发送测试对话…')
            const res = await api({
              op: 'customModels.test',
              baseUrl: row.baseUrl,
              apiKey: row.apiKey,
              protocol: row.protocol,
              model: row.model,
              provider: row.provider,
            })
            if (!res || !res.ok) {
              const msg = res && res.error ? res.error : '未知错误'
              noteModelAction(row, `测试失败：${msg}`)
              void uiAlert('模型测试失败', msg)
              return
            }
            noteModelAction(row, `测试成功：模型回复「${res.reply}」`)
            void uiAlert('模型测试成功', `模型 ${res.model} 已回复：${res.reply}`)
          }
          const addCustom = () => {
            const id = `cm_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`
            const row = {
              id,
              name: `模型 ${id.slice(-4)}`,
              provider: `venery-${id}`,
              keyRef: `VENERY_MODEL_${id.replace(/[^a-z0-9]/g, '_').toUpperCase()}`,
              baseUrl: '',
              model: '',
              reasoning: 'medium',
              protocol: 'openai-completions',
              apiKey: '',
              hasKey: false,
              createdAt: new Date().toISOString(),
            }
            setCfg(setIn(cfg, 'models.custom', [...customRows, row]))
          }
          const removeCustom = (index) => {
            const removed = customRows[index]
            let next = setIn(cfg, 'models.custom', customRows.filter((_, rowIndex) => rowIndex !== index))
            for (const tier of TIERS) {
              const row = (cfg.models && cfg.models[tier]) || {}
              if (row.provider === removed.provider) {
                next = setIn(setIn(setIn(next, `models.${tier}.provider`, ''), `models.${tier}.model`, ''), `models.${tier}.reasoning`, '')
              }
            }
            setCfg(next)
          }
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('modelHint')),
            TIERS.map((tier) => {
              const row = (cfg.models && cfg.models[tier]) || { provider: '', model: '', reasoning: '' }
              const currentValue = row.provider && row.model ? JSON.stringify([row.provider, row.model]) : ''
              const currentKnown = tierChoices.some((item) => item.value === currentValue)
              return h('div', { key: tier, className: 'rc2-field', style: { marginBottom: 12 } },
                h('label', null, `${t('model')} · ${TIER_LABEL[tier]}`),
                h('select', {
                  value: currentValue,
                  onChange: (event) => {
                    if (event.target.value === '') {
                      setCfg(setIn(setIn(setIn(cfg, `models.${tier}.provider`, ''), `models.${tier}.model`, ''), `models.${tier}.reasoning`, ''))
                      return
                    }
                    let picked
                    try { picked = JSON.parse(event.target.value) } catch { return }
                    const provider = asTextLike(picked[0])
                    const model = asTextLike(picked[1])
                    const choice = tierChoices.find((item) => item.provider === provider && item.model === model)
                    let next = setIn(setIn(cfg, `models.${tier}.provider`, provider), `models.${tier}.model`, model)
                    next = setIn(next, `models.${tier}.reasoning`, choice !== undefined ? (choice.reasoning || '') : '')
                    setCfg(next)
                  },
                },
                h('option', { value: '' }, '— 跟随 DSH（不单独配置）'),
                ...tierChoices.map((item) => h('option', { key: item.value, value: item.value }, item.label)),
                currentValue !== '' && !currentKnown
                  ? h('option', { value: currentValue }, `${row.model} · ${row.provider}`) : null))
            }),
            h('div', { className: 'rc2-sect' }, t('customModels')),
            h('div', { className: 'rc2-note' }, t('customModelsHint')),
            customRows.map((row, index) => h('div', {
              key: row.id,
              style: { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 6, padding: 8, marginBottom: 8 },
            },
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, '名称'),
                h('input', { value: row.name || '', onChange: (event) => updateCustom(index, 'name', event.target.value) })),
              h('div', { className: 'rc2-field' }, h('label', null, t('baseUrl')),
                h('input', {
                  value: row.baseUrl || '',
                  placeholder: 'https://api.example.com/v1',
                  onChange: (event) => updateCustom(index, 'baseUrl', event.target.value),
                })),
              h('div', { className: 'rc2-field' }, h('label', null, t('apiKey')),
                h('input', {
                  type: 'password',
                  value: row.apiKey || '',
                  placeholder: row.hasKey ? t('savedKey') : t('needKey'),
                  onChange: (event) => updateCustom(index, 'apiKey', event.target.value),
                }))),
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, t('protocol')),
                h('select', {
                  value: row.protocol === 'openai-responses' || !MODEL_PROTOCOLS.some((item) => item.id === row.protocol) ? 'openai-completions' : row.protocol,
                  onChange: (event) => updateCustom(index, 'protocol', event.target.value),
                }, MODEL_PROTOCOLS.map((item) => h('option', { key: item.id, value: item.id }, item.label)))),
              h('div', { className: 'rc2-field' }, h('label', null, t('modelId')),
                (manualModelRows[row.id] === true || (modelChoices[row.id] || []).length === 0)
                  ? h('input', {
                    value: row.model || '',
                    placeholder: 'gpt-4o-mini',
                    onChange: (event) => updateCustom(index, 'model', event.target.value),
                  })
                  : h('select', {
                    value: (modelChoices[row.id] || []).some((item) => item.id === row.model) ? row.model : '',
                    onChange: (event) => {
                      if (event.target.value === '__manual__') {
                        setManualModelRows((prev) => ({ ...prev, [row.id]: true }))
                        updateCustom(index, 'model', '')
                        return
                      }
                      updateCustom(index, 'model', event.target.value)
                    },
                  },
                  h('option', { value: '' }, '— 选择模型 —'),
                  (modelChoices[row.id] || []).map((item) => h('option', { key: item.id, value: item.id }, item.name || item.id)),
                  h('option', { value: '__manual__' }, '手动输入…'))),
              h('div', { className: 'rc2-field' }, h('label', null, t('thinkingDepth')),
                h('select', {
                  value: THINKING_LEVELS.includes(row.reasoning) ? row.reasoning : 'medium',
                  onChange: (event) => updateCustom(index, 'reasoning', event.target.value),
                }, THINKING_LEVELS.map((level) => h('option', { key: level, value: level }, THINKING_LABEL[level]))))),
            h('div', { className: 'rc2-row', style: { marginTop: 6 } },
              h('button', {
                className: 'rc2-btn ghost',
                title: '用当前 Base URL、API Key、协议请求 /models',
                disabled: String(modelActionStatus[row.id] || '').startsWith('正在'),
                onClick: () => { void discoverCustomModels(index) },
              }, '获取模型'),
              h('button', {
                className: 'rc2-btn ghost',
                title: '发送一句话给模型，只有模型回复“测试成功”才算通过',
                disabled: String(modelActionStatus[row.id] || '').startsWith('正在'),
                onClick: () => { void testCustomModel(index) },
              }, '测试模型'),
              h('button', {
                className: 'rc2-btn ghost',
                title: '保存当前模型配置到 DSH',
                onClick: () => { void save() },
              }, '保存模型')),
            h('div', { className: 'rc2-meta', style: { marginTop: 4, minHeight: 18 } }, modelActionStatus[row.id] || ''),
            h('div', { className: 'rc2-row' },
              h('span', { className: 'rc2-meta' }, `${t('route')}: ${row.provider || '—'}`),
              h('span', { className: 'rc2-meta' }, row.hasKey ? t('keySaved') : t('keyMissing')),
              h('span', { className: 'rc2-spacer' }),
              h('button', { className: 'rc2-btn danger', onClick: () => removeCustom(index) }, t('remove'))))),
            h('div', { className: 'rc2-row' },
              h('button', { className: 'rc2-btn on', onClick: addCustom }, t('addModel'))))
        }

        if (tab === 'keys') {
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('keysHint')),
            h('div', { className: 'rc2-grid2' },
              KEY_FIELDS.map((field) => h('div', { key: field, className: 'rc2-field' },
                h('label', null, field + (presence[field] ? ' · ✓' : '')),
                h('div', { className: 'rc2-row', style: { margin: 0 } },
                  h('input', {
                    type: 'password',
                    value: keys[field] || '',
                    placeholder: presence[field] ? '••••••••' : '—',
                    onChange: (event) => setKeys((prev) => ({ ...prev, [field]: event.target.value })),
                    style: { flex: '1 1 auto' },
                  }),
                  h('button', {
                    className: 'rc2-btn ghost',
                    onClick: async () => {
                      await api({ op: 'config.set', patch: { keys: { [field]: '' } } })
                      setPresence((prev) => ({ ...prev, [field]: false }))
                      setKeys((prev) => { const next = { ...prev }; delete next[field]; return next })
                    },
                  }, '⌫'))))),
            h('div', { className: 'rc2-field' },
              h('label', null, t('envHint')),
              h('textarea', {
                value: Array.isArray(cfg.env) ? cfg.env.join('\n') : String(cfg.env || ''),
                onChange: (event) => setCfg(setIn(cfg, 'env', event.target.value)),
              })))
        }

        if (tab === 'memory') {
          const memory = Array.isArray(cfg.memory) ? cfg.memory : []
          return h('div', null,
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn on',
                onClick: () => setCfg(setIn(cfg, 'memory', [...memory, { id: `m${Date.now()}`, title: '新记忆', content: '' }])),
              }, t('add'))),
            memory.length === 0 ? h('div', { className: 'rc2-note' }, t('memoryEmpty')) : null,
            memory.map((item, index) => h('div', { key: item.id || index, style: { marginBottom: 10 } },
              h('div', { className: 'rc2-row' },
                h('input', {
                  value: item.title || '',
                  onChange: (event) => setCfg(setIn(cfg, `memory.${index}.title`, event.target.value)),
                  style: { flex: '0 0 220px', borderRadius: 4, padding: '5px 7px', background: 'var(--dsw-alias-bg-layer-1)', border: '1px solid var(--dsw-alias-border-l1)', color: 'inherit' },
                }),
                h('button', {
                  className: 'rc2-btn danger',
                  onClick: () => setCfg(setIn(cfg, 'memory', memory.filter((_, i) => i !== index))),
                }, t('remove'))),
              h('textarea', {
                value: item.content || '',
                style: { width: '100%', marginTop: 4, minHeight: 54, fontFamily: 'ui-monospace,Menlo,monospace', fontSize: 11.5, borderRadius: 4, padding: '6px 8px', background: 'var(--dsw-alias-bg-layer-1)', border: '1px solid var(--dsw-alias-border-l1)', color: 'inherit' },
                onChange: (event) => setCfg(setIn(cfg, `memory.${index}.content`, event.target.value)),
              }))))
        }

        if (tab === 'skills') {
          const enabled = (cfg.skills && Array.isArray(cfg.skills.enabled)) ? cfg.skills.enabled : []
          return h('div', null,
            h('div', { className: 'rc2-note' }, '勾选的技能名会写进驾驶舱 AI 的系统提示；技能本体由 Harness skill 体系提供。'),
            skills.length === 0 ? h('div', { className: 'rc2-note' }, t('noSkills')) : null,
            skills.map((skill) => h('label', {
              key: skill.name,
              className: 'rc2-row',
              style: { cursor: 'pointer', alignItems: 'flex-start', padding: '4px 0', borderBottom: '1px solid var(--dsw-alias-border-l1)' },
            },
            h('input', {
              type: 'checkbox',
              checked: enabled.includes(skill.name),
              onChange: (event) => {
                const next = event.target.checked ? [...enabled, skill.name] : enabled.filter((name) => name !== skill.name)
                setCfg(setIn(cfg, 'skills.enabled', next))
              },
              style: { marginTop: 3 },
            }),
            h('div', null,
              h('div', { style: { fontSize: 12, fontWeight: 600 } }, skill.name),
              h('div', { className: 'rc2-note', style: { margin: '2px 0 0' } }, skill.description || '')))))
        }

        if (tab === 'mcp') {
          const rows = Array.isArray(cfg.mcp) ? cfg.mcp : []
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('mcpHint')),
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn on',
                onClick: () => setCfg(setIn(cfg, 'mcp', [...rows, { name: `server${rows.length + 1}`, transport: 'stdio', command: 'npx', args: [], url: '', headers: {}, env: {}, enabled: true }])),
              }, t('add'))),
            rows.map((row, index) => h('div', {
              key: index,
              style: { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 6, padding: 8, marginBottom: 8 },
            },
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, 'name'),
                h('input', { value: row.name || '', onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.name`, event.target.value)) })),
              h('div', { className: 'rc2-field' }, h('label', null, 'transport'),
                h('select', {
                  value: row.transport || 'stdio',
                  onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.transport`, event.target.value)),
                }, h('option', { value: 'stdio' }, 'stdio'), h('option', { value: 'streamable-http' }, 'streamable-http'))),
              h('div', { className: 'rc2-field' }, h('label', null, 'enabled'),
                h('select', {
                  value: row.enabled === false ? 'no' : 'yes',
                  onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.enabled`, event.target.value === 'yes')),
                }, h('option', { value: 'yes' }, 'yes'), h('option', { value: 'no' }, 'no')))),
            (row.transport === 'streamable-http')
              ? h('div', { className: 'rc2-field' }, h('label', null, 'url'),
                h('input', { value: row.url || '', onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.url`, event.target.value)) }))
              : h('div', null,
                h('div', { className: 'rc2-field' }, h('label', null, 'command'),
                  h('input', { value: row.command || '', onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.command`, event.target.value)) })),
                h('div', { className: 'rc2-field' }, h('label', null, 'args（逗号分隔）'),
                  h('input', {
                    value: Array.isArray(row.args) ? row.args.join(', ') : String(row.args || ''),
                    onChange: (event) => setCfg(setIn(cfg, `mcp.${index}.args`, event.target.value.split(',').map((s) => s.trim()).filter(Boolean))),
                  }))),
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn danger',
                onClick: () => setCfg(setIn(cfg, 'mcp', rows.filter((_, i) => i !== index))),
              }, t('remove'))))),
            mcpStatus !== null ? h('div', null,
              h('div', { className: 'rc2-sect' }, t('mcpStatus')),
              h('div', { className: 'rc2-pre' }, JSON.stringify(mcpStatus.servers || mcpStatus.bindings || mcpStatus, null, 2))) : null)
        }

      /* MCP 文本 <-> 数组：一行一个 name = 命令/URL，复杂配置可写成 JSON。 */
      const mcpTextOf = (role) => (Array.isArray(role.mcp) ? role.mcp : []).map(mcpLineOf).join('\n')
      const parseMcpText = parseMcpLines

        if (tab === 'roles') {
          if (rolesEdit === null) return h('div', { className: 'rc2-center' }, t('loading'))
          const update = (index, path, value) => {
            const next = rolesEdit.slice()
            const row = { ...next[index] }
            if (path === 'skills') {
              row.skills = String(value).split(',').map((x) => x.trim()).filter(Boolean)
            } else {
              row[path] = value
            }
            next[index] = row
            setRolesEdit(next)
          }
          const updateCore = (index, path, value) => {
            const next = (coreEdit || []).slice()
            const row = { ...next[index] }
            if (path === 'skills') {
              row.skills = String(value).split(',').map((x) => x.trim()).filter(Boolean)
            } else {
              row[path] = value
            }
            next[index] = row
            setCoreEdit(next)
          }
          const coreCard = (role, index) => h('div', {
            key: role.id,
            style: { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 6, padding: 8, marginBottom: 8 },
          },
          h('div', { className: 'rc2-line' },
            h('span', { className: 'rc2-kind' }, role.id === 'commander' ? '总指挥' : '参谋'),
            h('span', { className: 'rc2-meta' }, '常设席位 · 每靶标各一个 · 不可召唤/回收'),
            h('span', { className: 'rc2-spacer' }),
            h('span', { className: 'rc2-meta' }, role.id === 'commander' ? '最高指挥' : '向总指挥汇报')),
          h('div', { className: 'rc2-grid3' },
            h('div', { className: 'rc2-field' }, h('label', null, 'ID'),
              h('input', { value: role.id, readOnly: true, style: { opacity: 0.7 } })),
            h('div', { className: 'rc2-field' }, h('label', null, '名称'),
              h('input', { value: role.name || '', onChange: (e) => updateCore(index, 'name', e.target.value) })),
            h('div', { className: 'rc2-field' }, h('label', null, t('ruleTier')),
              h('select', { value: role.tier || 'dsh', onChange: (e) => updateCore(index, 'tier', e.target.value) },
                MODEL_CHOICES.map((tier) => h('option', { key: tier, value: tier }, TIER_LABEL[tier]))))),
          h('div', { className: 'rc2-field' }, h('label', null, '技能（逗号分隔）'),
            h('input', { value: (role.skills || []).join(', '), placeholder: 'nuclei-scan, web-fingerprint', onChange: (e) => updateCore(index, 'skills', e.target.value) })),
          h('div', { className: 'rc2-field' }, h('label', null, '提示词'),
            h('textarea', { style: { minHeight: 84 }, value: role.prompt || '', onChange: (e) => updateCore(index, 'prompt', e.target.value) })),
          h('div', { className: 'rc2-field' }, h('label', null, '专属 MCP（一行一个：name = command args 或 name = https://host/mcp；留空=只用本机命令）'),
            h('textarea', {
              style: { minHeight: 54, fontFamily: 'var(--dsw-font-mono, monospace)', fontSize: 11 },
              value: mcpTextOf(role),
              placeholder: 'nuclei-mcp = python3 /opt/mcp/nuclei_server.py',
              onChange: (e) => updateCore(index, 'mcp', parseMcpText(e.target.value)),
            })))
          const memberRows = rolesEdit.map((role, index) => ({ role, index }))
            .filter(({ role }) => role.id !== 'commander' && role.id !== 'staff')
          const reportTargetsOf = (role) => [...(Array.isArray(coreEdit) ? coreEdit : []), ...rolesEdit]
            .filter((row) => row.id !== role.id)
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('rolesHint')),
            h('div', { className: 'rc2-sect' }, t('commonPrompt')),
            h('div', { className: 'rc2-note' }, t('commonHint')),
            h('div', { className: 'rc2-field' },
              h('textarea', {
                style: { minHeight: 96 },
                value: (cfg.prompt && cfg.prompt.common) || '',
                placeholder: t('commonPlaceholder'),
                onChange: (event) => setCfg(setIn(cfg, 'prompt.common', event.target.value)),
              })),
            h('div', { className: 'rc2-sect' }, '新队员模型策略'),
            h('div', { className: 'rc2-field' },
              h('label', null, '总指挥招募新队员时的模型档位'),
              h('select', {
                value: recruitTier,
                onChange: (event) => setRecruitTier(event.target.value),
              },
              h('option', { value: 'auto' }, '由总指挥决定（auto）'),
              h('option', { value: 'deep' }, '深度 / Deep'),
              h('option', { value: 'fast' }, 'Flash / 快速'),
              h('option', { value: 'vision' }, '视觉 / Vision'))),
            h('div', { className: 'rc2-note' }, '固定档位时，手动派发、自动化、会议和小组扩员创建的新队员都会强制使用该档位；auto 时由总指挥在 spawn.tier 中决定，未指定则使用角色默认档位。'),
            h('div', { className: 'rc2-sect' }, t('coreSeats')),
            h('div', { className: 'rc2-note' }, t('coreSeatsHint')),
            Array.isArray(coreEdit) && coreEdit.length > 0
              ? coreEdit.map(coreCard)
              : h('div', { className: 'rc2-note' }, '没有读到常设席位配置：重载插件后会恢复内置总指挥/参谋。'),
            coreSupported
              ? null
              : h('div', { className: 'rc2-note' }, '宿主插件尚未重载：这里的修改会先写回旧的角色配置，重载后自动迁移到常设席位。'),
            h('div', { className: 'rc2-sect' }, t('squadRoles')),
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn on',
                onClick: () => setRolesEdit([...rolesEdit, {
                  id: `role-${Date.now().toString(36).slice(-4)}`, name: '新角色', tier: 'deep',
                  reportsTo: 'commander', prompt: '', skills: [], model: null,
                }]),
              }, t('add'))),
            memberRows.map(({ role, index }) => h('div', {
              key: role.id,
              style: { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 6, padding: 8, marginBottom: 8 },
            },
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, 'id'),
                h('input', { value: role.id, onChange: (e) => update(index, 'id', e.target.value) })),
              h('div', { className: 'rc2-field' }, h('label', null, '名称'),
                h('input', { value: role.name || '', onChange: (e) => update(index, 'name', e.target.value) })),
              h('div', { className: 'rc2-field' }, h('label', null, t('ruleTier')),
                h('select', { value: role.tier || 'dsh', onChange: (e) => update(index, 'tier', e.target.value) },
                  MODEL_CHOICES.map((tier) => h('option', { key: tier, value: tier }, TIER_LABEL[tier]))))),
            h('div', { className: 'rc2-field' }, h('label', null, '技能（逗号分隔）'),
              h('input', { value: (role.skills || []).join(', '), placeholder: 'nuclei-scan, web-fingerprint', onChange: (e) => update(index, 'skills', e.target.value) })),
            h('div', { className: 'rc2-field' }, h('label', null, '提示词'),
              h('textarea', { style: { minHeight: 84 }, value: role.prompt || '', onChange: (e) => update(index, 'prompt', e.target.value) })),
            h('div', { className: 'rc2-field' }, h('label', null, '专属 MCP（一行一个：name = command args 或 name = https://host/mcp；留空=只用本机命令）'),
              h('textarea', {
                style: { minHeight: 54, fontFamily: 'var(--dsw-font-mono, monospace)', fontSize: 11 },
                value: mcpTextOf(role),
                placeholder: 'nuclei-mcp = python3 /opt/mcp/nuclei_server.py\nshodan = https://mcp.example.com/shodan',
                onChange: (e) => update(index, 'mcp', parseMcpText(e.target.value)),
              })),
            h('div', { className: 'rc2-row' },
              h('span', { className: 'rc2-meta' }, '汇报给'),
              h('select', {
                className: 'rc2-select', style: { maxWidth: 160 },
                value: role.reportsTo || '',
                onChange: (e) => update(index, 'reportsTo', e.target.value || null),
              },
              h('option', { value: '' }, '— 无（最高）'),
              reportTargetsOf(role).map((x) => h('option', { key: x.id, value: x.id }, x.name || x.id))),
              h('span', { className: 'rc2-spacer' }),
              h('button', {
                className: 'rc2-btn danger',
                onClick: () => setRolesEdit(rolesEdit.filter((_, i) => i !== index)),
              }, t('remove'))))))
        }

        if (tab === 'meeting') {
          const num = (value, fallback) => (Number.isFinite(Number(value)) ? Number(value) : fallback)
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('meetingHint')),
            h('div', { className: 'rc2-field', style: { marginTop: 4 } }, h('label', null, '轨迹最高显示数量'),
              h('div', { className: 'rc2-row rc2-boardcfg-row' },
                h('select', {
                  className: 'rc2-select rc2-boardcfg-select',
                  value: traceMode,
                  onChange: (e) => {
                    const mode = e.target.value
                    setTraceMode(mode)
                    if (mode !== 'custom') {
                      const limit = Number(mode) || 500
                      setTraceCfg({ limit })
                      try { window.localStorage.setItem('rc2.traceLimit', String(limit)) } catch { /* 忽略 */ }
                    }
                  },
                },
                h('option', { value: '500' }, '500 条'),
                h('option', { value: '1000' }, '1000 条'),
                h('option', { value: '2000' }, '2000 条'),
                h('option', { value: 'custom' }, '自定义')),
                traceMode === 'custom'
                  ? h('input', {
                    type: 'number', min: 100, max: 5000, step: 100,
                    style: { width: 120 },
                    value: num(traceCfg.limit, 500),
                    onChange: (e) => {
                      const limit = Math.max(100, Math.min(5000, Number(e.target.value) || 500))
                      setTraceCfg({ limit })
                      try { window.localStorage.setItem('rc2.traceLimit', String(limit)) } catch { /* 忽略 */ }
                    },
                  })
                  : null,
                h('span', { className: 'rc2-meta' }, `当前：最多显示 ${num(traceCfg.limit, 500)} 条轨迹`))),
            h('div', { className: 'rc2-grid2' },
              h('div', { className: 'rc2-field' }, h('label', null, t('meetingReview')),
                h('input', {
                  type: 'number', min: 1, max: 60, value: num(meetCfg.reviewMinutes, 5),
                  onChange: (e) => setMeetCfg({ ...meetCfg, reviewMinutes: Math.max(1, Math.min(60, Number(e.target.value) || 5)) }),
                })),
              h('div', { className: 'rc2-field' }, h('label', null, t('meetingRounds')),
                h('input', {
                  type: 'number', min: 1, max: 20, value: num(meetCfg.maxRounds, 3),
                  onChange: (e) => setMeetCfg({ ...meetCfg, maxRounds: Math.max(1, Math.min(20, Number(e.target.value) || 3)) }),
                }))),
            h('div', { className: 'rc2-field', style: { marginTop: 12 } }, h('label', null, '看板：保留上限 / 触顶后合并条数'),
              h('div', { className: 'rc2-row rc2-boardcfg-row' },
                h('select', {
                  className: 'rc2-select rc2-boardcfg-select',
                  value: String(boardCfg.limit || 100),
                  onChange: (e) => {
                    const limit = Number(e.target.value) || 100
                    setBoardCfg({ ...boardCfg, limit, mergeCount: Math.min(boardCfg.mergeCount || 50, Math.max(10, Math.floor(limit / 2))) })
                  },
                }, ['50', '100', '200'].map((v) => h('option', { key: v, value: v }, `${v} 条`))),
                h('select', {
                  className: 'rc2-select rc2-boardcfg-select rc2-boardcfg-select-wide',
                  value: String(Math.min(boardCfg.mergeCount || 50, Math.max(10, Math.floor((boardCfg.limit || 100) / 2)))),
                  onChange: (e) => setBoardCfg({ ...boardCfg, mergeCount: Number(e.target.value) || 50 }),
                }, ['25', '50', '100'].filter((v) => Number(v) <= Math.max(10, Math.floor((boardCfg.limit || 100) / 2)))
                  .map((v) => h('option', { key: v, value: v }, `合并最早 ${v} 条`))),
                h('span', { className: 'rc2-meta' }, `当前：满 ${boardCfg.limit || 100} 条 → 最早 ${Math.min(boardCfg.mergeCount || 50, Math.max(10, Math.floor((boardCfg.limit || 100) / 2)))} 条压成一条摘要`))),
            h('div', { className: 'rc2-grid2', style: { marginTop: 10 } },
              h('div', { className: 'rc2-field' }, h('label', null, '看板合并方式'),
                h('select', {
                  className: 'rc2-select rc2-boardcfg-select rc2-boardcfg-select-wide',
                  style: { width: '100%', minWidth: 220 },
                  value: boardCfg.mergeMode === 'ai' ? 'ai' : 'deterministic',
                  onChange: (e) => setBoardCfg({ ...boardCfg, mergeMode: e.target.value === 'ai' ? 'ai' : 'deterministic' }),
                }, h('option', { value: 'deterministic' }, '无 AI：确定性归档汇总'), h('option', { value: 'ai' }, 'AI 语义合并'))),
              h('div', { className: 'rc2-field' }, h('label', null, 'AI 合并模型'),
                h('select', {
                  className: 'rc2-select rc2-boardcfg-select rc2-boardcfg-select-wide',
                  style: { width: '100%', minWidth: 220 },
                  value: boardCfg.mergeModel === 'deep' ? 'deep' : 'fast',
                  disabled: boardCfg.mergeMode !== 'ai',
                  onChange: (e) => setBoardCfg({ ...boardCfg, mergeModel: e.target.value === 'deep' ? 'deep' : 'fast' }),
                }, h('option', { value: 'fast' }, 'Flash / 快速'), h('option', { value: 'deep' }, '深度 / Deep')))),
            h('div', { className: 'rc2-grid3', style: { marginTop: 10 } },
              h('div', { className: 'rc2-field' }, h('label', null, t('handoverEnabled')),
                h('select', {
                  value: handCfg.enabled === false ? 'no' : 'yes',
                  onChange: (e) => setHandCfg({ ...handCfg, enabled: e.target.value === 'yes' }),
                }, h('option', { value: 'yes' }, '开启'), h('option', { value: 'no' }, '关闭'))),
              h('div', { className: 'rc2-field' }, h('label', null, t('handoverTimeout')),
                h('input', {
                  type: 'number', min: 15, max: 600, step: 15, value: Math.round(num(handCfg.timeoutMs, 90000) / 1000),
                  onChange: (e) => setHandCfg({ ...handCfg, timeoutMs: (Number(e.target.value) || 90) * 1000 }),
                })),
              h('div', { className: 'rc2-field' }, h('label', null, t('handoverSkill')),
                h('span', { className: 'rc2-meta', style: { paddingTop: 7 } }, '只写看板，不写记忆')))) 
        }

        if (tab === 'automation') {
          if (autoCfg === null) return h('div', { className: 'rc2-center' }, t('loading'))
          const rules = Array.isArray(autoCfg.rules) ? autoCfg.rules : []
          return h('div', null,
            h('div', { className: 'rc2-note' }, t('automationHint')),
            autoStatus !== null && autoStatus !== undefined
              ? h('div', { className: 'rc2-note' }, `自动化队列 ${autoStatus.queued || 0} · 运行 ${autoStatus.runningAutomation || 0}/${autoStatus.maxAutomationAgents || 3}`)
              : null,
            h('div', { className: 'rc2-grid2' },
              h('div', { className: 'rc2-field' }, h('label', null, t('maxAgents')),
                h('input', {
                  type: 'number', min: 1, max: 50, value: autoCfg.maxAgents || 8,
                  onChange: (e) => setAutoCfg({ ...autoCfg, maxAgents: Math.max(1, Math.min(50, Number(e.target.value) || 1)) }),
                })),
              h('div', { className: 'rc2-field' }, h('label', null, t('maxAutomationAgents')),
                h('input', {
                  type: 'number', min: 1, max: 50, value: autoCfg.maxAutomationAgents || 3,
                  title: '自动化自己的独立并发上限；超出的触发任务会排队',
                  onChange: (e) => setAutoCfg({ ...autoCfg, maxAutomationAgents: Math.max(1, Math.min(50, Number(e.target.value) || 3)) }),
                }))),
            h('div', { className: 'rc2-field' }, h('label', null, t('automationEnabled')),
              h('select', {
                value: autoCfg.enabled === false ? 'no' : 'yes',
                onChange: (e) => setAutoCfg({ ...autoCfg, enabled: e.target.value === 'yes' }),
              }, h('option', { value: 'yes' }, '开启'), h('option', { value: 'no' }, '关闭'))),
            h('div', { className: 'rc2-sect' }, t('automationRules')),
            h('div', { className: 'rc2-row', style: { flexWrap: 'wrap' } },
              h('button', {
                className: 'rc2-btn on',
                onClick: () => setAutoCfg({
                  ...autoCfg,
                  rules: [...rules, {
                    id: `rule-${Date.now()}`, on: 'node.created', enabled: true, role: 'hunter', tier: 'deep',
                    whenKinds: ['subdomain', 'url'], cooldownMs: 45000,
                    task: '新资产 {{kind}}:{{value}}（{{nodeId}}）刚进图谱，做一轮针对探测并把结论写进看板。',
                  }],
                }),
              }, t('ruleAdd')),
              h('button', {
                className: 'rc2-btn ghost',
                onClick: () => {
                  const rule = {
                    id: `asset-hunt-${Date.now().toString(36).slice(-4)}`, on: 'node.created', enabled: true,
                    role: 'hunter', tier: 'deep', cooldownMs: 45000,
                    whenKinds: ['subdomain', 'ip', 'url', 'service', 'endpoint', 'host'],
                    task: '新资产 {{kind}}:{{value}}（{{nodeId}}）刚进图谱，做一轮针对性探测（指纹→已知漏洞→未授权接口），'
                      + '每条结论用 recon_run 复现并把 commandId 写进 recon_vuln，猜想写进看板。',
                  }
                  setAutoCfg({ ...autoCfg, enabled: true, rules: [...rules, rule] })
                },
              }, '⚡ 新资产 → 猎手'),
              h('button', {
                className: 'rc2-btn ghost',
                onClick: () => {
                  const rule = {
                    id: `vuln-verify-${Date.now().toString(36).slice(-4)}`, on: 'vuln.created', enabled: true,
                    role: 'browser', tier: 'vision', cooldownMs: 30000,
                    whenSeverity: ['critical', 'high', 'medium'],
                    task: '新漏洞 {{title}}（{{severity}}，{{nodeId}}）需要复现：用 recon_browser 打开 {{endpoint}}，'
                      + '定位参数/交互点、截图存证，把「可复现 / 不可复现 / 需前置条件」写进看板并更新漏洞状态。',
                  }
                  setAutoCfg({ ...autoCfg, enabled: true, rules: [...rules, rule] })
                },
              }, '⚡ 新漏洞 → 浏览器'),
              h('button', {
                className: 'rc2-btn ghost',
                onClick: () => {
                  const rule = {
                    id: `patrol-${Date.now().toString(36).slice(-4)}`, on: 'interval', enabled: true,
                    role: 'analyst', tier: 'deep', everyMs: 1800000,
                    task: '做一次巡检：读图谱与看板，指出攻击面优先级与缺口，给出下一步 3 条可执行任务并写进看板。',
                  }
                  setAutoCfg({ ...autoCfg, enabled: true, rules: [...rules, rule] })
                },
              }, '⚡ 每 30 分钟巡检')),
            rules.map((rule, index) => h('div', {
              key: rule.id || index,
              style: { border: '1px solid var(--dsw-alias-border-l1)', borderRadius: 6, padding: 8, marginBottom: 8 },
            },
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, 'id'),
                h('input', { value: rule.id || '', onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.id`, e.target.value)) })),
              h('div', { className: 'rc2-field' }, h('label', null, t('ruleOn')),
                h('select', { value: rule.on || 'node.created', onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.on`, e.target.value)) },
                  h('option', { value: 'node.created' }, 'node.created'),
                  h('option', { value: 'vuln.created' }, 'vuln.created'),
                  h('option', { value: 'command.finished' }, 'command.finished'),
                  h('option', { value: 'interval' }, 'interval'))),
              h('div', { className: 'rc2-field' }, h('label', null, 'enabled'),
                h('select', { value: rule.enabled === false ? 'no' : 'yes', onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.enabled`, e.target.value === 'yes')) },
                  h('option', { value: 'yes' }, 'yes'), h('option', { value: 'no' }, 'no')))),
            h('div', { className: 'rc2-grid3' },
              h('div', { className: 'rc2-field' }, h('label', null, t('ruleRole')),
                h('select', { value: rule.role || 'hunter', onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.role`, e.target.value)) },
                  (autoRoles.length > 0 ? autoRoles : [
                    { id: 'scout', name: '信息收集' }, { id: 'web', name: 'Web 手' }, { id: 'reverser', name: '逆向手' },
                    { id: 'intranet', name: '内网手' }, { id: 'qa', name: '验收' },
                  ]).filter((role) => role.core !== true && role.id !== 'commander' && role.id !== 'staff')
                    .map((role) => h('option', { key: role.id, value: role.id }, `${role.name}（${role.id}）`)))),
              h('div', { className: 'rc2-field' }, h('label', null, t('ruleTier')),
                h('select', { value: rule.tier || 'deep', onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.tier`, e.target.value)) },
                  MODEL_CHOICES.map((tier) => h('option', { key: tier, value: tier }, TIER_LABEL[tier])))),
              h('div', { className: 'rc2-field' }, h('label', null, rule.on === 'interval' ? 'everyMs' : t('ruleCooldown')),
                h('input', {
                  type: 'number',
                  value: rule.on === 'interval' ? (rule.everyMs || 1800000) : (rule.cooldownMs || 45000),
                  onChange: (e) => setAutoCfg(setIn(autoCfg, rule.on === 'interval' ? `rules.${index}.everyMs` : `rules.${index}.cooldownMs`, Number(e.target.value) || 0)),
                }))),
            h('div', { className: 'rc2-field' }, h('label', null, t('ruleKinds')),
              h('input', {
                value: Array.isArray(rule.whenKinds) ? rule.whenKinds.join(', ') : '',
                placeholder: 'subdomain, ip, url',
                onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.whenKinds`, e.target.value.split(',').map((s2) => s2.trim()).filter(Boolean))),
              })),
            h('div', { className: 'rc2-field' }, h('label', null, '漏洞等级（逗号分隔）'),
              h('input', {
                value: Array.isArray(rule.whenSeverity) ? rule.whenSeverity.join(', ') : '',
                placeholder: 'critical, high, medium',
                onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.whenSeverity`, e.target.value.split(',').map((s2) => s2.trim()).filter(Boolean))),
              })),
            h('div', { className: 'rc2-field' }, h('label', null, t('ruleTask')),
              h('textarea', {
                value: rule.task || '',
                onChange: (e) => setAutoCfg(setIn(autoCfg, `rules.${index}.task`, e.target.value)),
              })),
            h('div', { className: 'rc2-row' },
              h('button', {
                className: 'rc2-btn danger',
                onClick: () => setAutoCfg({ ...autoCfg, rules: rules.filter((_, i) => i !== index) }),
              }, t('remove'))))))
        }

        const ui = cfg.ui || {}
        return h('div', null,
          h('div', { className: 'rc2-field' },
            h('label', null, t('accent')),
            h('select', { value: ui.accent || 'cyan', onChange: (event) => setCfg(setIn(cfg, 'ui.accent', event.target.value)) },
              ACCENTS.map((a) => h('option', { key: a, value: a }, a)))),
          ['glow', 'grid', 'scanlines'].map((flag) => h('div', { key: flag, className: 'rc2-field' },
            h('label', null, t(flag)),
            h('select', {
              value: ui[flag] === false ? 'no' : 'yes',
              onChange: (event) => setCfg(setIn(cfg, `ui.${flag}`, event.target.value === 'yes')),
            }, h('option', { value: 'yes' }, 'yes'), h('option', { value: 'no' }, 'no')))))
      })()

      return h('div', { className: 'rc2-drawer', onClick: (event) => { if (event.target === event.currentTarget) props.onClose() } },
        h('div', { className: 'rc2-panel' },
          h('div', { className: 'rc2-panelhead' },
            h('h2', null, t('settings')),
            h('span', { className: 'rc2-spacer' }),
            h('span', { className: 'rc2-note', style: { margin: 0 } }, notice),
            h('button', { className: 'rc2-btn on', onClick: () => void save(), disabled: saving }, saving ? t('saving') : t('save')),
            h('button', { className: 'rc2-btn ghost', onClick: props.onClose }, '✕')),
          h('div', { className: 'rc2-tabs' },
            [['models', 'tabModels'], ['keys', 'tabKeys'], ['roles', 'tabRole'], ['memory', 'tabMemory'],
              ['skills', 'tabSkills'], ['mcp', 'tabMcp'], ['automation', 'tabAutomation'],
              ['meeting', 'tabMeeting'], ['ui', 'tabUi']].map(([key, labelKey]) => h('button', {
              key, className: `rc2-tab${tab === key ? ' on' : ''}`, onClick: () => setTab(key),
            }, t(labelKey)))),
          h('div', { className: 'rc2-panelbody' }, body)))
    }

    /* ───────────────────────── 插件入口 ───────────────────────── */
    function apply(ctx) {
      ctx.effect(() => {
        const style = document.createElement('style')
        style.setAttribute('data-venery', 'v2')
        style.textContent = CSS
        document.head.appendChild(style)
        return () => { style.remove() }
      })
      ctx.effect(() => ctx.locale.register(NS, DICT))

      const t = ctx.locale.bind(NS)

      ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({
        name: 'sidebar.panellist',
        id: 'venery',
        order: 20,
        label: () => t('title'),
      }, ReconIcon))

      ctx.slots.inject('main', () => ctx.slots.register({
        name: 'main',
        key: 'venery',
        inject: () => ({ t }),
      }, (slotProps) => h(PanelBoundary, null, h(CockpitPage, slotProps))))
    }

    return { inject: ['slots', 'locale'], apply }
  },
})
