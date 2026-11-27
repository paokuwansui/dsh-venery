# 狩猎（dsh-venery）

红队信息收集驾驶舱插件，面向 DeepSeek Harness（DSH）Web 端。

项目名 `dsh-venery`，插件名 `dsh-狩猎`，界面标题「狩猎」。

它把一次演练中的**资产、关系、漏洞**画成一张可交互的节点图，同时把**命令留痕、团队看板、多智能体编队、断点续跑、验收审计**放进同一个面板。指挥席、AI 与编队成员共用同一份事实库。

强烈建议安装再kali操作系统并搭配破甲使用

> ⚠️ 仅限在获得明确授权的范围内使用。使用者需自行确保目标、数据与行为合法合规；本项目不提供任何形式的授权、许可或免责。
<img width="1237" height="701" alt="屏幕截图 2026-11-24 035445" src="https://github.com/user-attachments/assets/d8311b37-cf9f-49d0-b739-8db96cb2583f" />

---

## 功能

### 驾驶舱界面

| 区域 | 作用 |
|---|---|
| 顶部项目栏 | 切换 / 新建 / 删除靶标；资产·关系·漏洞·命令计数；连接状态；模型档位；视觉模式 |
| 轨迹栏 | 命令、工具调用、对话按时间滚动；可按 全部 / 调度 / 派活 / 队员 / 技能 筛选，可屏蔽本机 bash |
| 资产图 | 节点 = 资产（类型可自定义），边 = 关系，菱形 = 漏洞；点节点高亮「所有根到它的路径 + 整棵子树」，双击折叠子树，可拖拽 / 缩放 / 重排 / 适应 |
| 图例 | 按类型统计，点类型固定高亮该类节点；「漏洞」高亮所有带漏洞的节点；折叠时只占一行，右侧固定「+N 展开」与「漏洞」 |
| 节点详情 | 属性、关联数量、来源命令，支持折叠子树 / 归档 / 删除 |
| 漏洞列表 | 按等级排序，可查看 payload、证据命令与状态（open / verified / false-positive / fixed） |
| 团队看板 | 发现 / 猜想 / 任务 / 结论 / 备注，支持节点·漏洞·命令引用与截图缩略图，可编辑、删除、合并 |
| 协作小组 | 成员遇到跨职责卡点时可请求总指挥编组；组内串行求助、共享消息，整体只算一个并发，结束后逐人交接并一起回收 |
| 底部驾驶舱 | 对话 / 总结汇报 / 看板 / 队伍 / 任务 五个页签；切模型档位、导出、查看思维链、消息队列 |
| 总结汇报 | 独立的只读汇报席会话，每轮现算战况快照；不污染总指挥上下文 |
| 控制台 | 模型三档、测绘密钥、角色与提示词、记忆、技能、MCP、并发与自动化、轨迹会议与交接、看板阈值、外观 |

### 智能体能力

- **采集与判定**：`recon_start` `recon_run` `recon_ingest` `recon_asset` `recon_link` `recon_vuln` `recon_update` `recon_view` `recon_asset_remove`
- **指纹 Nday 检索**：`recon_nday`（信息收集手专用：按指纹 / 产品 / 版本查 Exploit-DB 与 NVD 的历史漏洞；只查公开库，不对目标发包；候选先写看板，实测后才 `recon_vuln`。信息收集手的岗位提示词里也内置了这项固定职能：测绘中探测到指纹后主动查，不必等总指挥单独指派）
- **协同**：`recon_board` `recon_squad` `recon_org` `recon_task` `recon_watch` `recon_meeting` `recon_audit` `recon_checkpoint` `recon_config`
- **浏览器**：`recon_browser`（Playwright + Chromium，登录态按靶标持久化；支持单步动作和 `steps` 多步流程）

### 编队与流程

- **常设席位**：每个靶标固定各一个总指挥、一个参谋，独立配置（`core`）、自动补位、不会被回收，也不能被 `recon_squad` / `recon_org` 召唤为队员；要派活直接用 `recon_squad task` 或驾驶舱对话。
- **独立工位**：每名队员有自己的工作目录，产物不互相覆盖；离职不删目录，同名复用。
- **专属 MCP**：每个队员可挂自己的 MCP 服务，注册名带私人前缀，其他成员看不到、调不到。
- **技能派发**：角色 skills 会随成员提示词下发；`recon_skill` 可从 `$HOME/Public/skills`、`$DSH_HOME/skills`、`$DSH_HOME/redteam/skills` 列出并加载完整技能正文。
- **MCP 示例**：Web/QA 可配置浏览器或扫描类 MCP，逆向/内网可配置 C2 或隧道类 MCP；实际连接状态需对应服务可用。
- **全局记忆**：所有 agent 强制完整读取；只有总指挥和参谋可以写入，只记录项目概况、总体目标、环境/工具、特殊手法、已确认漏洞和凭据等关键事实，写入条数不设上限。
- **离职交接**：任何释放动作先产出「发现 / 踩过的坑 / 技巧 / 建议」，只落看板，不写记忆。
- **全员会议**：任务都派完、没人在跑、一段时间无新进展时自动召集（有冷却与轮次上限），总指挥汇总成新一轮任务。
- **断点续跑**：手动中断或心跳超时自动存断点；「继续」时给总指挥发交接单并按未完成任务重新派活。
- **验收审计**：`recon_audit` 按覆盖度规则体检命令，判定 pass / improve / rework，并生成返工任务。
- **看板正文**：看板分两层：`summary`=概括索引，`text`=完整正文。用户条目只有正文，正文完整保存并强制注入所有 agent，条数和字数不设上限；agent 条目必须同时写概括索引和正文；概括必须是语义提炼（禁止复制或截断正文），所有概括索引强制注入上下文，正文用 `recon_board action=view id=...` 按需查看。agent 条目达到设定的看板上限时自动压缩最早一批，右侧看板顶部另有数量输入框和「手动压缩」按钮，输入 N 后立即压缩最早 N 条 agent 条目，用户发言不参与。截图始终只附路径。
- **轨迹显示上限**：控制台「轨迹会议与交接」可设 500 / 1000 / 2000 条或自定义 100–5000 条。
- **按队员看看板**：右侧看板栏、底部看板页签与放大视图都有作者下拉框；「你」永久作为第一项，其余作者按发言量排序。选中某个队员后只显示他的发言，下拉框右侧同步显示「名字 · N 条」（N 含被压缩的条数）；选「全部发言」时显示「你 · N 条」，N 为你在看板的发言总数。只有真人经看板输入框发出的内容才算「用户发言」，agent 与指挥席的记录不会再计入「你」。
- **压缩也能按人查**：被压缩的条目会按作者保留条数与摘要样本；选中某个队员时，他被压缩的发言单独显示为可展开的「📦 已压缩 N 条」卡片，摘要条目还能「按角色查看」并一键「只看他」。

---

## 环境要求

- DeepSeek Harness Web 版，且 profile 已启用 Web 相关 bundle。
- 可选依赖（按需安装）：
  - Kali / Linux 工具链：nmap、nuclei、ffuf、subfinder、httpx、sqlmap 等（`recon_run` 用）。
  - Python 3 + Playwright + Chromium（`recon_browser` 用）。

插件本身没有 npm 运行时依赖，`client.js` 是自包含的浏览器 bundle。

---

## 安装

本目录就是一个完整的 DSH 插件包（bundle），包名为 `dsh-venery`，在插件库里显示为 `dsh-狩猎`。

1. 把整个目录放到任意位置（不要放进 DSH 的 profile 目录里）。
2. 打开 DSH Web → **插件（Plugins）** → **添加插件 / Add plugin** → 选择本目录。
3. 安装完成后确认插件列表出现 `dsh-狩猎`（包名 `dsh-venery`）且已启用。
4. 刷新页面，侧栏会出现「狩猎」图标。

也可以让 DSH 的智能体调用插件管理工具的 `install_bundle`，参数为本目录的绝对路径。

安装后可在 profile 的 `cordis.patch.yml` 中调整插件行配置：

```yaml
- id: venery
  name: 'dsh-venery'
  config:
    root: !!js dshHomePath('recon')
    maxOutputChars: 24000
    defaultTimeoutMs: 300000
    systemPrompt: true
```

| 配置项 | 默认 | 说明 |
|---|---|---|
| `root` | `$DSH_HOME/recon` | 事实库根目录 |
| `maxOutputChars` | `24000` | 单条命令回给模型的输出上限（完整输出始终落盘） |
| `defaultTimeoutMs` | `300000` | 命令默认超时 |
| `systemPrompt` | `true` | 是否向主会话注入工作流段落（通用提示词的注入也受此开关控制） |

---

## 快速开始

1. 打开「狩猎」页面，新建一个靶标。
2. 在底部驾驶舱说一句「从这里开始收集 <目标>」，或让主会话调用 `recon_start`。
3. 所有 `recon_run` 的命令输出、`recon_asset` / `recon_ingest` 写入的资产与漏洞都会实时出现在图上。
4. 需要并行时，由总指挥用 `recon_squad spawn` 派活；任务账本用 `recon_task`。

典型工作流：

```
recon_start       建立靶标并落下起始资产
recon_run         跑命令，返回 commandId
recon_ingest      批量把节点 / 边 / 漏洞写入图谱（带 commandId 证据）
recon_link        「A 发现 B」连边
recon_vuln        登记可验证的风险，验证后 recon_update 改 verified
recon_view        不确定进度时查看图谱
```

---

## 配置

页面上的「控制台」与工具 `recon_config` 等价，配置写入 `$DSH_HOME/recon/config.json`。

- **模型**：三档 **Deep / Flash / Vision**；每档从控制台添加的自定义模型里**按名称**选择，选中即把该模型的 provider/model/思考深度应用到这一档；三档都留空时全部跟随 DSH 默认模型。自定义模型的思考深度四档 **Off / Low / Medium / High**。
- **自定义模型**：控制台「模型」页可以添加模型（Base URL、API Key、模型 id、协议、默认思考深度）；协议支持 OpenAI Compatible / OpenAI Responses / Anthropic Messages。保存后通过 DSH 的 `llm-pi-ai` 注册 provider 路由；API Key 写入 DSH credentials，不写进 venery 的 `config.json`。角色只选档位（Deep / Flash / Vision / 跟随 DSH），实际 provider/model 由模型页统一决定。
- **密钥**：FOFA、Shodan、GitHub、VirusTotal、Hunter、Quake、Censys、SecurityTrails、HunterHow、Daybreak、GitLab、Telegram 等。密钥只写在本机配置文件，并以环境变量注入 `recon_run` 的命令环境：

  `GITHUB_TOKEN` / `GH_TOKEN`、`FOFA_KEY`、`FOFA_EMAIL`、`SHODAN_API_KEY`、`VT_API_KEY`、`HUNTER_API_KEY`、`QUAKE_API_KEY`、`CENSYS_API_ID`、`CENSYS_API_SECRET`、`SECURITYTRAILS_API_KEY`、`HUNTERHOW_API_KEY`、`DAYBREAK_API_KEY`、`GITLAB_TOKEN`、`TELEGRAM_BOT_TOKEN`

- **通用提示词**：控制台「角色与提示词」页顶部的一段文本（`prompt.common`），注入所有 Agent——驾驶舱、汇报席、主会话与编队成员（含常设席位，以及自动化事件、会议、断点续跑派发的成员）。最终提示词 = 通用提示词 + 该 Agent 自身提示词；留空则不注入。主会话的注入还受插件 `systemPrompt` 配置开关控制。
- **角色与提示词**：控制台把原来的「角色·提示词」与「队伍」合并为一页。顶部「通用提示词」；下面是「常设席位」（`core.commander` / `core.staff`，每靶标各一个、不可召唤/回收）与「队员岗位」（`roles.squad[].prompt`，决定用 `recon_squad` 派出去的队员怎么干活；老配置里的常设席位会自动迁到 `core`）。**总指挥就是最高统领**：驾驶舱 lead 与编队总指挥共用 `core.commander` 的人设/提示词；参谋席位同理共用 `core.staff`。原来的独立 `role` / `prompt.extra` 驾驶舱人设已取消。角色与常设席位只选择模型档位（Deep / Flash / Vision / 跟随 DSH），provider/model 由「模型」页统一决定。队员身上还可以再带一条**专属指令**（派遣时的 `prompt` 参数，队员卡上显示为 📌），只对那名队员、本次在岗生效，优先级高于岗位提示词。
- **并发与自动化**：自动化默认开启。最大并发数默认 8；自动化有独立的 `maxAutomationAgents`（默认 3，可设置 1-50），只统计自动化派发的 agent。超过上限的触发任务进入队列，有空位后按顺序派发；下面是事件规则（新资产→猎手、新漏洞→浏览器、定时巡检），可逐条调冷却与任务模板。最大并发数同时抬高成员上限，不会被隐藏的 6 人上限拦住。
- **轨迹会议与交接**：轨迹最高显示数量（500 / 1000 / 2000 / 自定义）、停滞判定（默认 20 分钟）、会议冷却（20 分钟）、最多自动开会轮数（3）、离职交接开关 / 等待上限；交接只写看板。
- **看板**：正文完整保存与显示；达到设定的看板上限时自动压缩最早一批。右侧看板顶部可输入数量并点「手动压缩」，只压缩最早的 agent 条目，用户发言不参与。
- **外观**：主色、光晕、网格、扫描线。

---

## HTTP 接口

插件在 DSH Web 上注册三个同源路由：

| 方法 | 路径 | 作用 |
|---|---|---|
| `POST` | `/recon/api` | 全部业务操作，请求体 `{ "op": "...", ... }` |
| `GET` | `/recon/stream` | SSE 实时事件流（图谱变更 / 命令 / 漏洞 / 对话 / 轨迹） |
| `GET` | `/recon/asset?p=` | 读取浏览器截图或 uploads 产物（只允许 `browser/`、`uploads/`，非图片强制下载） |

常用 `op`：`overview` `select` `create` `delete` `deleteAll` `rename` `ingest` `asset` `link` `vuln` `update` `remove` `board` `tasks` `squad` `chat` `brief.chat` `brief.history` `mission` `config` `browsers.list` `meeting.status` `meeting.convene` `runner.status` `runner.pause` `runner.resume`。

---

## 数据目录

运行时数据全部写在 `$DSH_HOME/recon/`：

```
engagements/  靶标本体（节点 / 边 / 漏洞 / 命令元信息）
commands/     命令原始输出
board/        团队看板
tasks/        任务账本与作战目标
meeting/      全员会议轮数与冷却状态
trace/        轨迹
chat/         驾驶舱与队员对话
brief/        汇报席（总结汇报）的独立对话历史
browser/      浏览器截图与登录态
browsers/     浏览器活动画面（谁在操作、最新截图与错误）
work/         每条命令 / 每名队员的工作目录
uploads/      上传文件
checkpoints/  断点
roster.json   成员代号花名册（用于把历史正文里的内部 ID 翻译成名字）
config.json   配置与密钥
```

删除靶标会连同上述派生数据（含 `brief/` 与 `checkpoints/`）一起清理；清空全部时保留 `config.json`。

---

## 跨平台

`recon_run` 按平台选择 shell：

- Windows：`cmd.exe /d /s /c`（先 `chcp 65001` 切 UTF-8），失败依次回退 `cmd.exe` → `powershell.exe` → `pwsh.exe`。
- Linux / macOS：bash（找不到时回退 sh）。

可用环境变量覆盖：

| 变量 | 作用 |
|---|---|
| `DSH_RECON_SHELL` | 指定 shell 路径（如 Git Bash） |
| `DSH_RECON_SHELL_ARGS` | 指定 shell 参数，空格分隔；最后会追加命令 |
| `DSH_RECON_PYTHON` | 指定 `recon_browser` 使用的 Python 解释器 |
| `RECON_CHROMIUM` | 指定 Chromium / Chrome / Edge 可执行文件路径 |

超时或中断时，POSIX 杀进程组，Windows 使用 `taskkill /T /F`。

---

## 安全说明

- 本插件会**在本机执行 shell 命令**，请只在受控环境使用，并确保目标在授权范围内。
- 测绘密钥以明文保存在本机 `config.json`（文件权限 0600，未加密）；接口只回显「是否已配置」，不会把明文下发到页面。请自行保护该文件与所在主机。
- `/recon/api` 与 `/recon/asset` 都做同源校验；`/recon/asset` 只读取 `browser/` 与 `uploads/`，不暴露 `config.json`、浏览器登录态、命令日志或看板文件。
- 命令输出、截图、对话会落盘，注意演练结束后的数据清理。

---

## 目录结构

```
index.js            Host 半：事实库、工具注册、HTTP 桥、SSE、编队/任务/看板/浏览器/配置
client.js           Web 半：侧栏面板与全部界面（React + createElement）
browser_runner.py   浏览器子进程（Playwright）
cordis.patch.yml    bundle patch（挂载 Host 行）
locale/*.json       中英文案
package.json        插件清单（dsh.bundle / dsh.client）
icon.svg            侧栏图标
```

---

## 版本

当前版本 **0.51.5**。变更记录见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

本仓库未附带开源许可证。公开分发前请由作者选择并添加 `LICENSE` 文件。
