# Changelog

## 0.50.0

### 变更

- 项目更名为 `dsh-venery`，插件在插件库中显示为 `dsh-狩猎`，界面标题改为「狩猎」。
- 包名、客户端模块 id、cordis 入口 id 分别更新为 `dsh-venery` / `venery`。
- README 重写为面向发布的文档。

## 0.49.1

### 修复

- **全员会议不再重复创建总指挥 / 参谋**
  - `Meeting.convene` 不再对核心角色调用 `spawn`，改为在常设席位上用 `squad.task` 追加会议任务。
  - `Squad.spawn` 增加常设席位单例闸门与并发占位等待：commander / staff 已存在时直接复用，任务追加给原席位。
  - 核心席位名称改为纯「总指挥 / 参谋」，不再带序号。

- **插件重载导致的定时器泄漏**
  - `apply` 的清理函数只清除了第一个定时器，导致 `meetingTimer` / `runnerTimer` / `coreTimer` 泄漏；旧实例在重载后仍会每分钟补建常设席位、开会议、存断点。
  - 现在四个定时器全部清理。

- **看板「删」导致整页渲染失败**
  - 删除按钮以对象形式调用 `uiConfirm`，对象被当作 `title` 渲染成 React child，触发 `Objects are not valid as a React child`。
  - `uiConfirm` / `uiAlert` 同时接受字符串与对象两种签名。

- **Windows 支持**
  - `recon_run` 不再写死 `/bin/bash`：Windows 使用 `cmd.exe` 并回退 PowerShell，输出切换 UTF-8。
  - 杀进程树按平台处理（POSIX 进程组 / Windows `taskkill /T /F`）。
  - `recon_browser` 不再写死 `python3`，并补充 Windows 的 Chrome / Chromium / Edge 路径。
  - 提示词与界面不再假定 Kali Linux；新增 `DSH_RECON_SHELL`、`DSH_RECON_PYTHON`、`RECON_CHROMIUM` 覆盖项。

## 0.49.0

- 资产 / 关系 / 漏洞图谱，命令留痕与证据链。
- 团队看板、任务账本、多智能体编队与常设席位。
- 全员会议、断点续跑、离职交接、验收审计与返工。
- 真实浏览器工具与按靶标持久化登录态。
- 控制台：模型、密钥、角色、提示词、记忆、技能、MCP、自动化、看板阈值。
- 总结汇报只读会话、Markdown 渲染（含表格）。
