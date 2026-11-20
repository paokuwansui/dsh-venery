#!/usr/bin/env python3
"""recon_browser 的执行体：一次调用 = 一个 chromium 会话，登录态用 storageState 持久化。

约定：只在 stdout 打印一行 JSON 结果；日志全部走 stderr，便于 Host 侧解析。
"""
import json
import os
import sys
import traceback

def main():
    request = json.loads(sys.argv[1])
    action = request.get("action") or "goto"
    url = request.get("url") or ""
    selector = request.get("selector") or ""
    value = request.get("value") or ""
    key = request.get("text") or ""
    expression = request.get("expression") or ""
    state_path = request.get("statePath") or ""
    shot_path = request.get("shotPath") or ""
    timeout_ms = int(request.get("timeoutMs") or 20000)
    max_chars = int(request.get("maxChars") or 6000)
    steps = request.get("steps") or []
    headless = request.get("headless", True)

    result = {"ok": False, "action": action, "url": url, "title": "", "shot": None}

    from playwright.sync_api import sync_playwright

    def launch(pw):
        # 候选顺序：显式指定 → Playwright 自带 → 常见系统安装路径（Linux / macOS / Windows）
        local = os.environ.get("LOCALAPPDATA") or ""
        program_files = os.environ.get("PROGRAMFILES") or ""
        program_files_x86 = os.environ.get("PROGRAMFILES(X86)") or ""
        candidates = [
            os.environ.get("RECON_CHROMIUM"),
            None,
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            os.path.join(local, "Chromium", "Application", "chrome.exe") if local else None,
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe") if local else None,
            os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe") if program_files else None,
            os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe") if program_files_x86 else None,
            # 没装 Chrome 时用 Edge（Windows 自带）
            os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe") if program_files_x86 else None,
            os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe") if program_files else None,
        ]
        last_error = None
        for exe in candidates:
            if exe and not os.path.exists(exe):
                continue
            try:
                if exe:
                    return pw.chromium.launch(headless=headless, executable_path=exe,
                                              args=["--no-sandbox", "--disable-dev-shm-usage"])
                return pw.chromium.launch(headless=headless, args=["--no-sandbox", "--disable-dev-shm-usage"])
            except Exception as error:  # noqa: BLE001
                last_error = error
        raise last_error or RuntimeError(
            "找不到可用的 Chromium：装 Chrome/Edge，或用 RECON_CHROMIUM 指定浏览器路径")

    with sync_playwright() as pw:
        browser = launch(pw)
        context_args = {
            "viewport": {"width": 1440, "height": 900},
            "ignore_https_errors": True,
            "locale": "zh-CN",
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
        }
        if state_path and os.path.exists(state_path):
            context_args["storage_state"] = state_path
        context = browser.new_context(**context_args)
        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        console_logs = []

        def on_console(message):
            try:
                console_logs.append({"type": message.type, "text": str(message.text)[:500]})
            except Exception:
                pass

        page.on("console", on_console)
        page.on("pageerror", lambda error: console_logs.append({"type": "pageerror", "text": str(error)[:500]}))
        result["console"] = console_logs

        def snapshot(include_text=True, include_html=False):
            data = {"url": page.url, "title": page.title()}
            if include_text:
                try:
                    data["text"] = page.inner_text("body")[:max_chars]
                except Exception:
                    data["text"] = ""
            if include_html:
                try:
                    data["html"] = page.content()[:max_chars * 4]
                except Exception:
                    data["html"] = ""
            return data

        try:
            if url:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            def run_step(step):
                step_action = step.get("action") or "goto"
                if step.get("url"):
                    page.goto(step["url"], wait_until="domcontentloaded", timeout=timeout_ms)
                if step_action == "click":
                    if step.get("selector"):
                        page.click(step["selector"], timeout=timeout_ms)
                    elif step.get("x") is not None and step.get("y") is not None:
                        page.mouse.click(float(step["x"]), float(step["y"]))
                    else:
                        raise RuntimeError("click 需要 selector 或 x/y")
                    page.wait_for_timeout(int(step.get("waitMs") or 800))
                elif step_action == "fill":
                    page.fill(step["selector"], step.get("value") or "", timeout=timeout_ms)
                elif step_action == "press":
                    page.keyboard.press(step.get("text") or "Enter")
                    page.wait_for_timeout(int(step.get("waitMs") or 600))
                elif step_action == "wait":
                    page.wait_for_timeout(int(step.get("waitMs") or 1000))
                elif step_action == "waitFor":
                    page.wait_for_selector(step.get("selector"), timeout=timeout_ms)
                elif step_action == "goto":
                    page.wait_for_timeout(int(step.get("waitMs") or 500))
                elif step_action == "eval":
                    page.evaluate(step.get("expression") or "1")
                elif step_action == "screenshot":
                    target = step.get("shotPath") or shot_path
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    page.screenshot(path=target, full_page=True)
                    result.setdefault("shots", []).append(target)
                return {"action": step_action, "url": page.url, "title": page.title()}

            if action == "steps":
                trace = []
                for step in steps[:40]:
                    trace.append(run_step(step))
                result["steps"] = trace
                result.update(snapshot())
                result["console"] = console_logs
            elif action == "goto":
                page.wait_for_timeout(600)
                result.update(snapshot(include_html=True))
            elif action == "click":
                if selector:
                    page.click(selector, timeout=timeout_ms)
                elif request.get("x") is not None and request.get("y") is not None:
                    page.mouse.click(float(request["x"]), float(request["y"]))
                else:
                    raise RuntimeError("click 需要 selector 或 x/y")
                page.wait_for_timeout(900)
                result.update(snapshot())
            elif action == "fill":
                if not selector:
                    raise RuntimeError("fill 需要 selector")
                page.fill(selector, value, timeout=timeout_ms)
                result.update(snapshot())
            elif action == "press":
                page.keyboard.press(key or "Enter")
                page.wait_for_timeout(700)
                result.update(snapshot())
            elif action == "text":
                if selector:
                    result["text"] = page.inner_text(selector)[:max_chars]
                    result["value"] = page.input_value(selector) if page.query_selector(selector) else ""
                result.update(snapshot())
            elif action == "html":
                result["html"] = page.content()[: max_chars * 6]
                result.update(snapshot(include_text=False))
            elif action == "eval":
                if not expression:
                    raise RuntimeError("eval 需要 expression")
                result["value"] = page.evaluate(expression)
                result.update(snapshot(include_text=False))
            elif action == "links":
                items = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.slice(0, 300).map(e => ({text: (e.innerText||'').trim().slice(0,80), href: e.href}))",
                )
                result["items"] = items
                result.update(snapshot(include_text=False))
            elif action == "forms":
                items = page.eval_on_selector_all(
                    "input,textarea,select,button",
                    """els => els.slice(0, 300).map(e => ({
                        tag: e.tagName.toLowerCase(),
                        type: e.getAttribute('type') || '',
                        name: e.getAttribute('name') || '',
                        id: e.getAttribute('id') || '',
                        placeholder: e.getAttribute('placeholder') || '',
                        value: e.value !== undefined ? String(e.value).slice(0, 80) : ''
                    }))""",
                )
                result["items"] = items
                result.update(snapshot(include_text=False))
            elif action == "screenshot":
                if not shot_path:
                    raise RuntimeError("screenshot 需要 shotPath")
                os.makedirs(os.path.dirname(shot_path), exist_ok=True)
                page.screenshot(path=shot_path, full_page=True)
                result["shot"] = shot_path
                result.update(snapshot())
            else:
                raise RuntimeError("未知 action: " + action)

            if state_path:
                os.makedirs(os.path.dirname(state_path), exist_ok=True)
                context.storage_state(path=state_path)
            result["ok"] = True
        except Exception as error:  # noqa: BLE001
            result["ok"] = False
            result["error"] = f"{type(error).__name__}: {error}"
            try:
                result.update(snapshot(include_text=True))
            except Exception:
                pass
            traceback.print_exc(file=sys.stderr)
        finally:
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass

    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
