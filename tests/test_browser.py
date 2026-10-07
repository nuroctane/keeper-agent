"""Real Chromium/Edge exercise, with HTTPS fixture requests fulfilled in-process."""
import os
from types import SimpleNamespace

import pytest

from keeper_agent.engine import Engine
from keeper_agent.policy import validate


@pytest.mark.skipif(os.environ.get("KEEPER_AGENT_BROWSER_TEST") != "1", reason="Opt-in installed browser test")
def test_real_browser_fill_submit_redact_and_block(monkeypatch):
    import playwright.sync_api as pw
    real_factory = pw.sync_playwright
    submitted = []
    blocked = []
    secret = "browser-fixture-password"
    class Provider:
        def sync(self):
            pass
        def get(self, ref):
            return secret
    class FixturePlaywright:
        def __enter__(self):
            self.manager = real_factory()
            actual = self.manager.__enter__()
            def launch(**kwargs):
                browser = actual.chromium.launch(**kwargs)
                real_context = browser.new_context
                def new_context(**kwargs):
                    context = real_context(**kwargs)
                    real_route = context.route
                    def route(pattern, guard):
                        def handle(request_route):
                            def allow():
                                if request_route.request.url.endswith("/done"):
                                    submitted.append(request_route.request.post_data)
                                    request_route.fulfill(content_type="text/html", body=f"<p id='done'>{secret}</p>")
                                else:
                                    request_route.fulfill(content_type="text/html", body="""
                                        <form method='post' action='/done'>
                                        <input name='password' type='password'>
                                        <button type='submit'>Sign in</button></form>
                                        <img src='https://blocked.invalid/track'>
                                    """)
                            def abort():
                                blocked.append(request_route.request.url)
                                request_route.abort()
                            guard(SimpleNamespace(request=request_route.request, continue_=allow, abort=abort))
                        real_route(pattern, handle)
                    monkeypatch.setattr(context, "route", route)
                    return context
                monkeypatch.setattr(browser, "new_context", new_context)
                return browser
            return SimpleNamespace(chromium=SimpleNamespace(launch=launch))
        def __exit__(self, *args):
            return self.manager.__exit__(*args)
    monkeypatch.setattr(pw, "sync_playwright", FixturePlaywright)
    policy = validate({"version": 1, "actions": {"login": {
        "kind": "browser", "channel": os.environ.get("KEEPER_AGENT_BROWSER_CHANNEL") or None,
        "origins": ["https://fixture.invalid"], "timeout": 30,
        "secrets": {"password": {"record": "fixture", "field": "password"}},
        "steps": [
            {"op": "goto", "url": "https://fixture.invalid/login"},
            {"op": "fill", "selector": "input[name=password]", "value": "{{password}}"},
            {"op": "click", "selector": "button"},
            {"op": "wait", "selector": "#done"},
            {"op": "text", "selector": "#done", "name": "result"}
        ]}}})
    result = Engine(policy, Provider()).run("login")
    assert submitted == [f"password={secret}"]
    assert "https://blocked.invalid/track" in blocked
    assert result == {"completed": True, "data": {"result": "[REDACTED]"}}
