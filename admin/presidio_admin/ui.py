"""Server-rendered pages. Every interpolated value is escaped."""

from __future__ import annotations

import html
from typing import Any

from presidio_admin.authz import Principal


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def page(*, title: str, principal: Principal | None, body: str, notice: str = "") -> str:
    who = esc(principal.display_label) if principal else "signed out"
    oid = esc(principal.oid) if principal else ""
    banner = f"<p class='notice'>{esc(notice)}</p>" if notice else ""
    nav = ""
    if principal:
        nav = """
        <nav>
          <a href="/">Overview</a>
          <a href="/upstreams">Upstreams</a>
          <a href="/clients">Clients</a>
          <a href="/recognizers">Recognizers</a>
          <a href="/verifier">Verifier</a>
          <a href="/audit">Audit</a>
          <a href="/history">History</a>
          <a href="/proposals">Approvals</a>
          <a href="/health">Health</a>
        </nav>
        """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>{esc(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #1c1915;
      --muted: #5c564c;
      --line: #e4dccf;
      --paper: #f7f3ec;
      --card: #fffdf8;
      --accent: #8c3d1e;
      --ok: #1f6b45;
      --wait: #8a5a12;
      --bad: #8d2a2a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font: 16px/1.45 "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background: var(--paper);
    }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      padding: 1rem 1.5rem;
      background: #241c16;
      color: #f4efe6;
    }}
    header strong {{ font-weight: 650; letter-spacing: 0.01em; }}
    header span {{ color: #d7c4b2; }}
    nav {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      padding: 0.75rem 1.5rem;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }}
    nav a {{
      color: var(--ink);
      text-decoration: none;
      padding: 0.35rem 0.6rem;
      border-radius: 999px;
    }}
    nav a:hover {{ background: #f0e7db; }}
    main {{ padding: 1.25rem 1.5rem 3rem; max-width: 1100px; }}
    h1 {{ font-size: 1.5rem; margin: 0 0 0.75rem; }}
    h2 {{ font-size: 1.05rem; margin: 1.25rem 0 0.5rem; }}
    .notice {{
      background: #fff6e8;
      border: 1px solid #ead7b8;
      padding: 0.6rem 0.8rem;
      border-radius: 8px;
    }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }}
    .card, table {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; }}
    .card {{ padding: 0.8rem 1rem; }}
    .card .k {{ color: var(--muted); font-size: 0.85rem; }}
    .card .v {{ font-size: 1.25rem; margin-top: 0.2rem; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ text-align: left; padding: 0.55rem 0.7rem; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ font-size: 0.78rem; letter-spacing: 0.04em; text-transform: uppercase; color: var(--muted); }}
    form.inline {{ display: inline; }}
    button, .button {{
      background: var(--accent);
      color: white;
      border: 0;
      border-radius: 8px;
      padding: 0.4rem 0.7rem;
      font: inherit;
      cursor: pointer;
    }}
    button.quiet {{ background: #efe8de; color: var(--ink); }}
    input, select {{
      font: inherit;
      padding: 0.35rem 0.5rem;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: white;
    }}
    .ok {{ color: var(--ok); }}
    .wait {{ color: var(--wait); }}
    .bad {{ color: var(--bad); }}
    .meta {{ color: var(--muted); font-size: 0.9rem; }}
    code {{ font-family: ui-monospace, monospace; font-size: 0.9em; }}
  </style>
</head>
<body>
  <header>
    <div><strong>Presidio redaction</strong> <span>admin</span></div>
    <div>{who} <span>{oid}</span></div>
  </header>
  {nav}
  <main>
    <h1>{esc(title)}</h1>
    {banner}
    {body}
  </main>
</body>
</html>
"""


def login_page() -> str:
    body = """
    <p>This portal is for Entra ID users who hold the <strong>Admin</strong> app role.</p>
    <p>Conditional Access on the admin app must require multifactor authentication.
    The portal also checks the access token: <code>amr</code> must include <code>mfa</code>
    or <code>ngcmfa</code>, and <code>acrs</code> must include the configured authentication context
    (default <code>c1</code>).</p>
    <p>MCP clients are a closed list of pre-registered Entra apps. This portal does not
    offer dynamic client registration.</p>
    <p><a class="button" href="/auth/login">Sign in with Microsoft</a></p>
    """
    return page(title="Sign in", principal=None, body=body)


def hidden(csrf: str, **fields: object) -> str:
    parts = [f"<input type='hidden' name='csrf' value='{esc(csrf)}'>"]
    for key, value in fields.items():
        parts.append(f"<input type='hidden' name='{esc(key)}' value='{esc(value)}'>")
    return "".join(parts)


def metrics_cards(item: dict[str, Any]) -> str:
    cards = [
        ("Config", "valid" if item["config_valid"] else "invalid"),
        ("Audit chain", "valid" if item["chain_valid"] else "broken"),
        ("Version", item["version_id"]),
        ("Tools on", item["tools_enabled"]),
        ("Clients", item["clients"]),
        ("Verifier", "on" if item["verifier_enabled"] else "off"),
        ("Pending approvals", item["proposals_pending"]),
        ("Score threshold", item["score_threshold"]),
    ]
    rendered = []
    for label, value in cards:
        rendered.append(f"<div class='card'><div class='k'>{esc(label)}</div><div class='v'>{esc(value)}</div></div>")
    return "<div class='grid'>" + "".join(rendered) + "</div>"
