"""HTML rendering of a scan result (everything escaped; no external assets)."""
from __future__ import annotations

import html
import json
from typing import Any


def _esc(v: Any) -> str:
    return html.escape(str(v), quote=True)


def render_html(result: dict[str, Any]) -> str:
    inp, ts = result["input"], result["tamper_status"]
    rows = []
    for f in result["findings"]:
        rows.append(
            f"<tr><td>{_esc(f['rule_id'])}</td><td>{_esc(f['severity'])}</td>"
            f"<td>{'yes' if f['is_trace'] else 'no'}</td><td>{_esc(f['title'])}</td>"
            f"<td><pre>{_esc(json.dumps(f['evidence'], ensure_ascii=False, indent=1))}</pre></td>"
            f"<td>{_esc(f['interpretation'])}</td></tr>"
        )
    limits = "".join(f"<li><b>{_esc(l['family'])}</b>: {_esc(l['reason'])}</li>" for l in result["analysis_limits"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>DocForensics report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2em;max-width:1100px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:.4em;vertical-align:top;font-size:.9em}}pre{{white-space:pre-wrap;margin:0;max-height:16em;overflow:auto}}
.state{{padding:.6em;border-radius:.4em;background:#eef}}.ar{{direction:rtl;text-align:right}}</style></head><body>
<h1>DocForensics report</h1>
<p><b>File:</b> {_esc(inp['name'])} &middot; <b>SHA-256:</b> <code>{_esc(inp['sha256'])}</code> &middot;
<b>Size:</b> {inp['size_bytes']} bytes &middot; <b>Detected format:</b> {_esc(inp['detected_format'])}
({_esc(inp['format_evidence'])}) &middot; <b>Extension hint:</b> {_esc(inp['extension_hint'])}</p>
<div class="state"><h2>tamper_status: {_esc(ts['state'])}</h2>
<p class="ar">{_esc(ts['explanation_ar'])}</p><p>{_esc(ts['explanation_en'])}</p>
<p>revisions_found: {ts['revisions_found']} &middot; recovered_prior_metadata: {len(ts['recovered_prior_metadata'])}</p></div>
<h2>Findings ({len(result['findings'])})</h2>
<table><tr><th>rule</th><th>severity</th><th>trace</th><th>title</th><th>evidence (raw)</th><th>interpretation</th></tr>
{''.join(rows) or '<tr><td colspan="6">none</td></tr>'}</table>
<h2>Analysis limits</h2><ul>{limits or '<li>none</li>'}</ul>
<p><small>docforensics {_esc(result['docforensics_version'])} &middot; content-first identification &middot;
read-only scan. No state implies proof of authenticity.</small></p>
</body></html>"""
