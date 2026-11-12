#!/usr/bin/env python3
"""Record the tool's real terminal output into an animated docs/demo.svg.

Every step in tools/demo.json is executed for real (colours forced on), its
ANSI output is converted to styled text, and the session is played back as a
"filmstrip": each frame is a stack of <use> references to de-duplicated line
definitions, stepped through with a CSS keyframe animation. Nothing in the
demo is hand-written.

Usage: python3 tools/gen_demo.py            (run from the repository root)
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "tools" / "demo.json").read_text())

sys.path.insert(0, str(Path.home() / "github-profile" / "scripts"))
try:
    from brand import finish  # type: ignore  # embeds a JetBrains Mono subset
except Exception:  # pragma: no cover
    def finish(svg, faces=None):
        return svg

MONO = "'JBM','JetBrains Mono',ui-monospace,Consolas,Menlo,monospace"
PAL = {
    "text": "#C5CFDD", "dim": "#7C8AA0", "red": "#F87171", "green": "#34D399",
    "amber": "#FBBF24", "cyan": "#22D3EE", "blue": "#60A5FA", "white": "#F1F5FB",
    "crit": "#FFFFFF",
}
CW, FS, LH = 7.8, 13, 20
COLS = CFG.get("cols", 118)
ROWS = CFG.get("rows", 30)
VIEW_W, VIEW_H = int(COLS * CW) + 4, ROWS * LH + 6
W, H = VIEW_W + 36, VIEW_H + 76
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def parse_ansi(line):
    """-> list of (text, colour, bold, critical-background)."""
    segs, color, bold, dim, bg = [], "text", False, False, False
    pos = 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            segs.append((line[pos:m.start()], "dim" if dim and color == "text" else color, bold, bg))
        for code in (m.group(1) or "0").split(";"):
            c = int(code or 0)
            if c == 0:
                color, bold, dim, bg = "text", False, False, False
            elif c == 1:
                bold = True
            elif c == 2:
                dim = True
            elif c == 22:
                bold = dim = False
            elif c == 31 or c == 91:
                color = "red"
            elif c == 32 or c == 92:
                color = "green"
            elif c == 33 or c == 93:
                color = "amber"
            elif c == 36 or c == 96:
                color = "cyan"
            elif c == 34 or c == 94:
                color = "blue"
            elif c == 37 or c == 97:
                color = "white"
            elif c == 39:
                color = "text"
            elif c == 41:
                bg = True
            elif c == 49:
                bg = False
        pos = m.end()
    if pos < len(line):
        segs.append((line[pos:], "dim" if dim and color == "text" else color, bold, bg))
    return segs


def clip(segs, cols):
    out, n = [], 0
    for t, c, b, bg in segs:
        if n >= cols:
            break
        t = t[: cols - n]
        out.append((t, c, b, bg))
        n += len(t)
    return out


def prompt_segs(cmd):
    p = CFG["prompt"]
    return [(p["user"], "cyan", True, False), (":", "text", False, False),
            (p["path"], "blue", False, False), ("$ ", "text", False, False),
            (cmd, "white", False, False)]


def run(step):
    env = dict(os.environ, CLICOLOR_FORCE="1", COLUMNS=str(COLS))
    env.update(CFG.get("env", {}))
    r = subprocess.run(step["run"], shell=True, cwd=ROOT, env=env, capture_output=True, text=True)
    lines = (r.stdout + r.stderr).rstrip("\n").split("\n")
    if step.get("skip_blank_head"):
        while lines and not lines[0].strip():
            lines.pop(0)
    if "head" in step:
        lines = lines[: step["head"]]
    return [clip(parse_ansi(l.replace("\t", "    ")), COLS) for l in lines]


def build():
    screen, frames, durs = [], [], []

    def snap(d, extra=None):
        frames.append(screen[-ROWS:] if extra is None else (screen + [extra])[-ROWS:])
        durs.append(d)

    for step in CFG["steps"]:
        cmd = step["show"]
        for i in range(0, len(cmd) + 1, 2):
            snap(1, prompt_segs(cmd[:i] + "█"))
        snap(6, prompt_segs(cmd))
        screen.append(prompt_segs(cmd))
        out = run(step)
        chunk = step.get("chunk", 2)
        for i in range(0, len(out), chunk):
            screen.extend(out[i:i + chunk])
            snap(step.get("speed", 1))
        snap(step.get("hold", 30))
        screen.append([])
    snap(50, prompt_segs("█"))
    return frames, durs


def render():
    frames, durs = build()
    line_ids, defs = {}, []

    def lid(segs):
        key = tuple(segs)
        if key not in line_ids:
            n = len(line_ids)
            line_ids[key] = n
            parts, x = [f'<g id="l{n}">'], 0.0
            for t, c, b, bg in segs:
                if not t:
                    continue
                w = len(t) * CW
                if bg:
                    parts.append(f'<rect x="{x:.1f}" y="-14" width="{w:.1f}" height="18" fill="#B91C1C"/>')
                fill = PAL["crit"] if bg else PAL[c]
                wt = ' font-weight="700"' if b or bg else ""
                if t.strip():
                    parts.append(f'<text x="{x:.1f}" fill="{fill}"{wt} textLength="{w:.1f}" '
                                 f'lengthAdjust="spacingAndGlyphs">{escape(t)}</text>')
                x += w
            parts.append("</g>")
            defs.append("".join(parts))
        return line_ids[key]

    strip = []
    for i, fr in enumerate(frames):
        uses = "".join(f'<use href="#l{lid(seg)}" y="{16 + j * LH}"/>' for j, seg in enumerate(fr) if seg)
        strip.append(f'<g transform="translate(0,{i * VIEW_H})">{uses}</g>')

    total = sum(durs)
    cum, stops = 0, []
    for i, d in enumerate(durs):
        stops.append(f"{cum / total * 100:.3f}%{{transform:translateY(-{i * VIEW_H}px)}}")
        cum += d
    last = (len(durs) - 1) * VIEW_H
    stops.append(f"100%{{transform:translateY(-{last}px)}}")
    secs = max(12, round(total * 0.07))
    css = ("@keyframes play{" + "".join(stops) + "}"
           f".strip{{animation:play {secs}s steps(1,end) infinite}}"
           f"@media(prefers-reduced-motion){{.strip{{animation:none;transform:translateY(-{last}px)}}}}")

    title = escape(CFG["title"])
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
        f'role="img" aria-label="{title}">'
        f'<style>{css}</style><defs>{"".join(defs)}</defs>'
        f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="12" fill="#111826" stroke="#1E2A3D"/>'
        f'<path d="M0 40H{W}" stroke="#1E2A3D"/>'
        '<circle cx="24" cy="20" r="6" fill="#FF5F57"/><circle cx="44" cy="20" r="6" fill="#FEBC2E"/>'
        '<circle cx="64" cy="20" r="6" fill="#28C840"/>'
        f'<text x="{W / 2:.0f}" y="25" text-anchor="middle" fill="#8B98AD" font-family="{MONO}" font-size="13">{title}</text>'
        f'<svg x="18" y="54" width="{VIEW_W}" height="{VIEW_H}" viewBox="0 0 {VIEW_W} {VIEW_H}" overflow="hidden">'
        f'<g class="strip" font-family="{MONO}" font-size="{FS}" xml:space="preserve">{"".join(strip)}</g>'
        '</svg></svg>\n')
    return finish(svg, {("JBM", 400), ("JBM", 700)}), len(frames)


if __name__ == "__main__":
    out, n = render()
    p = ROOT / "docs" / "demo.svg"
    p.write_text(out, encoding="utf-8")
    print(f"wrote {p} ({len(out) // 1024} KB, {n} frames)")
