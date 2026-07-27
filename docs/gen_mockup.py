#!/usr/bin/env python3
"""Render the GoWAFyourself console to SVG in two operational states.

Kept as a script (rather than hand-written SVG) because the decision strip is
120 individual ticks and there are several states to keep consistent. Colours
and metrics mirror the shipped template in internal/panel/templates.go, so the
mockups stay honest to the real console. Regenerate with `make mockup` after a
design change; rasterize to PNG with docs/rasterize.py.

Outputs:
  docs/console.svg          steady-state operation
  docs/console-attack.svg   under an active attack
  docs/regions.json         crop boxes used to cut feature shots
"""
import json, os, random

# --- design tokens: identical to the CSS variables in the console template ---
BG, SURFACE, SURFACE2, LINE = "#0B1017", "#131B26", "#1A2432", "#22303F"
TEXT, DIM = "#E3ECF5", "#8296AB"
SIGNAL, PASS, WARN, ALARM = "#4FC3E8", "#43D9A3", "#F2B75C", "#FF5D6C"
TICK = {"allow": ("#2C6B57", 0.26), "detect": (WARN, 0.64),
        "block": (ALARM, 1.00), "shed": ("#3E4E60", 0.46), "error": ("#8C3B45", 0.80)}
MONO = "ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace"

W, H = 1120, 1132
M = 44                       # page margin
CW = W - 2 * M               # content width

# module state, reset per render
_out, _regions = [], {}
def add(s): _out.append(s)

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def rect(x, y, w, h, fill, rx=0, stroke=None, sw=1, opacity=None):
    o = f' opacity="{opacity}"' if opacity is not None else ""
    s = f' stroke="{stroke}" stroke-width="{sw}"' if stroke else ""
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{s}{o}/>')

def text(x, y, s, fill=TEXT, size=12, weight=400, anchor="start", spacing=None, opacity=None):
    ls = f' letter-spacing="{spacing}"' if spacing else ""
    op = f' opacity="{opacity}"' if opacity is not None else ""
    add(f'<text x="{x}" y="{y}" fill="{fill}" font-family="{MONO}" font-size="{size}" '
        f'font-weight="{weight}" text-anchor="{anchor}"{ls}{op}>{esc(s)}</text>')

def label(x, y, s):
    text(x, y, s.upper(), fill=DIM, size=9.5, weight=500, spacing="1.4")

def pill(x, y, s, color, border, bg=None, pad=11):
    w = len(s) * 6.3 + pad * 2
    rect(x, y, w, 21, bg if bg else "none", rx=2, stroke=border)
    text(x + pad, y + 14.5, s.upper(), fill=color, size=9.5, weight=500, spacing="0.9")
    return w

def card(x, y, w, h):
    rect(x, y, w, h, SURFACE, rx=3, stroke=LINE)

def button(x, y, s, color=TEXT, border=LINE, pad=13, h=27):
    w = len(s) * 6.35 + pad * 2
    rect(x, y, w, h, SURFACE2, rx=2, stroke=border)
    text(x + pad, y + h / 2 + 4, s, fill=color, size=11.5)
    return w


# --------------------------------------------------------------------------
# traffic patterns for the decision strip
# --------------------------------------------------------------------------
def strip_steady():
    random.seed(7)
    seq = []
    for i in range(120):
        if 46 <= i <= 62:                       # a scanner earlier in the window
            seq.append(random.choice(["block", "block", "block", "detect", "allow"]))
        elif 88 <= i <= 93:                     # a brief overload
            seq.append(random.choice(["shed", "shed", "allow"]))
        elif random.random() < 0.055:
            seq.append(random.choice(["detect", "block", "error"]))
        else:
            seq.append("allow")
    return seq

def strip_attack():
    random.seed(11)
    seq = []
    for i in range(120):
        if i >= 90:                             # sustained assault at the newest edge
            seq.append(random.choice(["block", "block", "block", "block", "detect", "error"]))
        elif 68 <= i <= 84:                     # ramping up
            seq.append(random.choice(["block", "detect", "block", "allow"]))
        elif random.random() < 0.09:
            seq.append(random.choice(["detect", "block"]))
        else:
            seq.append("allow")
    return seq


# --------------------------------------------------------------------------
# scenarios: only the things that actually change between states
# --------------------------------------------------------------------------
def counter_color(key):
    return {"alarm": ALARM, "warn": WARN}.get(key, TEXT)

STEADY = dict(
    title="127.0.0.1:9000",
    mode="block", bridge=False,
    strip=strip_steady(),
    capacity=dict(inflight="34", limit="256", queued="0", queuecap="512", frac=0.13, qfrac=0.0),
    counters=[
        ("128,431", "requests", ""), ("1,204", "blocked", "alarm"),
        ("37", "blocked (resp)", ""), ("512", "detected", "warn"),
        ("34", "in flight", ""), ("0", "queued", ""),
        ("88", "shed", "warn"), ("12", "upstream errs", "alarm"),
        ("3", "no route", ""), ("0", "bridged", ""),
        ("0", "waf panics", ""), ("0", "logs dropped", ""),
    ],
    backends=[("http://10.0.3.11:8080", "closed"), ("http://10.0.3.12:8080", "closed"),
              ("http://10.0.4.20:8080", "closed"), ("http://10.0.4.21:8080", "closed")],
    uptime="6d 04h",
)

ATTACK = dict(
    title="127.0.0.1:9000",
    mode="block", bridge=False,
    strip=strip_attack(),
    capacity=dict(inflight="212", limit="256", queued="47", queuecap="512", frac=0.83, qfrac=0.09),
    counters=[
        ("141,802", "requests", ""), ("9,540", "blocked", "alarm"),
        ("214", "blocked (resp)", "alarm"), ("3,120", "detected", "warn"),
        ("212", "in flight", "warn"), ("47", "queued", "warn"),
        ("1,880", "shed", "warn"), ("640", "upstream errs", "alarm"),
        ("8", "no route", ""), ("0", "bridged", ""),
        ("0", "waf panics", ""), ("156", "logs dropped", "warn"),
    ],
    backends=[("http://10.0.3.11:8080", "closed"), ("http://10.0.3.12:8080", "closed"),
              ("http://10.0.4.20:8080", "open"), ("http://10.0.4.21:8080", "half-open")],
    uptime="6d 11h",
)

STATE_COLOR = {"closed": PASS, "open": ALARM, "half-open": WARN}


def render(sc):
    """Render one scenario, returning (svg_string, regions_dict)."""
    _out.clear(); _regions.clear()

    add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        f'font-family="{MONO}" role="img" aria-label="GoWAFyourself control console">')
    rect(0, 0, W, H, BG)

    # browser chrome so this reads as a screenshot
    rect(0, 0, W, 38, "#0E141C")
    add(f'<line x1="0" y1="38" x2="{W}" y2="38" stroke="{LINE}" stroke-width="1"/>')
    for i, c in enumerate([ALARM, WARN, PASS]):
        add(f'<circle cx="{22 + i * 17}" cy="19" r="5" fill="{c}" opacity="0.55"/>')
    rect(84, 10, 300, 19, SURFACE2, rx=3, stroke=LINE)
    text(95, 23.5, sc["title"], fill=DIM, size=10.5)
    text(W - M, 23.5, "GoWAFyourself console", fill=DIM, size=10.5, anchor="end")

    y = 78

    # wordmark
    MK, ADV = 21, 21 * 0.6
    text(M, y, "Go", fill=DIM, size=MK, weight=700)
    text(M + 2 * ADV, y, "WAF", fill=SIGNAL, size=MK, weight=700)
    text(M + 5 * ADV, y, "yourself", fill=TEXT, size=MK, weight=700)
    text(M + 13 * ADV + 22, y - 1, "WEB APPLICATION FIREWALL", fill=DIM, size=9.5, spacing="1.6")

    # status pills
    if sc["bridge"]:
        btxt, bcol, bbord, bbg = "bridge open — waf skipped", ALARM, "#5C2A31", "#1E1116"
    else:
        btxt, bcol, bbord, bbg = "bridge closed", DIM, LINE, None
    pw2 = len(btxt) * 6.3 + 22
    mtxt = f"mode: {sc['mode']}"
    mcol = {"block": PASS, "detect": WARN, "off": DIM}[sc["mode"]]
    mbord = {"block": "#2A5B49", "detect": "#5C4A29", "off": LINE}[sc["mode"]]
    pw1 = len(mtxt) * 6.3 + 22
    pill(W - M - pw2, y - 15, btxt, bcol, bbord, bbg)
    pill(W - M - pw2 - pw1 - 8, y - 15, mtxt, mcol, mbord)

    y += 26

    # ---- decision strip (signature) ----
    _regions["decisions"] = [M - 6, y - 6, CW + 12, 132 + 12]
    card(M, y, CW, 132)
    text(M + 18, y + 26, "DECISIONS", fill=DIM, size=10.5, weight=600, spacing="1.5")
    text(M + 108, y + 26, "newest right", fill=DIM, size=10.5, opacity=0.75)
    text(M + CW - 18, y + 26, "last 120 requests", fill=DIM, size=10.5, anchor="end")

    sx, sy, sh = M + 18, y + 44, 48
    gap, tw = 1.3, 7.0
    for i, v in enumerate(sc["strip"]):
        color, frac = TICK[v]
        th = sh * frac
        add(f'<rect x="{sx + i * (tw + gap):.1f}" y="{sy + sh - th:.1f}" width="{tw}" '
            f'height="{th:.1f}" rx="1" fill="{color}"/>')
    add(f'<line x1="{sx}" y1="{sy + sh + 1}" x2="{M + CW - 18}" y2="{sy + sh + 1}" stroke="{LINE}"/>')

    lx = sx
    for name, key in [("allowed", "allow"), ("detected", "detect"), ("blocked", "block"),
                      ("shed", "shed"), ("upstream error", "error")]:
        rect(lx, sy + sh + 14, 8, 8, TICK[key][0], rx=1)
        text(lx + 13, sy + sh + 21.5, name, fill=DIM, size=10.5)
        lx += 13 + len(name) * 6.3 + 22

    y += 132 + 22

    # ---- counters ----
    cols, gh = 6, 62
    cwid = (CW - (cols - 1)) / cols
    rect(M, y, CW, gh * 2 + 1, LINE, rx=3)
    for i, (n, l, ck) in enumerate(sc["counters"]):
        cx = M + (i % cols) * (cwid + 1)
        cy = y + (i // cols) * (gh + 1)
        rect(cx, cy, cwid, gh, SURFACE)
        text(cx + 13, cy + 30, n, fill=counter_color(ck), size=19, weight=600)
        label(cx + 13, cy + 47, l)

    y += gh * 2 + 1 + 30

    # ---- controls band (enforcement / capacity / bridge / inspection) ----
    _regions["controls"] = [M - 6, y - 24, CW + 12, 0]  # height filled in below
    colw = (CW - 20) / 2
    lx, rx_ = M, M + colw + 20

    label(lx, y, "enforcement")
    card(lx, y + 10, colw, 92)
    modes = [("Block traffic", "block"), ("Detect only", "detect"), ("Turn WAF off", "off")]
    bx = lx + 16
    for lbl, mk in modes:
        active = sc["mode"] == mk
        bx += button(bx, y + 26, lbl,
                     PASS if active else TEXT,
                     "#2A5B49" if active else LINE) + 8
    text(lx + 16, y + 82, "Detect logs what it would have blocked and lets it", fill=DIM, size=10.5)
    text(lx + 16, y + 95, "through. Off skips inspection entirely.", fill=DIM, size=10.5)

    cap = sc["capacity"]
    label(rx_, y, "capacity")
    card(rx_, y + 10, colw, 92)
    text(rx_ + 16, y + 32, "In flight", fill=DIM, size=11)
    text(rx_ + colw - 16, y + 32, f"{cap['inflight']} / {cap['limit']}", fill=TEXT, size=11, anchor="end")
    rect(rx_ + 16, y + 40, colw - 32, 6, SURFACE2, rx=1)
    if cap["frac"] > 0:
        rect(rx_ + 16, y + 40, (colw - 32) * cap["frac"], 6,
             ALARM if cap["frac"] > 0.8 else SIGNAL, rx=1)
    text(rx_ + 16, y + 68, "Queued", fill=DIM, size=11)
    text(rx_ + colw - 16, y + 68, f"{cap['queued']} / {cap['queuecap']}", fill=TEXT, size=11, anchor="end")
    rect(rx_ + 16, y + 76, colw - 32, 6, SURFACE2, rx=1)
    if cap["qfrac"] > 0:
        rect(rx_ + 16, y + 76, (colw - 32) * cap["qfrac"], 6, WARN, rx=1)

    y += 118

    label(lx, y, "bridge")
    card(lx, y + 10, colw, 104)
    if sc["bridge"]:
        text(lx + 16, y + 34, "Traffic is bypassing the WAF and going", fill=TEXT, size=11.5)
        text(lx + 16, y + 50, "straight to your backends.", fill=TEXT, size=11.5)
        button(lx + 16, y + 72, "Close bridge — put the WAF back inline", PASS, "#2A5B49")
    else:
        text(lx + 16, y + 34, "The WAF is inline. Open the bridge to pass", fill=TEXT, size=11.5)
        text(lx + 16, y + 50, "traffic through untouched if inspection is", fill=TEXT, size=11.5)
        text(lx + 16, y + 66, "causing trouble.", fill=TEXT, size=11.5)
        button(lx + 16, y + 76, "Open bridge — skip the WAF", ALARM, "#5C2A31")

    label(rx_, y, "inspection")
    card(rx_, y + 10, colw, 104)
    for i, (name, on) in enumerate([("Inspect request bodies", True),
                                    ("Inspect responses", True),
                                    ("Inspect response bodies", False)]):
        cy = y + 32 + i * 22
        rect(rx_ + 16, cy - 9, 12, 12, "#16382E" if on else SURFACE2, rx=2,
             stroke=PASS if on else LINE)
        if on:
            add(f'<path d="M {rx_+19} {cy-3.5} l 2.6 2.8 l 5.2 -6" fill="none" '
                f'stroke="{PASS}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>')
        text(rx_ + 36, cy + 1, name, fill=TEXT, size=11.5)
    text(rx_ + 16, y + 96, "Paranoia 1 · anomaly threshold 5", fill=DIM, size=10.5)

    y += 130
    _regions["controls"][3] = (y - 8) - _regions["controls"][1]

    # ---- backends ----
    label(M, y, "backends")
    rows = sc["backends"]
    bh = 34 + len(rows) * 26 + 12
    card(M, y + 10, CW, bh)
    label(M + 16, y + 34, "backend")
    label(M + 420, y + 34, "circuit")
    add(f'<line x1="{M+16}" y1="{y+42}" x2="{M+CW-16}" y2="{y+42}" stroke="{LINE}"/>')
    for i, (b, st) in enumerate(rows):
        ry = y + 62 + i * 26
        text(M + 16, ry, b, fill=SIGNAL, size=11.5)
        text(M + 420, ry, st, fill=STATE_COLOR[st], size=11.5)
        if i < len(rows) - 1:
            add(f'<line x1="{M+16}" y1="{ry+9}" x2="{M+CW-16}" y2="{ry+9}" stroke="{LINE}" opacity="0.6"/>')

    y += bh + 32

    # ---- upstreams (config, identical across states) ----
    label(M, y, "upstreams")
    ups = [("shop.example.com", ["http://10.0.3.11:8080", "http://10.0.3.12:8080"], "global", "closed"),
           ("api.example.com", ["http://10.0.4.20:8080", "http://10.0.4.21:8080"], "detect", "closed"),
           ("legacy.example.com", ["http://10.0.5.9:8080"], "off", "open")]
    uh = 34 + sum(26 + 16 * (len(t) - 1) for _, t, _, _ in ups) + 74
    card(M, y + 10, CW, uh)
    label(M + 16, y + 34, "host — point a cname or a record here")
    label(M + 420, y + 34, "targets")
    label(M + 730, y + 34, "mode")
    label(M + 830, y + 34, "bridge")
    add(f'<line x1="{M+16}" y1="{y+42}" x2="{M+CW-16}" y2="{y+42}" stroke="{LINE}"/>')
    ry = y + 62
    for host, targets, mode, br in ups:
        text(M + 16, ry, host, fill=SIGNAL, size=11.5)
        for j, tgt in enumerate(targets):
            text(M + 420, ry + j * 16, tgt, fill=SIGNAL, size=11, opacity=0.85)
        text(M + 730, ry, mode, fill=DIM if mode == "global" else TEXT, size=11.5)
        text(M + 830, ry, br, fill=ALARM if br == "open" else DIM, size=11.5)
        button(M + CW - 90, ry - 15, "Remove", DIM, LINE, pad=10, h=23)
        ry += 26 + 16 * (len(targets) - 1)
        add(f'<line x1="{M+16}" y1="{ry-16}" x2="{M+CW-16}" y2="{ry-16}" stroke="{LINE}" opacity="0.6"/>')

    fy = ry + 4
    label(M + 16, fy, "host")
    rect(M + 16, fy + 6, 210, 28, SURFACE2, rx=2, stroke=LINE)
    text(M + 27, fy + 25, "app.example.com", fill=DIM, size=11.5, opacity=0.6)
    label(M + 240, fy, "target")
    rect(M + 240, fy + 6, 250, 28, SURFACE2, rx=2, stroke=LINE)
    text(M + 251, fy + 25, "http://127.0.0.1:3000", fill=DIM, size=11.5, opacity=0.6)
    button(M + 504, fy + 6, "Add upstream", SIGNAL, "#2A4A5B", h=28)

    y += uh + 26

    # ---- footer ----
    add(f'<line x1="{M}" y1="{y}" x2="{M+CW}" y2="{y}" stroke="{LINE}"/>')
    foot = [("http", ":8080"), ("https", ":8443 (acme)"), ("console", "127.0.0.1:9000"),
            ("logs", "both"), ("up", sc["uptime"])]
    fx = M
    for k, v in foot:
        text(fx, y + 20, k, fill=DIM, size=10.5)
        text(fx + len(k) * 6.3 + 8, y + 20, v, fill=SIGNAL, size=10.5)
        fx += len(k) * 6.3 + 8 + len(v) * 6.3 + 26

    add('</svg>')
    return "\n".join(_out), dict(_regions)


def main():
    os.makedirs("docs", exist_ok=True)
    regions = {}
    for name, sc in [("console", STEADY), ("console-attack", ATTACK)]:
        svg, reg = render(sc)
        with open(f"docs/{name}.svg", "w") as f:
            f.write(svg)
        regions[name] = reg
        print(f"wrote docs/{name}.svg ({len(sc['strip'])} ticks)")
    with open("docs/regions.json", "w") as f:
        json.dump(regions, f, indent=2)
    print("wrote docs/regions.json")


if __name__ == "__main__":
    main()
