#!/usr/bin/env python3
"""Rasterize the console SVGs to PNG and cut the feature crops.

Depends only on Pillow. This renders the primitive subset the generator emits
(rect, line, circle, text, path) -- it is a purpose-built companion to
gen_mockup.py, not a general SVG renderer. Run after `make mockup`:

    python3 docs/rasterize.py

Outputs docs/console.png, docs/console-attack.png, docs/decisions.png,
docs/controls.png.
"""
import json, re, os
from PIL import Image, ImageDraw, ImageFont

SCALE = 2
FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
_fonts = {}

def font(size, weight):
    key = (round(size * SCALE), weight >= 600)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(FONT_BOLD if weight >= 600 else FONT_REG, max(6, key[0]))
    return _fonts[key]

def _attrs(s):
    return dict(re.findall(r'([\w-]+)="([^"]*)"', s))

def rasterize(svg_path, png_path):
    svg = open(svg_path).read()
    vb = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    W, H = float(vb.group(1)), float(vb.group(2))
    img = Image.new("RGB", (int(W * SCALE), int(H * SCALE)), "#0B1017")
    d = ImageDraw.Draw(img)
    S = lambda v: float(v) * SCALE

    for m in re.finditer(r'<(rect|line|circle|path)\b([^>]*?)/>|<text\b([^>]*?)>(.*?)</text>', svg, re.S):
        if m.group(1):
            kind, a = m.group(1), _attrs(m.group(2))
            if kind == "rect":
                x, y = S(a.get("x", 0)), S(a.get("y", 0))
                w, h, r = S(a.get("width", 0)), S(a.get("height", 0)), S(a.get("rx", 0))
                box = [x, y, x + w, y + h]
                fill = a.get("fill", "none")
                if fill and fill != "none":
                    (d.rounded_rectangle(box, radius=r, fill=fill) if r > 0
                     else d.rectangle(box, fill=fill))
                st = a.get("stroke")
                if st and st != "none":
                    (d.rounded_rectangle(box, radius=r, outline=st, width=SCALE) if r > 0
                     else d.rectangle(box, outline=st, width=SCALE))
            elif kind == "line":
                d.line([S(a["x1"]), S(a["y1"]), S(a["x2"]), S(a["y2"])],
                       fill=a.get("stroke", "#fff"), width=SCALE)
            elif kind == "circle":
                cx, cy, r = S(a["cx"]), S(a["cy"]), S(a["r"])
                d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=a.get("fill", "#fff"))
            elif kind == "path":
                p = [float(v) for v in re.findall(r'-?[\d.]+', a.get("d", ""))]
                if len(p) >= 6:
                    x0, y0 = S(p[0]), S(p[1])
                    x1, y1 = x0 + S(p[2]), y0 + S(p[3])
                    x2, y2 = x1 + S(p[4]), y1 + S(p[5])
                    d.line([x0, y0, x1, y1, x2, y2], fill=a.get("stroke", "#fff"),
                           width=max(1, int(SCALE * 1.8)), joint="curve")
        else:
            a = _attrs(m.group(3))
            body = re.sub(r"<[^>]+>", "", m.group(4))
            for ent, ch in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&#8212;", "—")]:
                body = body.replace(ent, ch)
            f = font(float(a.get("font-size", 12)), int(a.get("font-weight", 400)))
            x, y = S(a.get("x", 0)), S(a.get("y", 0))
            fill = a.get("fill", "#fff")
            sp = float(a.get("letter-spacing", 0) or 0) * SCALE
            width = (sum(d.textlength(c, font=f) + sp for c in body) - sp) if sp else d.textlength(body, font=f)
            anchor = a.get("text-anchor", "start")
            if anchor == "end":
                x -= width
            elif anchor == "middle":
                x -= width / 2
            if sp:
                cx = x
                for c in body:
                    d.text((cx, y), c, font=f, fill=fill, anchor="ls")
                    cx += d.textlength(c, font=f) + sp
            else:
                d.text((x, y), body, font=f, fill=fill, anchor="ls")

    img.save(png_path)
    return img

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    docs = os.path.join(root, "docs")
    regions = json.load(open(os.path.join(docs, "regions.json")))

    imgs = {}
    for name in ("console", "console-attack"):
        imgs[name] = rasterize(os.path.join(docs, f"{name}.svg"), os.path.join(docs, f"{name}.png"))
        print(f"wrote docs/{name}.png {imgs[name].size}")

    # feature crops: the decision strip (from the attack state, more telling) and
    # the controls band (from the steady state).
    crops = [("console-attack", "decisions", "decisions.png"),
             ("console", "controls", "controls.png")]
    for src, region, out in crops:
        x, y, w, h = regions[src][region]
        box = (int(x * SCALE), int(y * SCALE), int((x + w) * SCALE), int((y + h) * SCALE))
        imgs[src].crop(box).save(os.path.join(docs, out))
        print(f"wrote docs/{out} {(box[2]-box[0], box[3]-box[1])}")

if __name__ == "__main__":
    main()
