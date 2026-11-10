import base64
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "assets" / "logo"
BG, ACCENT = "#0e1117", "#58a6ff"

# The mark is the wolf icon, not the shield-clock: the running wolf in its
# light circle comes straight from the tracked icon PNG (the same asset the
# system icons are cut from), embedded as a data URI so the SVG stays one
# self-contained file.
ICON_SRC = OUT / "greywatch-icon-256.png"
ICON_URI = "data:image/png;base64," + base64.b64encode(
    ICON_SRC.read_bytes()).decode("ascii")

BANNER_SVG = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="1200" height="340" viewBox="0 0 1200 340">
  <rect width="1200" height="340" rx="26" fill="{BG}"/>
  <rect x="1.5" y="1.5" width="1197" height="337" rx="24.5"
        fill="none" stroke="#2a3140" stroke-width="2"/>
  <!-- the wolf mark (the icon's running wolf in its light circle) -->
  <image x="56" y="42" width="256" height="256" href="{ICON_URI}"/>
  <!-- wordmark: grey in ink, watch in the accent; tagline in soft ink -->
  <text x="360" y="172" font-family="Inter" font-size="92" font-weight="700"
        fill="#dde5f2">grey<tspan fill="{ACCENT}">watch</tspan></text>
  <text x="364" y="232" font-family="Inter" font-size="27"
        fill="#8b9bb0">one dashboard for every protection on this Linux machine</text>
</svg>
"""


def banner(svg_src, dst: pathlib.Path):
    src = svg_src.with_name("greywatch-banner.svg")
    src.write_text(BANNER_SVG)
    import cairosvg
    cairosvg.svg2png(url=str(src), write_to=str(dst),
                     output_width=2400, output_height=680)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    banner(OUT / "greywatch-banner.svg", OUT / "greywatch-banner.png")
    img = ROOT / "doc" / "images"
    img.mkdir(parents=True, exist_ok=True)
    (img / "greywatch-banner.png").write_bytes(
        (OUT / "greywatch-banner.png").read_bytes())
    for p in sorted(OUT.glob("*")):
        print(p, p.stat().st_size)


if __name__ == "__main__":
    main()
