import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "assets" / "logo"
BG, PANEL, ACCENT = "#0e1117", "#161b22", "#58a6ff"
INK = "#c9d1d9"

BANNER_SVG = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="340" viewBox="0 0 1200 340">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{ACCENT}"/>
      <stop offset="1" stop-color="{ACCENT}" stop-opacity="0.55"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="340" rx="26" fill="{BG}"/>
  <rect x="1.5" y="1.5" width="1197" height="337" rx="24.5"
        fill="none" stroke="#2a3140" stroke-width="2"/>
  <!-- shield, slightly left-of-center at half scale of the icon -->
  <g transform="translate(52,34) scale(1.06)">
    <path d="M128 18 L226 52 V132 C226 190 182 224 128 240
             C74 224 30 190 30 132 V52 Z"
          fill="{PANEL}" stroke="url(#g)" stroke-width="10"/>
    <circle cx="128" cy="126" r="64" fill="{BG}" stroke="{ACCENT}" stroke-width="8"/>
    <path d="M128 88 V126 L158 142" stroke="{INK}" stroke-width="8"
          stroke-linecap="round" fill="none"/>
    <circle cx="128" cy="126" r="6" fill="{ACCENT}"/>
  </g>
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
