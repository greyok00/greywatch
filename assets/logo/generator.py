import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]   # .../logo/generator.py → greywatch root
OUT = ROOT / "assets" / "logo"
BG, PANEL, ACCENT = "#0e1117", "#161b22", "#58a6ff"
INK = "#c9d1d9"

SVG = f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{ACCENT}"/>
      <stop offset="1" stop-color="{ACCENT}" stop-opacity="0.55"/>
    </linearGradient>
  </defs>
  <!-- shield -->
  <path d="M128 18 L226 52 V132 C226 190 182 224 128 240 C74 224 30 190 30 132 V52 Z"
        fill="{PANEL}" stroke="url(#g)" stroke-width="10"/>
  <!-- watch face -->
  <circle cx="128" cy="126" r="64" fill="{BG}" stroke="{ACCENT}" stroke-width="8"/>
  <path d="M128 88 V126 L158 142" stroke="{INK}" stroke-width="8"
        stroke-linecap="round" fill="none"/>
  <circle cx="128" cy="126" r="6" fill="{ACCENT}"/>
  <!-- GW -->
  <text x="128" y="230" font-family="monospace" font-size="34" font-weight="700"
        fill="{ACCENT}" text-anchor="middle">GW</text>
</svg>
"""

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


def write_svg(path: pathlib.Path):
    path.write_text(SVG)


def png_from(svg: pathlib.Path, size: int, dst: pathlib.Path):
    import cairosvg
    cairosvg.svg2png(url=str(svg), write_to=str(dst),
                     output_width=size, output_height=size)


def banner(svg_src, dst: pathlib.Path):
    src = svg_src.with_name("greywatch-banner.svg")
    src.write_text(BANNER_SVG)
    import cairosvg
    cairosvg.svg2png(url=str(src), write_to=str(dst),
                     output_width=2400, output_height=680)


def install_icon(png: pathlib.Path):
    base = pathlib.Path.home() / ".local/share/icons/hicolor"
    subprocess.run(["convert", "-background", "none", str(png),
                    "-resize", "128x128",
                    str(base / "128x128/actions/greywatch.png")], check=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    svg = OUT / "greywatch-logo.svg"
    write_svg(svg)
    for size in (128, 256, 512):
        png_from(svg, size, OUT / f"greywatch-icon-{size}.png")
    banner(svg, OUT / "greywatch-banner.png")
    img = ROOT / "doc" / "images"
    img.mkdir(parents=True, exist_ok=True)
    for name in ("greywatch-banner.png", "greywatch-icon-128.png",
                 "greywatch-icon-256.png", "greywatch-icon-512.png"):
        png = OUT / name
        if png.exists():
            (img / name).write_bytes(png.read_bytes())
    inst = pathlib.Path.home() / ".local/share/icons/hicolor/128x128/actions"
    inst.mkdir(parents=True, exist_ok=True)
    install_icon(OUT / "greywatch-icon-256.png")
    for p in sorted(OUT.glob("*")):
        print(p, p.stat().st_size)
    subprocess.run(["gtk-update-icon-cache", "-q",
                    str(pathlib.Path.home() / ".local/share/icons/hicolor")],
                   capture_output=True)
    print("icon installed to hicolor 128x128/actions/greywatch.png")


if __name__ == "__main__":
    main()
