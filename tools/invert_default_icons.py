"""Invert the default greywatch icon: light disc + dark wolf.

The dark-disc icon disappears on dark themes; the art sheet's own
light-background circle (white disc, grey ring, dark wolf) is the
inverted presentation of the same mark, so it becomes the default icon
set. Re-derives it from the sheet, promotes the dark disc to a secondary
variant, and rewrites the doc/images copies.

Run from the repo root:  python3 tools/invert_default_icons.py <sheet.png>
"""
import pathlib
import sys

from PIL import Image, ImageDraw

SIZES = (16, 24, 32, 48, 64, 128, 256)


def _bbox_of(sheet, box, lo, hi):
    x0, y0, x1, y1 = box
    region = sheet.crop(box).convert("L")
    px = region.load()
    xs, ys = [], []
    for y in range(region.height):
        for x in range(region.width):
            if lo < px[x, y] < hi:
                xs.append(x); ys.append(y)
    return (x0 + min(xs), y0 + min(ys), x0 + max(xs) + 1, y0 + max(ys) + 1)


def main():
    sheet = Image.open(pathlib.Path(sys.argv[1]))
    out_dir = pathlib.Path("assets/logo")
    doc_dir = pathlib.Path("doc/images")

    # the grey ring inside the white card is the circle's true boundary
    ring = _bbox_of(sheet, (760, 70, 1070, 380), 110, 200)
    cx, cy = (ring[0] + ring[2]) / 2, (ring[1] + ring[3]) / 2
    r = max(ring[2] - ring[0], ring[3] - ring[1]) / 2 + 1
    s = int(2 * r)
    crop = sheet.crop((int(cx - r), int(cy - r), int(cx + r), int(cy + r)))
    ss = 4
    mask = Image.new("L", (s * ss, s * ss), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, s * ss - 1, s * ss - 1), fill=255)
    mask = mask.resize((s, s), Image.LANCZOS)
    master = crop.convert("RGBA")
    master.putalpha(mask)
    for size in SIZES:
        dst = out_dir / f"greywatch-icon-{size}.png"
        master.resize((size, size), Image.LANCZOS).save(dst)
        if size in (128, 256):
            (doc_dir / f"greywatch-icon-{size}.png").write_bytes(
                dst.read_bytes())

    # One mark, everywhere: the white-disc wolf set. The old dark-disc and
    # wordmark variants were removed 2026-10-30 (owner: "white wolf logo
    # only for all. remove other greywatch logos except the banner one");
    # scrub them if an older run of this tool left them behind.
    for stale in ("greywatch-icon-light-256.png",
                  "greywatch-icon-dark-256.png",
                  "greywatch-logo.png", "greywatch-logo-light.png",
                  "greywatch-logo-icon-dark.png"):
        for d in (out_dir, doc_dir):
            p = d / stale
            if p.exists():
                p.unlink()
                print("removed superseded:", p)
    print("ring:", tuple(map(int, (cx, cy, r))))


if __name__ == "__main__":
    main()