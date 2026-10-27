"""Extract the greywatch icon set from the wolf-art sheet on the Desktop.

One-off derivation tool (local only — the sheet itself is not part of the
repo). Locates the "app icon" ring and the light-background card by
brightness, crops with a supersampled circle/rounded-rect mask, writes the
hicolor size ladder into assets/logo + the doc/images copy. Run from the
repo root:  python3 tools/icons_from_sheet.py <sheet.png>
"""
import pathlib
import sys

from PIL import Image, ImageDraw

SIZES = (16, 24, 32, 48, 64, 128, 256)


def _bbox_of(sheet, box, thresh):
    """bbox of pixels brighter than thresh inside box, in sheet coords."""
    x0, y0, x1, y1 = box
    region = sheet.crop(box).convert("L")
    px = region.load()
    xs, ys = [], []
    for y in range(region.height):
        for x in range(region.width):
            if px[x, y] > thresh:
                xs.append(x); ys.append(y)
    return (x0 + min(xs), y0 + min(ys), x0 + max(xs) + 1, y0 + max(ys) + 1)


def circle_icon(sheet, box, out_dir, out_name, doc_dir):
    ring = _bbox_of(sheet, box, 40)
    cx, cy = (ring[0] + ring[2]) / 2, (ring[1] + ring[3]) / 2
    r = max(ring[2] - ring[0], ring[3] - ring[1]) / 2 + 1
    s = int(2 * r)
    crop = sheet.crop((int(cx - r), int(cy - r), int(cx + r), int(cy + r)))
    # supersampled circular alpha: corners outside the ring go transparent
    ss = 4
    mask = Image.new("L", (s * ss, s * ss), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, s * ss - 1, s * ss - 1), fill=255)
    mask = mask.resize((s, s), Image.LANCZOS)
    master = crop.convert("RGBA")
    master.putalpha(mask)
    for size in SIZES:
        dst = out_dir / f"greywatch-icon-{size}.png"
        master.resize((size, size), Image.LANCZOS).save(dst)
        if size == 128:
            (doc_dir / "greywatch-icon-128.png").write_bytes(dst.read_bytes())
    print("circle:", tuple(map(int, (cx, cy, r))), "->", out_name)


def light_icon(sheet, box, out_dir, doc_dir):
    card = _bbox_of(sheet, box, 200)
    crop = sheet.crop(card).convert("RGBA")
    w = crop.width
    ss = 4
    mask = Image.new("L", (w * ss, w * ss), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, w * ss - 1, w * ss - 1), radius=w * ss // 10, fill=255)
    crop = crop.resize((w, w), Image.LANCZOS)
    crop.putalpha(mask.resize((w, w), Image.LANCZOS))
    dst = out_dir / "greywatch-icon-light-256.png"
    crop.resize((256, 256), Image.LANCZOS).save(dst)
    (doc_dir / "greywatch-icon-light-256.png").write_bytes(dst.read_bytes())
    print("light card:", card)


def main():
    sheet_path = pathlib.Path(sys.argv[1])
    sheet = Image.open(sheet_path)
    out_dir = pathlib.Path("assets/logo")
    doc_dir = pathlib.Path("doc/images")
    doc_dir.mkdir(exist_ok=True)
    circle_icon(sheet, (370, 60, 750, 440), out_dir, "app icon", doc_dir)
    light_icon(sheet, (730, 50, 1080, 400), out_dir, doc_dir)
    # the art sheet is 1080 px wide with ~307 px rings: 512 would be an
    # upscale — the honest top size is 256; drop stale larger pngs
    for stale in ("greywatch-icon-512.png",):
        for d in (out_dir, doc_dir):
            p = d / stale
            if p.exists():
                p.unlink()
                print("removed stale:", p)
    # also replace the doc 256 with the new art
    (doc_dir / "greywatch-icon-256.png").write_bytes(
        (out_dir / "greywatch-icon-256.png").read_bytes())
    print("sizes written:", [p.name for p in sorted(out_dir.glob("greywatch-icon-*.png"))])


if __name__ == "__main__":
    main()