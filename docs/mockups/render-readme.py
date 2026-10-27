#!/usr/bin/env python3
"""Render the real README.md into the offline GitHub-page mockup.

Keeps docs/mockups/github-page.html in sync with the actual README:
every run replaces the text between the <!--README-BODY--> and
<!--END-README-BODY--> markers with a fresh markdown render of the
README, with doc/images/ paths rewritten so they also resolve from the
mockup's own location (../../doc/images/...).
"""
from pathlib import Path
import markdown

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
PAGE = Path(__file__).resolve().parent / "github-page.html"

html = markdown.markdown(
    README.read_text(),
    extensions=["toc", "fenced_code", "tables", "sane_lists"],
)
# the mockup lives two directories deeper than the repo root
html = html.replace('src="doc/images/', 'src="../../doc/images/')
html = html.replace('srcset="doc/images/', 'srcset="../../doc/images/')

page = PAGE.read_text()
start = page.index("<!--README-BODY-->") + len("<!--README-BODY-->")
end = page.index("<!--END-README-BODY-->")
page = page[:start] + "\n" + html + "\n      " + page[end:]
PAGE.write_text(page)
print(f"rendered {len(html)} bytes of README body into {PAGE.name}")