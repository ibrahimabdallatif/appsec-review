"""Embed the skill's light and dark logos into a written report page as data URIs.

The report must open without contacting any host, so the logos travel inside the page. The template keeps the
{{LOGO_LIGHT}} and {{LOGO_DARK}} placeholders; run this script on report.html after writing it.

Usage:
    python -I embed_logos.py <report.html>     fill the logo placeholders in place
    python -I test_embed_logos.py              run the unit tests
"""
import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOGOS = {"LOGO_LIGHT": os.path.join(HERE, "assets", "logo-light.png"),
         "LOGO_DARK": os.path.join(HERE, "assets", "logo-dark.png")}


def data_uri(path):
    """PNG file as a base64 data URI."""
    with open(path, "rb") as handle:
        return "data:image/png;base64," + base64.b64encode(handle.read()).decode("ascii")


def logo_values(logos=None):
    """Placeholder name -> data URI for every logo."""
    return {name: data_uri(path) for name, path in (logos or LOGOS).items()}


def embed(text, values):
    """Replace each {{NAME}} logo placeholder; raises ValueError when one is missing."""
    for name, uri in values.items():
        marker = "{{%s}}" % name
        if marker not in text:
            raise ValueError("no %s placeholder in the page" % marker)
        text = text.replace(marker, uri)
    return text


def embed_file(path, values):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(embed(text, values))


def main(args):
    if len(args) != 1:
        print(__doc__)
        return 2
    try:
        embed_file(args[0], logo_values())
    except (OSError, ValueError) as error:
        print("cannot embed logos: %s" % error)
        return 1
    print("embedded logos in %s" % args[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
