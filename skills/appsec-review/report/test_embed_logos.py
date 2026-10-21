"""Unit tests for embed_logos.py. Run: python -I test_embed_logos.py"""
import base64
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import embed_logos as el  # noqa: E402

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def run(args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = el.main(args)
    return code, out.getvalue().strip()


class DataUriTest(unittest.TestCase):
    def test_encodes_file_as_png_uri(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.png")
            with open(path, "wb") as handle:
                handle.write(b"abc")
            self.assertEqual(el.data_uri(path), "data:image/png;base64,YWJj")


class LogoValuesTest(unittest.TestCase):
    def test_shipped_logos_are_png(self):
        values = el.logo_values()
        self.assertEqual(set(values), {"LOGO_LIGHT", "LOGO_DARK"})
        for uri in values.values():
            raw = base64.b64decode(uri.split(",", 1)[1])
            self.assertTrue(raw.startswith(PNG_SIGNATURE))

    def test_light_and_dark_differ(self):
        values = el.logo_values()
        self.assertNotEqual(values["LOGO_LIGHT"], values["LOGO_DARK"])


class EmbedTest(unittest.TestCase):
    def test_replaces_every_occurrence(self):
        text = el.embed("{{LOGO_DARK}} {{LOGO_LIGHT}} {{LOGO_DARK}}", {"LOGO_LIGHT": "l", "LOGO_DARK": "d"})
        self.assertEqual(text, "d l d")

    def test_missing_placeholder_fails(self):
        with self.assertRaises(ValueError):
            el.embed("{{LOGO_LIGHT}}", {"LOGO_LIGHT": "l", "LOGO_DARK": "d"})

    def test_template_has_both_placeholders(self):
        with open(os.path.join(el.HERE, "report-template.html"), encoding="utf-8") as handle:
            text = el.embed(handle.read(), {"LOGO_LIGHT": "l", "LOGO_DARK": "d"})
        self.assertNotIn("{{LOGO_", text)


class MainTest(unittest.TestCase):
    def test_embeds_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('url("{{LOGO_LIGHT}}") url("{{LOGO_DARK}}")')
            code, _ = run([path])
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertEqual(code, 0)
        self.assertEqual(text.count("data:image/png;base64,"), 2)

    def test_page_without_placeholders_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("<p>done</p>")
            code, out = run([path])
        self.assertEqual(code, 1)
        self.assertIn("{{LOGO_LIGHT}}", out)

    def test_missing_file_fails(self):
        code, _ = run([os.path.join(tempfile.gettempdir(), "no-such-report.html")])
        self.assertEqual(code, 1)

    def test_wrong_args_print_usage(self):
        self.assertEqual(run([])[0], 2)


if __name__ == "__main__":
    unittest.main()
