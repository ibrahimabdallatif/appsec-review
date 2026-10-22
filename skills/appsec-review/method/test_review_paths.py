"""Unit tests for review_paths.py. Run: python -I test_review_paths.py"""
import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import review_paths  # noqa: E402


class ReviewPathsTest(unittest.TestCase):
    def test_keeps_the_separator_before_the_dot_directory(self):
        home = os.path.join("C:\\Users", "ibrahim.beshir") if os.name == "nt" else "/home/ibrahim.beshir"
        found = review_paths.review_paths("user-profile-service", home)
        expected = os.path.join(os.path.abspath(home), ".appsec-review", "user-profile-service")
        self.assertEqual(found["dir"], expected)
        self.assertEqual(found["html"], os.path.join(expected, "report.html"))
        self.assertEqual(found["markdown"], os.path.join(expected, "report.md"))
        glued = os.path.abspath(home) + ".appsec-review"
        self.assertFalse(found["html"].startswith(glued))
        self.assertNotIn("beshir.appsec-review", found["html"])
        printed = review_paths.format_paths(found)
        self.assertIn("- HTML: %s" % found["html"], printed)
        self.assertIn("- Markdown: %s" % found["markdown"], printed)

    def test_rejects_a_path_as_a_repository_name(self):
        for name in ("", "  ", ".", "..", "a/b", "a\\b", "C:repo"):
            with self.assertRaises(ValueError):
                review_paths.repository_name(name)

    def test_mkdir_creates_only_the_review_directory(self):
        with tempfile.TemporaryDirectory() as home:
            with contextlib.redirect_stdout(io.StringIO()):
                code = review_paths.main(["user-profile-service", "--mkdir"], home)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isdir(os.path.join(home, ".appsec-review", "user-profile-service")))

    def test_bad_usage_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(review_paths.main([]), 2)
            self.assertEqual(review_paths.main(["a/b"]), 2)


if __name__ == "__main__":
    unittest.main()
