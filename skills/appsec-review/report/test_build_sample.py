"""Unit tests for build_sample.py. Run: python -I test_build_sample.py"""
import copy
import json
import os
import re
import sys
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_sample as bs  # noqa: E402

DATA = json.loads(bs.read_text(bs.FIXTURE))
TEMPLATE = bs.read_text(bs.TEMPLATE)
PLACEHOLDER = re.compile(r"\{\{[A-Z_:]+\}\}")


def finding(**changes):
    base = {"key": "k", "layer": "Backend", "vector": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
    base.update(changes)
    return base


class ScoreTest(unittest.TestCase):
    def test_scores_with_calculator(self):
        scored = bs.score(finding())
        self.assertEqual((scored["cvss"], scored["rating"]), (9.3, "Critical"))
        self.assertTrue(scored["vector"].startswith("CVSS:4.0/"))

    def test_no_vector_is_informational(self):
        scored = bs.score(finding(vector=None))
        self.assertEqual((scored["cvss"], scored["rating"], scored["vector"]), (0.0, "Informational", ""))

    def test_sort_breaks_ties_on_vc_vi(self):
        low = bs.score(finding(vector="AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"))
        high = dict(low, vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
        self.assertEqual(sorted([low, high], key=bs.sort_key)[0], high)


class SectionsTest(unittest.TestCase):
    def test_one_section_per_layer_numbered_and_sorted(self):
        sections = bs.build_sections(DATA)
        self.assertEqual([s["num"] for s in sections], ["4.1", "4.2"])
        scores = [f["cvss"] for f in sections[0]["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        first = sections[1]["findings"][0]
        self.assertEqual((first["id"], first["anchor"]), ("4.2.1", "f2-1"))

    def test_counts(self):
        findings = bs.all_findings(bs.build_sections(DATA))
        self.assertEqual(sum(bs.count_ratings(findings).values()), len(DATA["findings"]))
        self.assertEqual(bs.count_locations(findings), sum(len(f["assets"]) for f in DATA["findings"]))


class TextTest(unittest.TestCase):
    IDS = {"x": ("4.1.1", "f1-1")}

    def test_html_text_escapes_codes_and_links(self):
        out = bs.html_text("Use `<b>` see {ref:x} & go", self.IDS)
        self.assertEqual(out, 'Use <code>&lt;b&gt;</code> see <a href="#f1-1">4.1.1</a> &amp; go')

    def test_md_text_resolves_refs(self):
        self.assertEqual(bs.md_text("see {ref:x}", self.IDS), "see 4.1.1")

    def test_unknown_ref_fails(self):
        with self.assertRaises(KeyError):
            bs.md_text("{ref:missing}", self.IDS)


class TemplateEditingTest(unittest.TestCase):
    def test_fill(self):
        self.assertEqual(bs.fill("{{A}}-{{B:C}}", {"A": 1, "B:C": "x"}), "1-x")

    def test_repeat_line(self):
        text = "a\n  <li>{{X}}</li>\nb"
        self.assertEqual(bs.repeat_line(text, "{{X}}", [{"X": 1}, {"X": 2}]), "a\n  <li>1</li>\n  <li>2</li>\nb")

    def test_line_must_be_unique(self):
        with self.assertRaisesRegex(ValueError, "found 2"):
            bs.find_line("{{X}}\n{{X}}", "{{X}}")
        with self.assertRaisesRegex(ValueError, "found 0"):
            bs.find_line("a", "{{X}}")

    def test_uncomment(self):
        self.assertEqual(bs.uncomment("  <!-- LAYERS ONLY, note: <p>{{X}}</p> -->"), "  <p>{{X}}</p>")
        with self.assertRaises(ValueError):
            bs.uncomment("<p>plain</p>")

    def test_block_range_uses_indent(self):
        lines = ["x", "  <div a>", "    <div>", "    </div>", "  </div>", "y"]
        self.assertEqual(bs.block_range(lines, "<div a>", "</div>"), (1, 5))

    def test_block_range_unclosed(self):
        with self.assertRaisesRegex(ValueError, "no"):
            bs.block_range(["  <div a>"], "<div a>", "</div>")

    def test_strip_comments_keeps_markup(self):
        text = "a\n  <!-- one\n two -->\n<dd><!-- x --><p>b</p></dd>\n"
        self.assertEqual(bs.strip_comments(text), "a\n<dd><p>b</p></dd>\n")

    def test_drop_empty_bars_and_legend(self):
        bars = '  <span class="s-high" style="flex:0"></span>\n  <span class="s-low" style="flex:2"></span>\n'
        self.assertEqual(bs.drop_empty_bars(bars), '  <span class="s-low" style="flex:2"></span>\n')
        kept = '  <div class="s-low" style="flex:2"><b>2</b><span>Low</span></div>\n'
        legend = '  <div class="s-high" style="flex:0"><b>0</b><span>High</span></div>\n' + kept
        self.assertEqual(bs.drop_empty_legend(legend), kept)

    def test_wrap_document_sets_charset(self):
        out = bs.wrap_document("<title>t</title>\n")
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertIn('<meta charset="utf-8">', out)
        self.assertTrue(out.endswith("</html>\n"))

    def test_poc_block_escapes_and_highlights(self):
        out = bs.poc_block({"poc": ["a", "<b>"], "highlight": [2]})
        self.assertEqual(out, '<pre>a\n<span class="hl">&lt;b&gt;</span></pre>')

    def test_fence_longer_than_backticks(self):
        self.assertEqual(bs.fence_for(["x"]), "```")
        self.assertEqual(bs.fence_for(["a ```` b"]), "`````")


class HtmlBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = bs.build_html(TEMPLATE, DATA)

    def test_no_placeholders_or_comments_left(self):
        self.assertEqual(PLACEHOLDER.findall(self.page), [])
        self.assertNotIn("<!--", self.page)

    def test_logos_embedded_once_each(self):
        for uri in bs.embed_logos.logo_values().values():
            self.assertEqual(self.page.count(uri), 1)
        self.assertEqual(self.page.count('class="logo"'), 2)

    def test_every_finding_has_card_and_glance_row(self):
        for f in bs.all_findings(bs.build_sections(DATA)):
            self.assertEqual(self.page.count('id="%s"' % f["anchor"]), 1)
            self.assertIn('href="#%s"' % f["anchor"], self.page)

    def test_layer_sections_and_rail(self):
        for anchor, label in (("s1", "4.1 Backend"), ("s2", "4.2 Web frontend")):
            self.assertIn('href="#%s">%s<' % (anchor, label), self.page)
            self.assertIn('id="%s"' % anchor, self.page)

    def test_needs_confirmation_tagged_and_listed(self):
        self.assertEqual(self.page.count('<span class="confirm">Needs confirmation</span>'), 1)
        self.assertIn("SHOW default_transaction_isolation;", self.page)

    def test_code_is_escaped(self):
        self.assertNotIn("<img src=x", self.page)
        self.assertIn("&lt;img src=x onerror=...&gt;", self.page)

    def test_keeps_theme_script_and_credit(self):
        self.assertIn('id="theme-toggle"', self.page)
        self.assertIn('label.textContent = current() === "dark" ? "Light mode" : "Dark mode";', self.page)
        self.assertNotIn("aria-pressed", self.page)
        self.assertIn(bs.REPO_URL, self.page)

    def test_no_facts_gives_none_row(self):
        data = copy.deepcopy(DATA)
        for f in data["findings"]:
            f.pop("needs_confirmation", None)
        self.assertIn('<td colspan="4">None</td>', bs.build_html(TEMPLATE, data))


class MarkdownBuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.md = bs.build_markdown(DATA)

    def test_front_matter_and_no_html(self):
        self.assertTrue(self.md.startswith('---\nservice: "acme-shop"'))
        self.assertNotIn("<pre", self.md)
        self.assertNotIn("{ref:", self.md)

    def test_same_sections_as_page(self):
        for heading in ("## 1.0 Executive Summary", "### 1.3 Findings at a Glance", "## 2.0 Scope and Threat Model",
                        "## 3.0 Security Controls Checklist", "### 4.1 acme-shop · Backend",
                        "### 4.2 acme-shop · Web frontend", "#### 4.1.1 Admin Token Signature Not Verified",
                        "### 5.2 Facts to Confirm", "### 6.4 Candidates Rejected by Verification"):
            self.assertIn(heading, self.md)

    def test_vulnerable_lines_listed(self):
        self.assertIn("Vulnerable lines: 3, 4", self.md)

    def test_credit_line(self):
        self.assertIn("Skill author: Ibrahim Abdallatif · LinkedIn (%s)" % bs.LINKEDIN_URL, self.md)


class CommittedSampleTest(unittest.TestCase):
    def test_docs_match_fresh_build(self):
        self.assertEqual(bs.stale_outputs(bs.build_all()), [],
                         "sample report is out of date: run python -I report/build_sample.py")

    def test_main_rejects_unknown_args(self):
        self.assertEqual(bs.main(["--nope"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
