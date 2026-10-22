"""Structural tests for the cross-platform skill layout. Run: python -I test_layout.py"""
import os
import re
import sys
import unittest

sys.dont_write_bytecode = True

METHOD = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(METHOD)
REPO = os.path.dirname(os.path.dirname(SKILL))
CANONICAL = os.path.join(SKILL, "SKILL.md")
ADAPTERS = (
    os.path.join(REPO, ".claude", "skills", "appsec-review", "SKILL.md"),
    os.path.join(REPO, ".cursor", "skills", "appsec-review", "SKILL.md"),
    os.path.join(REPO, ".agents", "skills", "appsec-review", "SKILL.md"),
)
SKIP_WALK = {".git", "__pycache__", ".idea", ".vscode"}


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def frontmatter(text):
    if not text.startswith("---\n"):
        raise AssertionError("missing frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise AssertionError("frontmatter is not closed")
    data = {}
    section = None
    for line in text[4:end].splitlines():
        if line.startswith("  ") and section:
            key, value = line.strip().split(":", 1)
            data[section][key] = value.strip()
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if value == "":
            section = key
            data[key] = {}
        else:
            section = None
            if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            data[key] = value
    return data


def walk_files(name):
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [item for item in dirs if item not in SKIP_WALK]
        if name in files:
            found.append(os.path.join(root, name))
    return found


class CanonicalSkillTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(CANONICAL)
        cls.meta = frontmatter(cls.text)

    def test_name_matches_directory_and_spec(self):
        self.assertEqual(self.meta["name"], "appsec-review")
        self.assertEqual(os.path.basename(SKILL), "appsec-review")
        self.assertLessEqual(len(self.meta["name"]), 64)
        self.assertRegex(self.meta["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")

    def test_description_and_compatibility_limits(self):
        self.assertTrue(self.meta["description"])
        self.assertLessEqual(len(self.meta["description"]), 1024)
        self.assertIn("explicitly invokes", self.meta["description"])
        self.assertIn("Do not run for a general security question", self.meta["description"])
        self.assertLessEqual(len(self.meta["compatibility"]), 500)
        self.assertEqual(self.meta["license"], "MIT")
        self.assertEqual(self.meta["disable-model-invocation"], "true")
        self.assertNotIn("internal", self.meta.get("metadata", {}))

    def test_points_at_shared_workflow_files(self):
        for rel in ("method/orchestration.md", "method/parallel_mode.py", "method/finding-contract.md",
                    "method/hunters.md", "method/verifier.md", "method/coverage-ledger.md",
                    "method/ledger.py", "method/inventory.py", "report/cvss40.py", "report/REPORT.md",
                    "rules/00-overview.md"):
            self.assertIn(rel.replace("\\", "/"), self.text.replace("\\", "/"), rel)
            self.assertTrue(os.path.isfile(os.path.join(SKILL, *rel.split("/"))), rel)

    def test_methodology_is_not_copied_into_adapters(self):
        self.assertIn("Seed the coverage ledger", self.text)
        for path in ADAPTERS:
            body = read(path).split("\n---\n", 1)[1]
            self.assertNotIn("Seed the coverage ledger", body)
            self.assertLess(body.count("\n"), 40, path)


class AdapterTest(unittest.TestCase):
    def test_adapters_match_and_resolve_to_the_canonical_skill(self):
        bodies = [read(path) for path in ADAPTERS]
        self.assertTrue(all(body == bodies[0] for body in bodies))
        canonical = frontmatter(read(CANONICAL))
        for path in ADAPTERS:
            meta = frontmatter(read(path))
            self.assertEqual(meta["name"], "appsec-review")
            self.assertEqual(meta["description"], canonical["description"])
            self.assertEqual(meta["disable-model-invocation"], "true")
            self.assertEqual(meta["metadata"]["internal"], "true")
            target = os.path.normpath(os.path.join(os.path.dirname(path), "..", "..", "..",
                                                   "skills", "appsec-review", "SKILL.md"))
            self.assertEqual(os.path.normcase(target), os.path.normcase(CANONICAL))
            self.assertIn("../../../skills/appsec-review/SKILL.md", read(path))


class SingleCopyTest(unittest.TestCase):
    def test_rules_and_calculator_are_not_duplicated(self):
        overviews = walk_files("00-overview.md")
        self.assertEqual(overviews, [os.path.join(SKILL, "rules", "00-overview.md")])
        calculators = walk_files("cvss40.py")
        self.assertEqual(calculators, [os.path.join(SKILL, "report", "cvss40.py")])
        skills = walk_files("SKILL.md")
        self.assertEqual(len(skills), 1 + len(ADAPTERS))

    def test_orchestration_covers_hosts_and_fallback(self):
        text = read(os.path.join(METHOD, "orchestration.md"))
        for phrase in ("Claude Code", "Cursor", "Codex", "sequential", "rejection_reviewed",
                       "readonly", "Do not publish"):
            self.assertIn(phrase, text)
        hunters = read(os.path.join(METHOD, "hunters.md"))
        verifier = read(os.path.join(METHOD, "verifier.md"))
        self.assertIn("orchestration.md", hunters)
        self.assertIn("orchestration.md", verifier)
        self.assertIn("sequential", hunters.lower())
        self.assertIn("sequential", verifier.lower())
        self.assertNotIn("Agent tool, `general-purpose`.", hunters)


class DocsTest(unittest.TestCase):
    def test_install_docs_name_each_platform_and_the_untested_boundary(self):
        readme = read(os.path.join(REPO, "README.md"))
        started = read(os.path.join(REPO, "docs", "getting-started.md"))
        platforms = read(os.path.join(REPO, "docs", "platforms.md"))
        for text in (readme, started, platforms):
            for name in ("Claude Code", "Cursor", "Codex"):
                self.assertIn(name, text)
        self.assertIn("Live skill invocation was not executed", platforms)
        self.assertIn("sequential", platforms.lower())
        self.assertIn("install_links.py", platforms)
        self.assertIn("metadata.internal", platforms)


if __name__ == "__main__":
    unittest.main()
