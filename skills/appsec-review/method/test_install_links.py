"""Unit tests for install_links.py. Run: python -I test_install_links.py"""
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import install_links  # noqa: E402


def make_skill(root):
    os.makedirs(os.path.join(root, "rules"))
    os.makedirs(os.path.join(root, "method"))
    for rel in ("SKILL.md", os.path.join("rules", "00-overview.md"), os.path.join("method", "ledger.py")):
        with open(os.path.join(root, rel), "w", encoding="utf-8") as handle:
            handle.write("marker\n")
    with open(os.path.join(root, "marker.txt"), "w", encoding="utf-8") as handle:
        handle.write("keep\n")
    return root


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmp.name, "home")
        self.skill = make_skill(os.path.join(self.tmp.name, "skill"))
        os.makedirs(self.home)

    def tearDown(self):
        self.tmp.cleanup()

    def test_links_every_destination_without_copying(self):
        code, lines = install_links.run(self.home, self.skill)
        self.assertEqual(code, 0, lines)
        self.assertEqual(len(lines), len(install_links.DESTINATIONS))
        for label, parts in install_links.DESTINATIONS:
            link = install_links.destination(self.home, parts)
            self.assertTrue(install_links.same_directory(link, self.skill), link)
            self.assertTrue(install_links.is_reparse(link), link)
            self.assertTrue(os.path.samefile(
                os.path.join(link, "marker.txt"), os.path.join(self.skill, "marker.txt")))
        with open(os.path.join(self.skill, "marker.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "keep\n")

    def test_second_run_is_unchanged(self):
        self.assertEqual(install_links.run(self.home, self.skill)[0], 0)
        code, lines = install_links.run(self.home, self.skill)
        self.assertEqual(code, 0, lines)
        self.assertTrue(all(line.startswith("unchanged\t") for line in lines), lines)

    def test_refuses_a_real_directory_and_keeps_its_file(self):
        dest = install_links.destination(self.home, (".claude", "skills"))
        os.makedirs(dest)
        kept = os.path.join(dest, "keep.txt")
        with open(kept, "w", encoding="utf-8") as handle:
            handle.write("safe\n")
        code, lines = install_links.run(self.home, self.skill)
        self.assertEqual(code, 1, lines)
        with open(kept, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "safe\n")
        self.assertFalse(install_links.is_reparse(dest))

    def test_replace_retargets_a_link_and_not_a_directory(self):
        other = make_skill(os.path.join(self.tmp.name, "other"))
        self.assertEqual(install_links.run(self.home, other)[0], 0)
        code, lines = install_links.run(self.home, self.skill, replace=True)
        self.assertEqual(code, 0, lines)
        link = install_links.destination(self.home, (".cursor", "skills"))
        self.assertTrue(install_links.same_directory(link, self.skill))
        with open(os.path.join(other, "marker.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "keep\n")

    def test_replace_does_not_delete_a_real_directory(self):
        dest = install_links.destination(self.home, (".agents", "skills"))
        os.makedirs(dest)
        with open(os.path.join(dest, "keep.txt"), "w", encoding="utf-8") as handle:
            handle.write("safe\n")
        code, _lines = install_links.run(self.home, self.skill, replace=True)
        self.assertEqual(code, 1)
        self.assertTrue(os.path.isfile(os.path.join(dest, "keep.txt")))

    def test_dry_run_creates_nothing(self):
        code, lines = install_links.run(self.home, self.skill, dry_run=True)
        self.assertEqual(code, 0, lines)
        self.assertTrue(all(line.startswith("would-create\t") for line in lines), lines)
        self.assertFalse(os.path.exists(os.path.join(self.home, ".claude")))

    def test_missing_skill_files_exit_2(self):
        with self.assertRaises(ValueError):
            install_links.require_skill_dir(self.home)

    def test_main_rejects_a_missing_home(self):
        missing = os.path.join(self.tmp.name, "no-such-home")
        self.assertEqual(install_links.main(["--home", missing, "--skill-dir", self.skill]), 2)

    def test_remove_link_removes_a_directory_link_and_keeps_its_target(self):
        link = install_links.destination(self.home, (".claude", "skills"))
        os.makedirs(os.path.dirname(link))
        install_links.create_link(self.skill, link)
        install_links.remove_link(link)
        self.assertFalse(os.path.lexists(link))
        with open(os.path.join(self.skill, "marker.txt"), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "keep\n")

    def test_remove_link_refuses_a_real_directory(self):
        dest = install_links.destination(self.home, (".codex", "skills"))
        os.makedirs(dest)
        with self.assertRaises(RuntimeError):
            install_links.remove_link(dest)
        self.assertTrue(os.path.isdir(dest))


class RepoSkillTest(unittest.TestCase):
    def test_default_skill_dir_is_this_skill(self):
        root = install_links.require_skill_dir(install_links.default_skill_dir())
        self.assertTrue(root.endswith(os.path.join("skills", "appsec-review")) or
                        root.replace("\\", "/").endswith("skills/appsec-review"))
        self.assertFalse(os.path.islink(root))


if __name__ == "__main__":
    unittest.main()
