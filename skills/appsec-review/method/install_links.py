"""Link this skill into user-level discovery directories without copying it.

Usage:
    python -I install_links.py [--home DIR] [--skill-dir DIR] [--replace] [--dry-run]

The canonical folder is the skill directory that contains this script (the parent
of method/), unless --skill-dir points at another folder that contains SKILL.md,
rules/00-overview.md and method/ledger.py.

Each destination is a directory symlink, or a junction when Windows denies symlinks.
Nothing under the canonical folder is copied or deleted. A real directory at a
destination is left untouched. --replace retargets an existing link only.

    <home>/.claude/skills/appsec-review     Claude Code
    <home>/.cursor/skills/appsec-review     Cursor
    <home>/.agents/skills/appsec-review     Codex and Cursor
    <home>/.codex/skills/appsec-review      Codex (skills CLI global path)

Exit codes: 0 linked or already correct, 1 a destination was refused, 2 bad arguments.
"""
import argparse
import os
import subprocess
import sys

sys.dont_write_bytecode = True

SKILL_NAME = "appsec-review"
DESTINATIONS = (
    ("Claude Code", (".claude", "skills")),
    ("Cursor", (".cursor", "skills")),
    ("Codex and Cursor", (".agents", "skills")),
    ("Codex", (".codex", "skills")),
)
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


def default_skill_dir():
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def require_skill_dir(path):
    root = os.path.abspath(path)
    required = ("SKILL.md", os.path.join("rules", "00-overview.md"), os.path.join("method", "ledger.py"))
    missing = [rel for rel in required if not os.path.isfile(os.path.join(root, rel))]
    if missing:
        raise ValueError("not a canonical skill folder (missing %s): %s" % (", ".join(missing), root))
    return root


def destination(home, parts):
    return os.path.join(os.path.abspath(home), *parts, SKILL_NAME)


def is_reparse(path):
    """True for a symlink or, on Windows, a junction. False for a real directory."""
    if os.path.islink(path):
        return True
    if os.name != "nt" or not os.path.isdir(path):
        return False
    import ctypes
    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    if attrs == INVALID_FILE_ATTRIBUTES:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def same_directory(link, target):
    try:
        return os.path.samefile(link, target)
    except OSError:
        return False


def remove_link(path):
    """Remove a symlink or junction. Never removes a real directory tree.

    A symlink is unlinked even when its target is a directory. On Linux, rmdir
    follows that symlink and fails with ENOTDIR. rmdir is only for a Windows
    junction, which is not reported as a symlink.
    """
    if not is_reparse(path):
        raise RuntimeError("refusing to remove a real directory: %s" % path)
    if os.path.islink(path):
        os.unlink(path)
        return
    os.rmdir(path)


def create_link(target, link):
    """Create a directory link. Returns 'symlink' or 'junction'."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return "symlink"
    except OSError as symlink_error:
        if os.name != "nt":
            raise
        windows_error = symlink_error
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", link, target],
        capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or str(windows_error)).strip()
        raise OSError("could not create a symlink or junction: %s" % detail)
    return "junction"


def link_one(target, link, replace, dry_run):
    """Return a status word. Raises RuntimeError when the destination must be left alone."""
    if os.path.lexists(link):
        if same_directory(link, target):
            return "unchanged"
        if not is_reparse(link):
            raise RuntimeError("refusing to replace a real directory: %s" % link)
        if not replace:
            raise RuntimeError("link points elsewhere; pass --replace to retarget it: %s" % link)
        if dry_run:
            return "would-replace"
        remove_link(link)
    if dry_run:
        return "would-create"
    os.makedirs(os.path.dirname(link), exist_ok=True)
    return create_link(target, link)


def run(home, skill_dir, replace=False, dry_run=False):
    """Link every destination. Returns (exit code, lines)."""
    if not os.path.isdir(home):
        raise ValueError("home is not a directory: %s" % home)
    target = require_skill_dir(skill_dir)
    lines = []
    failed = False
    for label, parts in DESTINATIONS:
        link = destination(home, parts)
        try:
            status = link_one(target, link, replace, dry_run)
        except (RuntimeError, OSError) as exc:
            failed = True
            lines.append("failed\t%s\t%s" % (label, exc))
            continue
        lines.append("%s\t%s\t%s" % (status, label, link))
    return (1 if failed else 0), lines


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Link the appsec-review skill into user skill directories.")
    parser.add_argument("--home", default=os.path.expanduser("~"))
    parser.add_argument("--skill-dir", default=default_skill_dir())
    parser.add_argument("--replace", action="store_true",
                        help="retarget an existing link; never deletes a real directory")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv):
    try:
        args = parse_args(argv)
        code, lines = run(args.home, args.skill_dir, args.replace, args.dry_run)
    except ValueError as exc:
        print("install_links.py: %s" % exc, file=sys.stderr)
        return 2
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
