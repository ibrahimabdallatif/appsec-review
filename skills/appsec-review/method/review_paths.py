"""Absolute paths for a repository's private review files.

Usage:
    python -I review_paths.py <repo-name> [--mkdir]
    python -I test_review_paths.py

The review directory is <home>/.appsec-review/<repo-name>. Build it with
os.path.join. Do not expand "~/.appsec-review" by replacing "~/" : on Windows
that deletes the separator and produces "C:\\Users\\name.appsec-review".

Prints one "key: path" line for dir, html, markdown, inventory and ledger.
Copy those paths unchanged. --mkdir creates the directory and nothing else.
"""
import os
import sys

sys.dont_write_bytecode = True

KEYS = ("dir", "html", "markdown", "inventory", "ledger")


def repository_name(name):
    """A single folder name. Rejects paths, so the directory stays under the review root."""
    if not isinstance(name, str):
        raise ValueError("repository name is required")
    cleaned = name.strip()
    if not cleaned or cleaned in (".", ".."):
        raise ValueError("repository name is required")
    if any(mark in cleaned for mark in ("/", "\\", ":", "\0")):
        raise ValueError("repository name must be a single folder name")
    return cleaned


def review_paths(name, home=None):
    """Absolute dir, report, inventory and ledger paths for one repository."""
    folder = repository_name(name)
    root = os.path.abspath(home if home is not None else os.path.expanduser("~"))
    directory = os.path.join(root, ".appsec-review", folder)
    return {
        "dir": directory,
        "html": os.path.join(directory, "report.html"),
        "markdown": os.path.join(directory, "report.md"),
        "inventory": os.path.join(directory, "inventory.json"),
        "ledger": os.path.join(directory, "coverage-ledger.json"),
    }


def format_paths(found):
    lines = ["%s: %s" % (key, found[key]) for key in KEYS]
    lines.extend([
        "Report",
        "- HTML: %s" % found["html"],
        "- Markdown: %s" % found["markdown"],
    ])
    return "\n".join(lines)


def main(argv, home=None):
    args = [arg for arg in argv if arg != "--mkdir"]
    make = "--mkdir" in argv
    if len(args) != 1:
        print("usage: python -I review_paths.py <repo-name> [--mkdir]", file=sys.stderr)
        return 2
    try:
        found = review_paths(args[0], home)
    except ValueError as exc:
        print("review_paths.py: %s" % exc, file=sys.stderr)
        return 2
    if make:
        os.makedirs(found["dir"], exist_ok=True)
    print(format_paths(found))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
