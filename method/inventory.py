"""Deterministic inventory of a repository's entry points and sinks for appsec-review.

Usage:
    python -I inventory.py <repo> [--stack <name> ...] [--only <path prefix> ...] [--out <file>]
    python -I test_inventory.py                     run the unit tests

Lists the same entry points and sinks for the same commit on every run, so the coverage ledger is seeded from a
fixed list instead of from what a run happens to notice. Stacks are detected from manifests unless --stack names
them; --only narrows the scan to path prefixes (an endpoint or files review). Patterns live in
inventory_patterns.py. With --out the JSON goes to that file and a summary is printed; otherwise the JSON is
printed.
"""
import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inventory_patterns as patterns  # noqa: E402

MAX_BYTES = 1000000
LABEL_CAP = 80
TEXT_CAP = 160
SKIP_PATH = re.compile(patterns.SKIP_PATH)
TEST_PATH = re.compile(patterns.TEST_PATH)


def run_git(repo, *args):
    """Stdout of a git command in repo, or None when git fails or is missing."""
    try:
        done = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, check=False)
    except OSError:
        return None
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def git_files(repo):
    out = run_git(repo, "ls-files", "-z")
    return None if out is None else [p for p in out.split("\0") if p]


def walk_files(repo):
    """Repository-relative paths when repo is not a git work tree."""
    found = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if not SKIP_PATH.search(d + "/"))
        rel = os.path.relpath(root, repo)
        found += [n if rel == "." else "%s/%s" % (rel.replace(os.sep, "/"), n) for n in names]
    return found


def is_excluded(path):
    return SKIP_PATH.search(path) is not None or TEST_PATH.search(path) is not None


def in_scope(path, only):
    return not only or any(path.startswith(prefix) for prefix in only)


def list_files(repo, only=()):
    """Sorted, in-scope source paths with dependencies, build output and tests removed."""
    files = git_files(repo)
    files = walk_files(repo) if files is None else files
    return sorted(p for p in files if in_scope(p, only) and not is_excluded(p))


def read_text(repo, path):
    """File text, or None when unreadable or larger than MAX_BYTES."""
    full = os.path.join(repo, path)
    try:
        if os.path.getsize(full) > MAX_BYTES:
            return None
        with open(full, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def manifest_matches(text, needles):
    return text is not None and (not needles or any(n in text for n in needles))


def stack_detected(repo, files, spec):
    for glob, needles in spec["detect"]:
        for path in files:
            if fnmatch.fnmatch(path.rsplit("/", 1)[-1], glob) and manifest_matches(read_text(repo, path), needles):
                return True
    return False


def detect_stacks(repo, files):
    """Stack names (rules/stacks/ stems) whose manifests appear in the repository."""
    return sorted(name for name, spec in patterns.STACKS.items() if stack_detected(repo, files, spec))


def is_code_line(line):
    return not line.lstrip().startswith(patterns.IMPORT_PREFIXES)


def clean(text, cap):
    """Single-line text without '::' (reserved in ledger ids), cut to cap characters."""
    return " ".join(text.split()).replace("::", ":")[:cap]


def label_for(match):
    groups = match.groupdict()
    return clean(groups.get("label") or match.group(0), LABEL_CAP)


def matching_lines(text, regex):
    """(line number, line, match) for each code line the regex matches."""
    compiled = re.compile(regex)
    for number, line in enumerate(text.splitlines(), 1):
        match = compiled.search(line) if is_code_line(line) else None
        if match:
            yield number, line, match


def entry_hits(path, text, stack, spec):
    hits = []
    for kind, regex, path_regex in spec["entry"]:
        if path_regex and not re.search(path_regex, path):
            continue
        hits += [{"path": path, "line": n, "stack": stack, "kind": kind, "label": label_for(m)}
                 for n, _, m in matching_lines(text, regex)]
    return hits


def file_entries(path, stack, spec):
    return [{"path": path, "line": 1, "stack": stack, "kind": kind, "label": kind}
            for kind, path_regex in spec["entry_files"] if re.search(path_regex, path)]


def sink_hits(path, text, stack, spec):
    hits = []
    for kind, area, regex in spec["sinks"]:
        hits += [{"path": path, "line": n, "stack": stack, "kind": kind, "area": area, "text": clean(line, TEXT_CAP)}
                 for n, line, _ in matching_lines(text, regex)]
    return hits


def dedupe(hits, fields):
    """First hit per key, in input order: stacks that share files report a line once."""
    seen, kept = set(), []
    for hit in hits:
        key = tuple(hit[f] for f in fields)
        if key not in seen:
            seen.add(key)
            kept.append(hit)
    return kept


def assign_surfaces(entries):
    """Add the deep-mode ledger surface '<path>#<kind> <label>', numbering repeats within a file."""
    counts = {}
    for entry in entries:
        base = "%s#%s %s" % (entry["path"], entry["kind"], entry["label"])
        counts[base] = counts.get(base, 0) + 1
        entry["surface"] = base if counts[base] == 1 else "%s (%d)" % (base, counts[base])
    return entries


def scan_file(repo, path, stacks):
    """(entries, sinks) for one file across every stack whose extensions it has."""
    entries, sinks, text = [], [], None
    for stack in stacks:
        spec = patterns.STACKS[stack]
        if not path.endswith(spec["extensions"]):
            continue
        text = read_text(repo, path) if text is None else text
        entries += file_entries(path, stack, spec)
        if text is not None:
            entries += entry_hits(path, text, stack, spec)
            sinks += sink_hits(path, text, stack, spec)
    return entries, sinks


def scan_repo(repo, files, stacks):
    entries, sinks = [], []
    for path in files:
        found_entries, found_sinks = scan_file(repo, path, stacks)
        entries += found_entries
        sinks += found_sinks
    entries = dedupe(sorted(entries, key=lambda e: (e["path"], e["line"], e["kind"])), ("path", "line", "kind"))
    sinks = dedupe(sorted(sinks, key=lambda s: (s["path"], s["line"], s["kind"])), ("path", "line", "kind"))
    return assign_surfaces(entries), sinks


def git_state(repo):
    """(HEAD sha or None, True when the work tree has uncommitted changes)."""
    head = run_git(repo, "rev-parse", "HEAD")
    status = run_git(repo, "status", "--porcelain")
    return (head.strip() if head else None), bool(status and status.strip())


def build_inventory(repo, stacks=None, only=()):
    all_files = list_files(repo)
    stacks = sorted(stacks) if stacks else detect_stacks(repo, all_files)
    files = [p for p in all_files if in_scope(p, only)]
    entries, sinks = scan_repo(repo, files, stacks)
    head, dirty = git_state(repo)
    return {
        "repo": os.path.basename(os.path.abspath(repo)), "source_ref": head, "dirty": dirty,
        "stacks": stacks, "only": list(only), "files_scanned": len(files),
        "modules": sorted({e["path"] for e in entries}),
        "entry_points": entries, "sinks": sinks,
    }


def count_by(items, field):
    counts = {}
    for item in items:
        counts[item[field]] = counts.get(item[field], 0) + 1
    return counts


def summary(inventory):
    return {
        "source_ref": inventory["source_ref"], "dirty": inventory["dirty"], "stacks": inventory["stacks"],
        "files_scanned": inventory["files_scanned"], "modules": len(inventory["modules"]),
        "entry_points": count_by(inventory["entry_points"], "kind"),
        "sinks": count_by(inventory["sinks"], "area"),
        "sink_files": len({s["path"] for s in inventory["sinks"]}),
    }


def parse_args(args):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("repo")
    parser.add_argument("--stack", action="append", choices=sorted(patterns.STACKS))
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--out")
    try:
        return parser.parse_args(args)
    except SystemExit:
        return None


def write_json(path, data):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1)


def normalize_prefix(prefix):
    """Repository-relative prefix with forward slashes and no leading './'."""
    prefix = prefix.replace("\\", "/")
    while prefix.startswith("./"):
        prefix = prefix[2:]
    return prefix


def main(args):
    options = parse_args(args)
    if options is None or not os.path.isdir(options.repo):
        print(__doc__)
        return 2
    only = [normalize_prefix(p) for p in options.only]
    inventory = build_inventory(options.repo, options.stack, only)
    if options.out:
        write_json(os.path.expanduser(options.out), inventory)
        print(json.dumps(summary(inventory), indent=2, sort_keys=True))
    else:
        print(json.dumps(inventory, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
