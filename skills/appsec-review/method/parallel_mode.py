"""Decide whether this review may spawn subagents.

Usage:
    python -I parallel_mode.py [--sequential]
    python -I test_parallel_mode.py

Prints one line: "parallel" or "sequential", a tab, and a short reason.
Exit 0 on a decision, 2 on a bad argument or an unrecognised APPSEC_REVIEW_PARALLEL value.

--sequential means the user asked for a sequential run. APPSEC_REVIEW_PARALLEL
overrides the default when it is set: 1/true/on/parallel, or 0/false/off/sequential.
An empty variable is the default, which is parallel. The host still falls back
to sequential when it cannot spawn a subagent; this script only records the request.
"""
import os
import sys

sys.dont_write_bytecode = True

ON = {"1", "true", "yes", "on", "parallel"}
OFF = {"0", "false", "no", "off", "sequential"}


def decide(argv, env):
    """(mode, reason) from argv and env. Raises ValueError on a bad request."""
    args = [a for a in argv if a != "--"]
    unknown = [a for a in args if a != "--sequential"]
    if unknown:
        raise ValueError("unknown argument: %s" % unknown[0])
    raw = env.get("APPSEC_REVIEW_PARALLEL", "")
    if not isinstance(raw, str):
        raise ValueError("APPSEC_REVIEW_PARALLEL must be a string")
    value = raw.strip().lower()
    if value and value not in ON and value not in OFF:
        raise ValueError(
            "APPSEC_REVIEW_PARALLEL must be 0, 1, false, true, off, on, sequential, or parallel")
    if "--sequential" in args:
        return "sequential", "user asked for a sequential run"
    if value in OFF:
        return "sequential", "APPSEC_REVIEW_PARALLEL=%s" % value
    if value in ON:
        return "parallel", "APPSEC_REVIEW_PARALLEL=%s" % value
    return "parallel", "default"


def main(argv, env=None):
    try:
        mode, reason = decide(argv, os.environ if env is None else env)
    except ValueError as exc:
        print("parallel_mode.py: %s" % exc, file=sys.stderr)
        return 2
    print("%s\t%s" % (mode, reason))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
