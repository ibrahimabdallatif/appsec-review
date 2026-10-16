"""Run statistics for appsec-review: elapsed time and token consumption.

Usage:
    python -I run_stats.py --start                     print the current epoch seconds; keep the value
    python -I run_stats.py <start epoch>               print the time elapsed since then, e.g. "12m 05s"
    python -I run_stats.py --tokens <budget at start> <budget at end> [subagent tokens ...]
        main-session tokens are the drop in the remaining token budget; pass "-" for both budgets when
        the session shows none. Subagent values are the counts the Agent tool reported.
    python -I test_run_stats.py                        run the unit tests
"""
import sys
import time


def now():
    """Current time as whole epoch seconds."""
    return int(time.time())


def parse_start(text):
    """Epoch seconds from the command line; raises ValueError for anything else."""
    value = int(text.strip())
    if value <= 0:
        raise ValueError("start must be a positive epoch value")
    return value


def format_duration(seconds):
    """Human duration: '45s', '12m 05s' or '1h 02m 09s'. Negative values count as zero."""
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return "%dh %02dm %02ds" % (hours, minutes, secs)
    if minutes:
        return "%dm %02ds" % (minutes, secs)
    return "%ds" % secs


def format_tokens(count):
    """Thousands-separated token count, e.g. 1234567 -> '1,234,567'."""
    return "{:,}".format(int(count))


def parse_count(text):
    """Non-negative token count; '-' means unknown (None). Raises ValueError otherwise."""
    text = text.strip().replace(",", "")
    if text == "-":
        return None
    value = int(text)
    if value < 0:
        raise ValueError("token counts cannot be negative")
    return value


def token_usage(budget_start, budget_end, subagents):
    """Main-session tokens from the budget drop (None when unknown), subagent sum, and total."""
    main_tokens = None
    if budget_start is not None and budget_end is not None:
        main_tokens = max(0, budget_start - budget_end)
    sub_tokens = sum(subagents)
    total = sub_tokens + (main_tokens or 0)
    return {"main": main_tokens, "subagents": sub_tokens, "subagent_count": len(subagents), "total": total}


def describe_usage(usage):
    """One line for the run summary."""
    main_text = "not shown by this session" if usage["main"] is None else format_tokens(usage["main"])
    total_text = format_tokens(usage["total"])
    if usage["main"] is None:
        total_text += " (subagents only)"
    return "main session %s | %d subagent(s) %s | total %s" % (
        main_text, usage["subagent_count"], format_tokens(usage["subagents"]), total_text)


def tokens_command(args):
    if len(args) < 2:
        print(__doc__)
        return 2
    try:
        start, end = parse_count(args[0]), parse_count(args[1])
        subagents = [parse_count(a) for a in args[2:]]
    except ValueError:
        print("token values must be non-negative integers, or '-' for an unknown budget")
        return 2
    if None in subagents:
        print("subagent token counts must be numbers")
        return 2
    print(describe_usage(token_usage(start, end, subagents)))
    return 0


def main(args, clock=now):
    if args and args[0] == "--tokens":
        return tokens_command(args[1:])
    if len(args) != 1:
        print(__doc__)
        return 2
    if args[0] == "--start":
        print(clock())
        return 0
    try:
        start = parse_start(args[0])
    except ValueError:
        print("start must be the epoch value printed by --start")
        return 2
    print(format_duration(clock() - start))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
