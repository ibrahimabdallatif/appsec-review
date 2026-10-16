"""CVSS 3.1 base score calculator for appsec-review reports.

Usage:
    python cvss31.py "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" [more vectors...]
    python cvss31.py --selftest
"""
import math
import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

BANDS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Informational"),
)


def roundup(value):
    """CVSS 3.1 Roundup: smallest one-decimal number >= value, float-safe."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector):
    text = vector.strip()
    if text.startswith("CVSS:3.1/"):
        text = text[len("CVSS:3.1/"):]
    metrics = dict(part.split(":", 1) for part in text.split("/") if part)
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise ValueError("missing metrics: " + ", ".join(missing))
    return metrics


def impact_subscore(metrics):
    iss = 1 - (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    if metrics["S"] == "U":
        return 6.42 * iss
    return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def exploitability(metrics):
    pr_table = PR_CHANGED if metrics["S"] == "C" else PR_UNCHANGED
    return 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr_table[metrics["PR"]] * UI[metrics["UI"]]


def base_score(vector):
    metrics = parse_vector(vector)
    impact = impact_subscore(metrics)
    if impact <= 0:
        return 0.0
    total = impact + exploitability(metrics)
    if metrics["S"] == "C":
        total *= 1.08
    return roundup(min(total, 10))


def rating(score):
    for floor, label in BANDS:
        if score >= floor:
            return label
    return "Informational"


KNOWN = {
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
    "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 4.3,
    "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
}


def selftest():
    failures = [(v, s, base_score(v)) for v, s in KNOWN.items() if base_score(v) != s]
    for vector, expected, actual in failures:
        print("FAIL %s expected %.1f got %.1f" % (vector, expected, actual))
    print("selftest: %d/%d passed" % (len(KNOWN) - len(failures), len(KNOWN)))
    return 1 if failures else 0


def main(args):
    if not args:
        print(__doc__)
        return 2
    if args[0] == "--selftest":
        return selftest()
    for vector in args:
        score = base_score(vector)
        print("%-45s %4.1f  %s" % (vector, score, rating(score)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
