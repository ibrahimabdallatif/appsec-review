"""CVSS 4.0 base score (CVSS-B) calculator for appsec-review reports.

Port of the FIRST reference calculator (https://github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause,
Copyright FIRST, Red Hat, and contributors; see NOTICE.md). Only base metrics are scored: threat and
environmental metrics keep their defaults (E:X, CR/IR/AR:X).

Usage:
    python cvss40.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" [more vectors...]
    python cvss40.py --selftest
"""
import math
import sys

PREFIX = "CVSS:4.0/"
BASE_VALUES = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
}
# Unscored threat and environmental metrics take their worst case (E:X = A, CR/IR/AR:X = H).
DEFAULTS = {"E": "A", "CR": "H", "IR": "H", "AR": "H"}
IMPACT_METRICS = ("VC", "VI", "VA", "SC", "SI", "SA")

# Severity level of each value, used to measure how far a vector sits below its MacroVector's maximum.
LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
# Metrics summed into the severity distance of EQ1, EQ2, EQ3+EQ6 and EQ4 (EQ5 always adds 0).
EQ_METRICS = (
    ("AV", "PR", "UI"),
    ("AC", "AT"),
    ("VC", "VI", "VA", "CR", "IR", "AR"),
    ("SC", "SI", "SA"),
)

# Highest-severity vectors of each MacroVector part (max_composed.js); EQ3 is also keyed by EQ6.
MAX_COMPOSED = {
    1: {0: ["AV:N/PR:N/UI:N"], 1: ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
        2: ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"]},
    2: {0: ["AC:L/AT:N"], 1: ["AC:H/AT:N", "AC:L/AT:P"]},
    3: {0: {0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
            1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"]},
        1: {0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"],
            1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M"]},
        2: {1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"]}},
    4: {0: ["SC:H/SI:S/SA:S"], 1: ["SC:H/SI:H/SA:H"], 2: ["SC:L/SI:L/SA:L"]},
    5: {0: ["E:A"], 1: ["E:P"], 2: ["E:U"]},
}

# Depth of each MacroVector part in severity steps (max_severity.js); EQ3 is also keyed by EQ6.
MAX_SEVERITY = {
    1: {0: 1, 1: 4, 2: 5},
    2: {0: 1, 1: 2},
    3: {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    4: {0: 6, 1: 5, 2: 4},
}
STEP = 0.1

# Score of the highest-severity vector in each MacroVector (cvss_lookup.js).
LOOKUP = {
    "000000": 10, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2, "000100": 10, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9, "000210": 8.9, "000211": 8,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8,
    "001210": 7.8, "001211": 7, "001220": 6.9, "001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5, "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2, "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8,
    "011111": 7.2, "011120": 7, "011121": 5.9, "011200": 8.4, "011201": 7, "011210": 7.1, "011211": 5.2, "011220": 5,
    "011221": 3, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9, "110010": 8.8, "110011": 7.6, "110020": 7.6, "110021": 7, "110100": 9, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3, "111000": 8.9, "111001": 7.8, "111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6, "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7, "200201": 5.4, "200210": 5.2, "200211": 4, "200220": 4, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2, "202101": 4.7, "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6, "210021": 5, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4, "210120": 4.1, "210121": 2, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1, "212211": 0.3, "212221": 0.1,
}

BANDS = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "Informational"),
)


def split_metrics(text):
    return dict(part.split(":", 1) for part in text.split("/") if part)


def parse_vector(vector):
    """Return the base metrics plus the unscored defaults; reject missing, extra or invalid metrics."""
    text = vector.strip()
    if text.startswith(PREFIX):
        text = text[len(PREFIX):]
    metrics = split_metrics(text)
    missing = [m for m in BASE_VALUES if m not in metrics]
    if missing:
        raise ValueError("missing metrics: " + ", ".join(missing))
    extra = [m for m in metrics if m not in BASE_VALUES]
    if extra:
        raise ValueError("only base metrics are scored, remove: " + ", ".join(extra))
    invalid = ["%s:%s" % (m, v) for m, v in metrics.items() if len(v) != 1 or v not in BASE_VALUES[m]]
    if invalid:
        raise ValueError("invalid values: " + ", ".join(invalid))
    metrics.update(DEFAULTS)
    return metrics


def normalize(vector):
    """The vector in canonical metric order with the CVSS:4.0 prefix."""
    metrics = parse_vector(vector)
    return PREFIX + "/".join("%s:%s" % (m, metrics[m]) for m in BASE_VALUES)


def eq1(m):
    if m["AV"] == "N" and m["PR"] == "N" and m["UI"] == "N":
        return 0
    if m["AV"] != "P" and "N" in (m["AV"], m["PR"], m["UI"]):
        return 1
    return 2


def eq2(m):
    return 0 if m["AC"] == "L" and m["AT"] == "N" else 1


def eq3(m):
    if m["VC"] == "H" and m["VI"] == "H":
        return 0
    return 1 if "H" in (m["VC"], m["VI"], m["VA"]) else 2


def eq4(m):
    if m["SI"] == "S" or m["SA"] == "S":
        return 0
    return 1 if "H" in (m["SC"], m["SI"], m["SA"]) else 2


def eq5(m):
    return {"A": 0, "P": 1, "U": 2}[m["E"]]


def eq6(m):
    pairs = (("CR", "VC"), ("IR", "VI"), ("AR", "VA"))
    return 0 if any(m[req] == "H" and m[imp] == "H" for req, imp in pairs) else 1


def macro_vector(m):
    """The six EQ levels (0 = most severe) that select the MacroVector."""
    return (eq1(m), eq2(m), eq3(m), eq4(m), eq5(m), eq6(m))


def lookup_shifted(macro, *indexes):
    """Score of the MacroVector one level lower at each EQ index, or None when it doesn't exist."""
    shifted = list(macro)
    for index in indexes:
        shifted[index] += 1
    return LOOKUP.get("".join(str(level) for level in shifted))


def eq3eq6_lower_score(macro):
    """EQ3 and EQ6 step down together; from 00 both 01 and 10 are lower and the higher score is used."""
    pair = (macro[2], macro[5])
    if pair == (0, 0):
        left, right = lookup_shifted(macro, 5), lookup_shifted(macro, 2)
        return left if left is not None and right is not None and left > right else right
    if pair == (1, 0):
        return lookup_shifted(macro, 5)
    if pair in ((0, 1), (1, 1)):
        return lookup_shifted(macro, 2)
    return lookup_shifted(macro, 2, 5)


def lower_scores(macro):
    """Next lower MacroVector score for EQ1, EQ2, EQ3+EQ6, EQ4 and EQ5 (None when there is none)."""
    return [lookup_shifted(macro, 0), lookup_shifted(macro, 1), eq3eq6_lower_score(macro),
            lookup_shifted(macro, 3), lookup_shifted(macro, 4)]


def max_vectors(macro):
    """Every combination of the highest-severity vectors of the MacroVector's parts."""
    e1, e2, e3, e4, e5, e6 = macro
    groups = [MAX_COMPOSED[1][e1], MAX_COMPOSED[2][e2], MAX_COMPOSED[3][e3][e6],
              MAX_COMPOSED[4][e4], MAX_COMPOSED[5][e5]]
    combos = [{}]
    for group in groups:
        combos = [dict(combo, **split_metrics(part)) for combo in combos for part in group]
    return combos


def distances_from(m, max_vector):
    return {metric: LEVELS[metric][m[metric]] - LEVELS[metric][max_vector[metric]] for metric in LEVELS}


def severity_distances(m, macro):
    """Per-metric distance from the first max vector the scored vector doesn't exceed (else the last one)."""
    distances = None
    for max_vector in max_vectors(macro):
        distances = distances_from(m, max_vector)
        if all(value >= 0 for value in distances.values()):
            break
    return distances


def eq_distances(distances):
    """Summed severity distance for EQ1, EQ2, EQ3+EQ6, EQ4 and EQ5."""
    return [sum(distances[metric] for metric in metrics) for metrics in EQ_METRICS] + [0]


def max_depths(macro):
    """Depth of each EQ's MacroVector part as a distance; EQ5 has none."""
    e1, e2, e3, e4, _, e6 = macro
    depths = [MAX_SEVERITY[1][e1], MAX_SEVERITY[2][e2], MAX_SEVERITY[3][e3][e6], MAX_SEVERITY[4][e4]]
    return [depth * STEP for depth in depths] + [None]


def mean_drop(value, lowers, distances, depths):
    """Mean proportional score drop over the EQs that have a lower MacroVector."""
    drops = [(value - lower) * (0 if depth is None else distance / depth)
             for lower, distance, depth in zip(lowers, distances, depths) if lower is not None]
    return sum(drops) / len(drops) if drops else 0


def round_half_up(value):
    """One-decimal rounding with halves up, matching Math.round in the reference calculator."""
    return math.floor(value * 10 + 0.5) / 10


def has_no_impact(m):
    return all(m[metric] == "N" for metric in IMPACT_METRICS)


def base_score(vector):
    m = parse_vector(vector)
    if has_no_impact(m):
        return 0.0
    macro = macro_vector(m)
    value = LOOKUP["".join(str(level) for level in macro)]
    distances = eq_distances(severity_distances(m, macro))
    value -= mean_drop(value, lower_scores(macro), distances, max_depths(macro))
    return round_half_up(min(max(value, 0.0), 10.0))


def rating(score):
    for floor, label in BANDS:
        if score >= floor:
            return label
    return "Informational"


# Scores from the FIRST reference calculator.
KNOWN = {
    "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
    "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
    "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N": 9.3,
    "AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.2,
    "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N": 8.7,
    "AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.5,
    "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N": 7.1,
    "AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 6.9,
    "AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N": 6.0,
    "AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N": 5.3,
    "AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 5.3,
    "AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 1.0,
    "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
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
        print("%-64s %4.1f  %s" % (normalize(vector), score, rating(score)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
