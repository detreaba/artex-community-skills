"""Match a deployed package inventory against an offline OSV advisory snapshot.

Every result is mechanical. It comes from OSV records that ARTEX maintainers have not
reviewed against the vendor bulletins, so the output carries "review_level": "unreviewed".

Usage:
  python3 scripts/check.py [--osv FAMILY=PATH ...] [--kev PATH] < request.json
FAMILY is npm, Packagist or Debian. PATH is an OSV export zip (for example
https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip) or a directory of OSV
JSON records. The request may also embed a small snapshot for examples and tests.
The checker reads local files only and makes no network requests.
"""
import hashlib
import json
import math
import re
import sys
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from functools import cmp_to_key
from pathlib import Path

MAX_STDIN = 8 * 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
MAX_KEV = 32 * 1024 * 1024
MAX_PACKAGES = 20_000
MAX_FIELD = 256
FAMILIES = ("npm", "Packagist", "Debian")
ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,127}")
EVENT_KINDS = ("introduced", "fixed", "last_affected", "limit")


# ---------------------------------------------------------------------------
# Version comparators. Each parse() returns an orderable value or None when the
# string is outside the documented syntax. None always leads to "unknown".
# ---------------------------------------------------------------------------

def _cmp(a, b):
    return (a > b) - (a < b)


_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def semver_parse(value):
    """SemVer 2.0.0 precedence (semver.org, section 11). Build metadata is ignored."""
    if not isinstance(value, str) or len(value) > MAX_FIELD:
        return None
    m = _SEMVER.fullmatch(value)
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    if pre is None:
        return (int(major), int(minor), int(patch), 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (int(major), int(minor), int(patch), 0, ids)


# The suffix tail accepts the same strings as the earlier "(?:[.-]?[0-9]{1,9})*", but each digit
# run has one parse, so a failed match backtracks in linear time. re.ASCII stops Unicode case
# folding (for example U+017F matching the "s" of "stable").
_COMPOSER = re.compile(
    r"[vV]?([0-9]{1,9})(?:\.([0-9]{1,9}))?(?:\.([0-9]{1,9}))?(?:\.([0-9]{1,9}))?"
    r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?[0-9]+(?:[.-][0-9]+)*)?))?",
    re.IGNORECASE | re.ASCII)
_COMPOSER_RANK = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5}


def composer_parse(value):
    """Composer release ordering: up to four numeric parts, then alpha < beta < RC < stable < patch.

    Build metadata after '+' is dropped as Composer does. Development branches and
    "-dev" versions have no release ordering here and yield None.
    """
    if not isinstance(value, str) or len(value) > MAX_FIELD:
        return None
    base = value.split("+", 1)[0] if "+" in value else value
    m = _COMPOSER.fullmatch(base)
    if not m:
        return None
    nums = tuple(int(x) if x is not None else 0 for x in m.groups()[:4])
    stability, extra = m.group(5), m.group(6) or ""
    rank = _COMPOSER_RANK[stability.lower()] if stability else 4
    extra_nums = tuple(int(x) for x in re.findall(r"[0-9]+", extra))
    return nums + (rank, extra_nums)


_DPKG_UPSTREAM = re.compile(r"[0-9][A-Za-z0-9.+~-]*")
_DPKG_REVISION = re.compile(r"[A-Za-z0-9.+~]+")


def dpkg_parse(value):
    """Debian version syntax, Debian Policy 5.6.12: [epoch:]upstream_version[-debian_revision]."""
    if not isinstance(value, str) or not value or len(value) > MAX_FIELD:
        return None
    epoch, rest = 0, value
    if ":" in value:
        head, rest = value.split(":", 1)
        if not head.isdigit() or not head.isascii():
            return None
        epoch = int(head)
    revision = ""
    if "-" in rest:
        rest, revision = rest.rsplit("-", 1)
        if not _DPKG_REVISION.fullmatch(revision):
            return None
    elif not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", rest):
        return None
    if not _DPKG_UPSTREAM.fullmatch(rest):
        return None
    return (epoch, rest, revision)


def _dpkg_order(ch):
    # Policy: letters sort before non-letters, and '~' sorts before anything, even the end.
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return ord(ch)
    return ord(ch) + 256


def _dpkg_part_cmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        na = re.match(r"[^0-9]*", a[i:]).group()
        nb = re.match(r"[^0-9]*", b[j:]).group()
        for k in range(max(len(na), len(nb))):
            oa = _dpkg_order(na[k] if k < len(na) else "")
            ob = _dpkg_order(nb[k] if k < len(nb) else "")
            if oa != ob:
                return -1 if oa < ob else 1
        i, j = i + len(na), j + len(nb)
        da = re.match(r"[0-9]*", a[i:]).group()
        db = re.match(r"[0-9]*", b[j:]).group()
        va, vb = int(da or "0"), int(db or "0")
        if va != vb:
            return -1 if va < vb else 1
        i, j = i + len(da), j + len(db)
    return 0


def dpkg_cmp(a, b):
    return _cmp(a[0], b[0]) or _dpkg_part_cmp(a[1], b[1]) or _dpkg_part_cmp(a[2], b[2])


# OSV orders Packagist versions with PHP's version_compare(), as documented in osv.dev's
# osv/ecosystems/packagist.py (Apache-2.0). The behaviour is re-implemented here, not copied.
# Special parts match exactly and case-sensitively; any other non-numeric part sorts below "dev".
_PHP_SPECIAL = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "RC": 3, "rc": 3, "#": 4, "pl": 5, "p": 5}


def php_parts(value):
    if not isinstance(value, str) or len(value) > MAX_FIELD:
        return None
    if value.startswith("v"):
        value = value[1:]
    value = re.sub(r"[-_+.]+", ".", value)
    value = re.sub(r"([^\d.])(\d)", r"\1.\2", value)
    value = re.sub(r"(\d)([^\d.])", r"\1.\2", value)
    return tuple(value.split("."))


def _php_rank(part):
    return _PHP_SPECIAL.get(part, -1)


def php_cmp(a, b):
    for x, y in zip(a, b):
        if x.isdecimal() and y.isdecimal():
            result = _cmp(int(x), int(y))
        elif not x.isdecimal() and not y.isdecimal():
            result = _cmp(_php_rank(x), _php_rank(y))
        elif x.isdecimal():
            result = _cmp(_php_rank("#"), _php_rank(y))
        else:
            result = _cmp(_php_rank(x), _php_rank("#"))
        if result:
            return result
    if len(a) > len(b):
        return 1 if a[len(b)].isdecimal() else php_cmp(a[len(b):], ("#",))
    if len(a) < len(b):
        return -1 if b[len(a)].isdecimal() else php_cmp(("#",), b[len(a):])
    return 0


COMPARATORS = {
    "SEMVER": (semver_parse, _cmp),
    "npm": (semver_parse, _cmp),
    "Packagist": (composer_parse, _cmp),
    "PackagistOSV": (php_parts, php_cmp),
    "Debian": (dpkg_parse, dpkg_cmp),
}

_MIN, _MAX = ("min",), ("max",)


def _bounded_cmp(cmp):
    def compare(x, y):
        if x is _MIN or y is _MAX:
            return 0 if x is y else -1
        if x is _MAX or y is _MIN:
            return 0 if x is y else 1
        return cmp(x, y)
    return compare


# ---------------------------------------------------------------------------
# OSV evaluation (schema "Evaluation" pseudocode), made conservative where the
# schema itself warns about false negatives.
# ---------------------------------------------------------------------------

def family_of(ecosystem):
    if ecosystem == "npm":
        return "npm"
    if ecosystem == "Packagist" or ecosystem.startswith("Packagist:"):
        return "Packagist"
    # The schema makes the Debian release suffix optional; an unsuffixed entry is unscoped.
    if ecosystem == "Debian" or ecosystem.startswith("Debian:"):
        return "Debian"
    return None


def package_key(family, ecosystem, name):
    if family == "Packagist":
        return ("Packagist", name.lower())
    if family == "Debian":
        return (ecosystem, name)
    return (family, name)


def _order_ties(events, cmp, lead):
    """Sort events by version, putting events of kind `lead` first among those sharing a version."""
    return sorted(events, key=cmp_to_key(lambda x, y: cmp(x[0], y[0]) or _cmp(x[1] != lead, y[1] != lead)))


def _walk(events, v, cmp):
    vulnerable, setter = False, None
    for key, kind, _ in events:
        if kind == "introduced" and cmp(v, key) >= 0:
            vulnerable, setter = True, kind
        elif kind == "fixed" and cmp(v, key) >= 0:
            vulnerable, setter = False, kind
        elif kind == "last_affected" and cmp(v, key) > 0:
            vulnerable, setter = False, kind
    return vulnerable, setter


def evaluate_range(rng, version, ordering, ceiling_clear=False):
    """Return (state, reason, fixed_above) for one range; state is affected, clear or inconclusive.

    The schema warns that versions above last_affected may be false negatives, so they are
    inconclusive here. ceiling_clear applies the schema's literal reading instead; it is used
    only for malicious-release reports (MAL-), which enumerate the compromised releases.
    """
    rtype = rng.get("type")
    if rtype == "GIT":
        return "inconclusive", "A GIT range needs the source repository.", []
    if rtype not in ("SEMVER", "ECOSYSTEM"):
        return "inconclusive", "Unsupported range type.", []
    kinds = [next(iter(event)) for event in rng.get("events", [])]
    if "introduced" not in kinds:
        # The OSV schema requires every range to contain an introduced event.
        return "inconclusive", "The range has no introduced event, which the OSV schema requires.", []
    if "fixed" in kinds and "last_affected" in kinds:
        return "inconclusive", "The range mixes fixed and last_affected events, which the OSV schema forbids.", []
    parse, raw_cmp = COMPARATORS["SEMVER" if rtype == "SEMVER" else ordering]
    cmp = _bounded_cmp(raw_cmp)
    v = parse(version)
    if v is None:
        return "inconclusive", "The version is outside the syntax this range type defines.", []
    events, limits = [], []
    for event in rng.get("events", []):
        (kind, raw), = event.items()
        if kind == "introduced" and raw == "0":
            key = _MIN
        elif kind == "limit" and "*" in raw:
            key = _MAX
        else:
            key = parse(raw)
            if key is None:
                shown = raw if len(raw) <= 64 else raw[:64] + "..."
                return "inconclusive", f"Event version {shown!r} is outside the expected syntax.", []
        (limits if kind == "limit" else events).append((key, kind, raw))
    if limits and not any(cmp(v, key) < 0 for key, _, _ in limits):
        return "clear", "At or above every range limit.", []
    events.sort(key=cmp_to_key(lambda x, y: cmp(x[0], y[0])))
    # The schema leaves the order of events that share a version open. Events of one kind give the
    # same walk in any order. For introduced together with last_affected, walk both extreme orders
    # and require them to agree; that settles the shared version itself. Introduced together with
    # fixed describes an empty or contradictory range and stays inconclusive.
    orders = [events]
    for first, second in zip(events, events[1:]):
        if cmp(first[0], second[0]) != 0 or first[1] == second[1]:
            continue
        if {first[1], second[1]} == {"introduced", "last_affected"}:
            orders = [_order_ties(events, cmp, lead) for lead in ("introduced", "last_affected")]
            continue
        return "inconclusive", "The range has an introduced and a fixed event at the same version.", []
    outcomes = {_walk(order, v, cmp) for order in orders}
    if len(outcomes) > 1:
        return "inconclusive", "Events that share a version give different results depending on their order.", []
    vulnerable, setter = outcomes.pop()
    fixed_above = [raw for key, kind, raw in events if kind == "fixed" and cmp(key, v) > 0]
    if vulnerable:
        return "affected", "The version falls inside an affected range.", fixed_above
    if setter == "last_affected" and not ceiling_clear:
        return "inconclusive", "Above a last_affected ceiling and no fixed version is published.", []
    return "clear", "Outside this range.", []


def evaluate_entry(entry, version, family, ceiling_clear=False):
    """Packagist entries are evaluated under Composer's ordering and OSV's own Packagist
    ordering; a verdict needs both to agree, otherwise the entry is inconclusive."""
    first = evaluate_entry_under(entry, version, family, ceiling_clear)
    if family != "Packagist":
        return first
    second = evaluate_entry_under(entry, version, "PackagistOSV", ceiling_clear)
    if first[0] == second[0]:
        return first
    if "inconclusive" in (first[0], second[0]):
        return first if first[0] == "inconclusive" else second
    return ("inconclusive", "Composer's version ordering and OSV's Packagist ordering disagree for this version.", [])


def _composer_dev(value):
    low = value.lower()
    return low.startswith("dev-") or low.endswith("dev")


def evaluate_entry_under(entry, version, ordering, ceiling_clear=False):
    parse, raw_cmp = COMPARATORS[ordering]
    listed = entry.get("versions") or []
    ranges = entry.get("ranges") or []
    states = [evaluate_range(r, version, ordering, ceiling_clear) for r in ranges]
    hits = [s for s in states if s[0] == "affected"]
    parsed = parse(version)
    unparsed = False
    for item in listed:
        other = parse(item)
        if item == version or (parsed is not None and other is not None and raw_cmp(parsed, other) == 0):
            return "affected", "The version is enumerated by the record.", hits[0][2] if hits else []
        # A listed version outside the syntax cannot be compared, so it cannot be ruled out. Composer
        # development versions ("dev-main", "2.2-dev") are the exception: Composer never treats one
        # as equal to a tagged release, so they match by exact string only.
        if other is None and not (ordering == "Packagist" and _composer_dev(item)):
            unparsed = True
    if hits:
        return hits[0]
    if unparsed:
        return "inconclusive", "A listed version is outside the expected syntax, so it cannot be ruled out.", []
    if not ranges:
        if listed:
            return "clear", "Not among the enumerated versions.", []
        return "inconclusive", "The record lists neither ranges nor versions.", []
    for state in states:
        if state[0] == "inconclusive":
            return state
    return "clear", "Outside every listed range.", []


# ---------------------------------------------------------------------------
# Snapshot loading and validation
# ---------------------------------------------------------------------------

def _str_list(value):
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def _reject_constant(name):
    raise ValueError(f"{name} is not valid JSON.")


def _finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("Number out of range.")
    return value


def strict_json(raw, unique=False):
    """RFC 8259 JSON in UTF-8. One leading byte order mark is accepted; NaN, Infinity and
    numbers that overflow to infinity are rejected."""
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_keys if unique else None,
                      parse_constant=_reject_constant, parse_float=_finite_float)


def _short(value, limit=64):
    """Echo a record-supplied value only when it is a short string."""
    return value if isinstance(value, str) and len(value) <= limit else None


_RFC3339 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?"
                      r"([Zz]|[+-][0-9]{2}:[0-9]{2})")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def rfc3339_ns(value):
    """Nanoseconds since 1970 for an RFC 3339 timestamp, or None when the value is not one.
    Fractions are kept to the nanosecond, so '...00Z' and '...00.500Z' order correctly."""
    m = _RFC3339.fullmatch(value) if isinstance(value, str) and len(value) <= 64 else None
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(x) for x in m.groups()[:6])
    zone, offset = m.group(8), 0
    if zone not in ("Z", "z"):
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            return None
        offset = (hours * 60 + minutes) * 60 * (1 if zone[0] == "+" else -1)
    try:
        moment = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=timezone.utc)
    except ValueError:
        return None
    if second > 60:
        return None
    seconds = (moment - _EPOCH) // timedelta(seconds=1) - offset + (second == 60)
    return seconds * 1_000_000_000 + int((m.group(7) or "")[:9].ljust(9, "0"))


def valid_record(rec):
    if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not 0 < len(rec["id"]) <= MAX_FIELD:
        return False
    for key in ("aliases", "upstream"):
        if key in rec and not _str_list(rec[key]):
            return False
    affected = rec.get("affected", [])
    if not isinstance(affected, list):
        return False
    for entry in affected:
        if not isinstance(entry, dict) or not isinstance(entry.get("package", {}), dict):
            return False
        pkg = entry.get("package", {})
        if not isinstance(pkg.get("ecosystem", ""), str) or not isinstance(pkg.get("name", ""), str):
            return False
        if "versions" in entry and not _str_list(entry["versions"]):
            return False
        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list):
            return False
        for rng in ranges:
            if not isinstance(rng, dict) or not isinstance(rng.get("events", []), list):
                return False
            for event in rng.get("events", []):
                if (not isinstance(event, dict) or len(event) != 1 or next(iter(event)) not in EVENT_KINDS
                        or not isinstance(next(iter(event.values())), str)):
                    return False
    return True


TRACKER_COVERAGE = 0.25


class Snapshot:
    def __init__(self):
        self.index = {}
        self.copies = {}
        self.sources = []
        self.complete = {}
        # Per Debian release: Debian security-tracker records (ID prefix "DEBIAN-"), counted only
        # from sources declared to cover Debian. DSA/DLA records only describe fixed issues, so
        # they cannot show that a release's open issues are tracked.
        self.tracker = {}
        # Ecosystem strings (for example a Packagist:<repository> suffix) seen in each declared family.
        self.declared = {family: set() for family in FAMILIES}

    def debian_release_covered(self, eco):
        best = max(self.tracker.values(), default=0)
        return self.tracker.get(eco, 0) >= max(1, TRACKER_COVERAGE * best)

    def add_record(self, rec, stats):
        if not valid_record(rec):
            stats["invalid"] += 1
            return
        stats["records"] += 1
        for fam in {family_of(e.get("package", {}).get("ecosystem", "")) for e in rec.get("affected", [])} - {None}:
            stats["family_records"][fam] = stats["family_records"].get(fam, 0) + 1
        # The schema makes "withdrawn" an RFC 3339 time. Any other value is ignored and counted,
        # so the record stays active. No clock is read: a well-formed time is always honoured.
        withdrawn = rec.get("withdrawn")
        withdrawn_at = rfc3339_ns(withdrawn) if withdrawn is not None and withdrawn != "" else None
        if withdrawn is not None and withdrawn != "" and withdrawn_at is None:
            stats["withdrawn_ignored"] += 1
        active = withdrawn_at is None
        modified_at = rfc3339_ns(rec.get("modified"))
        self.copies.setdefault(rec["id"], []).append((modified_at, active, rec))
        if not active:
            stats["withdrawn"] += 1
            return
        for entry in rec.get("affected", []):
            for rng in entry.get("ranges", []):
                kinds = [next(iter(event)) for event in rng.get("events", [])]
                if "introduced" not in kinds or ("fixed" in kinds and "last_affected" in kinds):
                    stats["damaged_ranges"] += 1
        if modified_at is not None and modified_at > stats["newest_modified_ns"]:
            stats["newest_modified_ns"], stats["newest_modified"] = modified_at, rec["modified"]
        for entry in rec.get("affected", []):
            eco = entry.get("package", {}).get("ecosystem", "")
            family = family_of(eco)
            # Ecosystem strings are short; the bound keeps record text out of reported keys.
            if family in stats["declares"] and len(eco) <= 64:
                self.declared[family].add(eco)
        if "Debian" in stats["declares"] and rec["id"].startswith("DEBIAN-"):
            for eco in {e.get("package", {}).get("ecosystem", "") for e in rec.get("affected", [])}:
                if eco.startswith("Debian:") and len(eco) <= 64:
                    self.tracker[eco] = self.tracker.get(eco, 0) + 1

    def resolve(self):
        """Index, for each advisory ID, the newest copy across every source, by parsed `modified`
        time. A newer withdrawal therefore wins whatever the load order, and a newer copy that drops
        a package removes the older copy's match. When the newest copies tie, or any copy's time
        cannot be read, every candidate copy is kept and the most severe result wins, so a tie
        between an active and a withdrawn copy leaves the record active."""
        for rid, copies in self.copies.items():
            times = [t for t, _, _ in copies]
            winners = copies if None in times else [c for c in copies if c[0] == max(times)]
            live, seen = [], set()
            for _, active, rec in winners:
                text = json.dumps(rec, sort_keys=True) if len(winners) > 1 else None
                if active and text not in seen:
                    live.append(rec)
                    if text is not None:
                        seen.add(text)
            for rec in live:
                for entry in rec.get("affected", []):
                    pkg = entry.get("package", {})
                    eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
                    family = family_of(eco)
                    if family is None or not name:
                        continue
                    held = self.index.setdefault(package_key(family, eco, name), {}).setdefault(rid, [])
                    if not any(r is rec for r in held):
                        held.append(rec)
        self.copies = {}

    @staticmethod
    def _new_stats(family, source, declares):
        return {"family": family, "source": source, "sha256": None, "records": 0, "withdrawn": 0,
                "withdrawn_ignored": 0, "invalid": 0, "unreadable": 0, "oversized": 0, "skipped": 0,
                "damaged_ranges": 0, "newest_modified": "", "newest_modified_ns": -1, "family_records": {},
                "declares": set(declares)}

    def _store(self, raw, stats):
        if raw is None:
            stats["unreadable"] += 1
        elif len(raw) > MAX_RECORD:
            stats["oversized"] += 1
        else:
            self._parse_into(raw, stats)

    def load(self, family, path):
        # Every entry must be read as a record. Anything skipped, unreadable or oversized leaves
        # the family incomplete, so it can only lead to "unknown", never to a clean result.
        stats = self._new_stats(family, path.name, (family,))
        if path.is_dir():
            for item in sorted(path.iterdir()):
                if not item.is_file() or item.suffix.lower() != ".json":
                    stats["skipped"] += 1
                    continue
                try:
                    with open(item, "rb") as handle:
                        raw = handle.read(MAX_RECORD + 1)
                except OSError:
                    raw = None
                self._store(raw, stats)
        else:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
            stats["sha256"] = digest.hexdigest()
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if not info.filename.lower().endswith(".json"):
                        stats["skipped"] += 1
                        continue
                    if info.file_size > MAX_RECORD:
                        stats["oversized"] += 1
                        continue
                    # Read at most MAX_RECORD + 1 bytes whatever the header claims, so a falsified
                    # size cannot inflate an entry in memory. Encrypted, unsupported or corrupt
                    # entries count as unreadable.
                    try:
                        with archive.open(info) as member:
                            raw = member.read(MAX_RECORD + 1)
                    except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError):
                        raw = None
                    self._store(raw, stats)
        self._finish(family, stats)

    def load_inline(self, snapshot):
        covers = list(dict.fromkeys(snapshot["covers"]))
        shared = self._new_stats("+".join(covers), "inline:" + snapshot.get("label", "request"), covers)
        for rec in snapshot.get("advisories", []):
            self.add_record(rec, shared)
        # Report completeness per covered family, so the metadata matches each family's verdicts.
        for family in covers:
            stats = dict(shared, family=family, family_records=dict(shared["family_records"]), declares=set(covers))
            self._finish(family, stats, declared_export=False)

    def _parse_into(self, raw, stats):
        try:
            rec = strict_json(raw)
        except (ValueError, RecursionError):
            stats["unreadable"] += 1
            return
        self.add_record(rec, stats)

    def _finish(self, family, stats, report=True, declared_export=True):
        # A declared export must be dominated by its family, so that a mislabeled file
        # (e.g. the Packagist export passed as npm) cannot claim coverage.
        in_family = stats["family_records"].get(family, 0)
        needed = 0.9 * stats["records"] if declared_export else 1
        ok = (stats["records"] > 0 and in_family >= needed
              and not (stats["invalid"] or stats["unreadable"] or stats["oversized"] or stats["skipped"]))
        self.complete[family] = (self.complete[family] and ok) if family in self.complete else ok
        if report:
            stats["complete"] = ok
            stats["newest_modified"] = stats["newest_modified"] or None
            stats["family_records"] = dict(sorted(stats["family_records"].items()))
            stats.pop("declares", None)
            stats.pop("newest_modified_ns", None)
            if family == "Debian":
                stats["debian_tracker_records"] = dict(sorted(self.tracker.items()))
            self.sources.append(stats)


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

def fields(obj, allowed):
    if not isinstance(obj, dict) or obj.keys() - set(allowed):
        raise ValueError("Unexpected input shape.")
    return obj


def alias(value):
    return value if isinstance(value, str) and ALIAS.fullmatch(value) else None


_KEV_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def load_kev(data):
    """Map each listed CVE to its earliest well-formed dateAdded, or None. Membership, not the
    date, decides whether a CVE is listed."""
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("KEV catalog lacks a vulnerabilities list.")
    kev = {}
    for item in vulns:
        if isinstance(item, dict) and isinstance(item.get("cveID"), str):
            date = item.get("dateAdded")
            date = date if isinstance(date, str) and _KEV_DATE.fullmatch(date) else None
            dates = [d for d in (kev.get(item["cveID"]), date) if d]
            kev[item["cveID"]] = min(dates) if dates else None
    return kev, _short(data.get("catalogVersion"))


_DEBIAN_SOURCE = re.compile(r"[a-z0-9][a-z0-9+.-]+")


def record_cves(rec):
    ids = [rec["id"]] + rec.get("aliases", []) + rec.get("upstream", [])
    return sorted({x for x in ids if isinstance(x, str) and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", x)})


def review_package(pkg, snapshot, kev, bound):
    eco, name, version = pkg["ecosystem"], pkg["name"], pkg["version"]
    family = family_of(eco)
    row = {"ecosystem": eco, "name": name, "version": version, "status": "unknown", "reason": "", "advisories": []}
    if not bound:
        row["reason"] = "The inventory is not tied to the deployed build."
        return row
    if family is None:
        row["reason"] = "This ecosystem is not supported by this release of the checker."
        return row
    if family == "Debian" and pkg.get("source_package") is not True:
        row["reason"] = "Debian advisories name source packages. Supply the source package name and source version with source_package true."
        return row
    if family == "Debian" and eco == "Debian":
        row["reason"] = "Name the Debian release, for example Debian:12. Coverage is judged per release."
        return row
    if family == "Debian" and not _DEBIAN_SOURCE.fullmatch(name):
        row["reason"] = ("Debian source package names have at least two characters: lower-case letters, digits, "
                         "'+', '-' and '.', starting with a letter or digit (Debian Policy 5.6.1).")
        return row
    # The OSV schema's wildcard name "*" covers every package in the ecosystem (for example an
    # end-of-life release), and an unsuffixed "Debian" entry is not scoped to a release, so both
    # kinds of record apply to this package too.
    own_key = package_key(family, eco, name)
    keys = {own_key, package_key(family, eco, "*")}
    if family == "Debian":
        keys |= {("Debian", name), ("Debian", "*")}
    records = {}
    for key in keys:
        for rid, held in snapshot.index.get(key, {}).items():
            copies = records.setdefault(rid, [])
            copies.extend(rec for rec in held if not any(rec is c for c in copies))
    affected, inconclusive = [], []
    for rid in sorted(records):
        best = None
        for rec in records[rid]:
            results, wildcard = [], False
            for entry in rec.get("affected", []):
                p = entry.get("package", {})
                if family_of(p.get("ecosystem", "")) != family:
                    continue
                entry_key = package_key(family, p.get("ecosystem", ""), p.get("name", ""))
                if entry_key not in keys:
                    continue
                wildcard = wildcard or entry_key[1] == "*"
                outcome = evaluate_entry(entry, version, family, ceiling_clear=rid.startswith("MAL-"))
                results.append((outcome, entry))
            if not results:
                continue
            state, decisive = next((r for r in results if r[0][0] == "affected"), None) or \
                next((r for r in results if r[0][0] == "inconclusive"), None) or results[0]
            # Tied copies of one ID: the most severe result wins.
            rank = {"clear": 0, "inconclusive": 1, "affected": 2}[state[0]]
            if best is None or rank > best[0]:
                best = (rank, state, decisive, rec, wildcard)
        if best is None or best[1][0] == "clear":
            continue
        _, state, decisive, rec, wildcard = best
        cves = record_cves(rec)
        listed = [c for c in cves if c in kev]
        kev_dates = sorted(kev[c] for c in listed if kev[c])
        # Urgency comes from the entry that produced the verdict, not from another release's entry.
        specific = decisive.get("ecosystem_specific")
        urgency = _short(specific.get("urgency")) if isinstance(specific, dict) else None
        summary = rec.get("summary")
        item = {"id": rec["id"], "cves": cves, "status": "affected" if state[0] == "affected" else "inconclusive",
                "reason": state[1], "fixed_in": state[2][:5], "kev_listed": bool(listed),
                "kev_date_added": kev_dates[0] if kev_dates else None,
                "malicious": rec["id"].startswith("MAL-"),
                "summary": summary[:200] if isinstance(summary, str) else "",
                "modified": _short(rec.get("modified"))}
        if urgency:
            item["distribution_urgency"] = urgency
        if wildcard:
            item["wildcard_package"] = True
        (affected if state[0] == "affected" else inconclusive).append(item)
    row["advisories"] = affected + inconclusive
    if affected:
        row["status"] = "affected"
        row["reason"] = f"{len(affected)} advisory record(s) in the snapshot affect this version."
    elif not snapshot.complete.get(family):
        row["reason"] = "No complete snapshot for this ecosystem was loaded."
    elif family == "Debian" and not snapshot.debian_release_covered(eco):
        best = max(snapshot.tracker.values(), default=0)
        if best == 0:
            row["reason"] = ("The loaded Debian data has no security-tracker (DEBIAN-*) records, so it cannot show "
                             f"that open issues for {eco} are tracked.")
        else:
            row["reason"] = (f"The loaded Debian data does not track open issues for {eco}: "
                             f"{snapshot.tracker.get(eco, 0)} security-tracker records, against {best} for the "
                             "best-covered release. Fixed-advisory (DSA/DLA) records alone cannot rule out open issues.")
    elif family == "Packagist" and eco != "Packagist" and eco not in snapshot.declared["Packagist"]:
        row["reason"] = ("The loaded Packagist data has no records for this Composer repository. "
                         "OSV's export covers packagist.org and packages.drupal.org.")
    elif COMPARATORS[family][0](version) is None:
        row["reason"] = "The version is outside the syntax this ecosystem defines."
    elif inconclusive:
        row["reason"] = "Some advisory records could not be evaluated conclusively."
    else:
        row["status"] = "no_matching_advisory"
        row["reason"] = "No record in the loaded snapshot affects this version."
    return row


def review(request, osv_args, kev_path):
    fields(request, ("inventory", "snapshot", "kev"))
    inventory = fields(request.get("inventory"), ("asset", "build", "ref", "deployment_verified", "packages"))
    packages = inventory.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("Supply between 1 and 20000 packages.")
    for pkg in packages:
        fields(pkg, ("ecosystem", "name", "version", "source_package"))
        for key in ("ecosystem", "name", "version"):
            if not isinstance(pkg.get(key), str) or not pkg[key] or len(pkg[key]) > MAX_FIELD:
                raise ValueError("Each package needs ecosystem, name and version strings.")
        if "source_package" in pkg and type(pkg["source_package"]) is not bool:
            raise ValueError("source_package must be true or false.")
    snapshot = Snapshot()
    inline = request.get("snapshot")
    if inline is not None:
        fields(inline, ("label", "covers", "advisories"))
        covers = inline.get("covers")
        if (not isinstance(covers, list) or not covers or any(c not in FAMILIES for c in covers)
                or not isinstance(inline.get("advisories"), list)):
            raise ValueError("An inline snapshot needs covers and advisories.")
        if "label" in inline and not alias(inline["label"]):
            raise ValueError("Invalid snapshot label.")
        snapshot.load_inline(inline)
    for family, path in osv_args:
        snapshot.load(family, path)
    if not snapshot.sources:
        raise ValueError("Supply an OSV snapshot with --osv or an inline snapshot.")
    snapshot.resolve()
    kev, kev_meta = {}, None
    if "kev" in request:
        kev, version = load_kev(request["kev"])
        kev_meta = {"catalog_version": version, "source": "inline", "sha256": None}
    if kev_path is not None:
        with open(kev_path, "rb") as handle:
            raw = handle.read(MAX_KEV + 1)
        if len(raw) > MAX_KEV:
            raise ValueError("The KEV catalog exceeds the supported size.")
        file_kev, version = load_kev(strict_json(raw))
        kev.update(file_kev)
        kev_meta = {"catalog_version": version, "source": kev_path.name, "sha256": hashlib.sha256(raw).hexdigest()}
    scope = {k: alias(inventory.get(k)) for k in ("asset", "build")}
    ref = alias(inventory.get("ref"))
    bound = all(scope.values()) and ref is not None and inventory.get("deployment_verified") is True
    rows = [review_package(pkg, snapshot, kev, bound) for pkg in packages]
    summary = {"packages": len(rows)}
    for status in ("affected", "unknown", "no_matching_advisory"):
        summary[status] = sum(r["status"] == status for r in rows)
    summary["kev_listed"] = sum(any(a["kev_listed"] and a["status"] == "affected" for a in r["advisories"])
                                for r in rows)
    summary["malicious_listed"] = sum(any(a["malicious"] and a["status"] == "affected" for a in r["advisories"])
                                      for r in rows)
    return {
        "skill": "package-advisory-review", "review_level": "unreviewed",
        "scope": scope, "evidence_refs": {"inventory": ref},
        "inventory_binding": "verified" if bound else "unverified",
        "snapshots": snapshot.sources, "kev": kev_meta, "summary": summary, "packages": rows,
        "limitations": [
            "Results are mechanical matches against OSV records that ARTEX maintainers have not reviewed.",
            "no_matching_advisory covers only the loaded snapshot at its newest modified time. It is not a fix verdict.",
            "Distribution results depend on the distribution's own records and source package versions.",
            "Exposure of a deployed feature needs separate configuration evidence.",
        ],
    }


def parse_args(argv):
    osv, kev = [], None
    items = list(argv)
    while items:
        flag = items.pop(0)
        if flag not in ("--osv", "--kev") or not items:
            raise ValueError("Usage: check.py [--osv FAMILY=PATH ...] [--kev PATH] < request.json")
        value = items.pop(0)
        if flag == "--kev":
            if not value.strip():
                raise ValueError("Name the KEV catalog file.")
            kev = Path(value)
        else:
            family, sep, path = value.partition("=")
            # An empty PATH would resolve to the current directory and be read as an export.
            if not sep or family not in FAMILIES or not path.strip():
                raise ValueError("Use --osv npm=PATH, --osv Packagist=PATH or --osv Debian=PATH.")
            osv.append((family, Path(path)))
    return osv, kev


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate input key.")
    return obj


def main(argv=None):
    # Output contract: exactly one JSON object on stdout, exit 0 with a result or exit 2 with
    # invalid_input. RuntimeError covers RecursionError and NotImplementedError.
    try:
        osv_args, kev_path = parse_args(sys.argv[1:] if argv is None else argv)
        stream = getattr(sys.stdin, "buffer", None)
        if stream is None:
            raise ValueError("No request on standard input.")
        raw = stream.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            raise ValueError("Input exceeds the supported size.")
        result = review(strict_json(raw, unique=True), osv_args, kev_path)
        text = json.dumps(result, allow_nan=False)
    except (ValueError, RuntimeError, OSError, zipfile.BadZipFile, zlib.error, EOFError, KeyError, TypeError):
        print(json.dumps({"error": "invalid_input",
                          "detail": "Check the inventory, snapshot paths and options. No verdict was produced."}))
        return 2
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
