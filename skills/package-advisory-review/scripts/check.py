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
import re
import sys
import zipfile
from functools import cmp_to_key
from pathlib import Path

MAX_STDIN = 8 * 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
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


_COMPOSER = re.compile(
    r"[vV]?([0-9]{1,9})(?:\.([0-9]{1,9}))?(?:\.([0-9]{1,9}))?(?:\.([0-9]{1,9}))?"
    r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?[0-9]{1,9})*))?", re.IGNORECASE)
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


COMPARATORS = {
    "SEMVER": (semver_parse, _cmp),
    "npm": (semver_parse, _cmp),
    "Packagist": (composer_parse, _cmp),
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
    if ecosystem.startswith("Debian:"):
        return "Debian"
    return None


def package_key(family, ecosystem, name):
    if family == "Packagist":
        return ("Packagist", name.lower())
    if family == "Debian":
        return (ecosystem, name)
    return (family, name)


def evaluate_range(rng, version, family, ceiling_clear=False):
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
    parse, raw_cmp = COMPARATORS["SEMVER" if rtype == "SEMVER" else family]
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
                return "inconclusive", f"Event version {raw!r} is outside the expected syntax.", []
        (limits if kind == "limit" else events).append((key, kind, raw))
    if limits and not any(cmp(v, key) < 0 for key, _, _ in limits):
        return "clear", "At or above every range limit.", []
    events.sort(key=cmp_to_key(lambda x, y: cmp(x[0], y[0])))
    for first, second in zip(events, events[1:]):
        if cmp(first[0], second[0]) == 0:
            return "inconclusive", "Two events in one range share a version.", []
    vulnerable, setter = False, None
    for key, kind, _ in events:
        if kind == "introduced" and cmp(v, key) >= 0:
            vulnerable, setter = True, kind
        elif kind == "fixed" and cmp(v, key) >= 0:
            vulnerable, setter = False, kind
        elif kind == "last_affected" and cmp(v, key) > 0:
            vulnerable, setter = False, kind
    fixed_above = [raw for key, kind, raw in events if kind == "fixed" and cmp(key, v) > 0]
    if vulnerable:
        return "affected", "The version falls inside an affected range.", fixed_above
    if setter == "last_affected" and not ceiling_clear:
        return "inconclusive", "Above a last_affected ceiling and no fixed version is published.", []
    return "clear", "Outside this range.", []


def evaluate_entry(entry, version, family, ceiling_clear=False):
    parse, raw_cmp = COMPARATORS[family]
    listed = entry.get("versions") or []
    ranges = entry.get("ranges") or []
    states = [evaluate_range(r, version, family, ceiling_clear) for r in ranges]
    hits = [s for s in states if s[0] == "affected"]
    parsed = parse(version)
    for item in listed:
        other = parse(item)
        if item == version or (parsed is not None and other is not None and raw_cmp(parsed, other) == 0):
            return "affected", "The version is enumerated by the record.", hits[0][2] if hits else []
    if hits:
        return hits[0]
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


def valid_record(rec):
    if not isinstance(rec, dict) or not isinstance(rec.get("id"), str):
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


class Snapshot:
    def __init__(self):
        self.index = {}
        self.ecosystems = set()
        self.sources = []
        self.complete = {}

    def add_record(self, rec, stats):
        if not valid_record(rec):
            stats["invalid"] += 1
            return
        stats["records"] += 1
        for fam in {family_of(e.get("package", {}).get("ecosystem", "")) for e in rec.get("affected", [])} - {None}:
            stats["family_records"][fam] = stats["family_records"].get(fam, 0) + 1
        if rec.get("withdrawn"):
            stats["withdrawn"] += 1
            return
        modified = rec.get("modified")
        if isinstance(modified, str) and modified > stats["newest_modified"]:
            stats["newest_modified"] = modified
        for entry in rec.get("affected", []):
            pkg = entry.get("package", {})
            eco, name = pkg.get("ecosystem", ""), pkg.get("name", "")
            family = family_of(eco)
            if family is None or not name:
                continue
            self.ecosystems.add(eco)
            bucket = self.index.setdefault(package_key(family, eco, name), {})
            current = bucket.get(rec["id"])
            if current is None or str(rec.get("modified", "")) > str(current.get("modified", "")):
                bucket[rec["id"]] = rec

    def load(self, family, path):
        stats = {"family": family, "source": path.name, "sha256": None, "records": 0, "withdrawn": 0,
                 "invalid": 0, "unreadable": 0, "oversized": 0, "newest_modified": "", "family_records": {}}
        if path.is_dir():
            for item in sorted(path.glob("*.json")):
                if item.stat().st_size > MAX_RECORD:
                    stats["oversized"] += 1
                    continue
                self._parse_into(item.read_bytes(), stats)
        else:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(block)
            stats["sha256"] = digest.hexdigest()
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or not info.filename.endswith(".json"):
                        continue
                    if info.file_size > MAX_RECORD:
                        stats["oversized"] += 1
                        continue
                    self._parse_into(archive.read(info), stats)
        self._finish(family, stats)

    def load_inline(self, snapshot):
        stats = {"family": "+".join(snapshot["covers"]), "source": "inline:" + snapshot.get("label", "request"),
                 "sha256": None, "records": 0, "withdrawn": 0, "invalid": 0, "unreadable": 0,
                 "oversized": 0, "newest_modified": "", "family_records": {}}
        for rec in snapshot.get("advisories", []):
            self.add_record(rec, stats)
        for family in snapshot["covers"]:
            self._finish(family, stats, report=family == snapshot["covers"][0], declared_export=False)

    def _parse_into(self, raw, stats):
        try:
            rec = json.loads(raw)
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
              and not (stats["invalid"] or stats["unreadable"] or stats["oversized"]))
        self.complete[family] = (self.complete[family] and ok) if family in self.complete else ok
        if report:
            stats["complete"] = ok
            stats["newest_modified"] = stats["newest_modified"] or None
            stats["family_records"] = dict(sorted(stats["family_records"].items()))
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


def load_kev(data):
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        raise ValueError("KEV catalog lacks a vulnerabilities list.")
    kev = {}
    for item in vulns:
        if isinstance(item, dict) and isinstance(item.get("cveID"), str):
            kev[item["cveID"]] = str(item.get("dateAdded", ""))
    return kev, str(data.get("catalogVersion", ""))


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
    if eco not in snapshot.ecosystems and family == "Debian":
        row["reason"] = "The loaded snapshot has no records for this ecosystem string."
        return row
    records = snapshot.index.get(package_key(family, eco, name), {})
    affected, inconclusive = [], []
    for rec in sorted(records.values(), key=lambda r: r["id"]):
        if rec.get("withdrawn"):
            continue
        results = []
        for entry in rec.get("affected", []):
            p = entry.get("package", {})
            if family_of(p.get("ecosystem", "")) != family:
                continue
            if package_key(family, p.get("ecosystem", ""), p.get("name", "")) != package_key(family, eco, name):
                continue
            results.append(evaluate_entry(entry, version, family, ceiling_clear=rec["id"].startswith("MAL-")))
        if not results:
            continue
        state = next((r for r in results if r[0] == "affected"), None) or \
            next((r for r in results if r[0] == "inconclusive"), None) or results[0]
        if state[0] == "clear":
            continue
        cves = record_cves(rec)
        kev_dates = sorted({kev[c] for c in cves if c in kev})
        urgency = next((e.get("ecosystem_specific", {}).get("urgency") for e in rec.get("affected", [])
                        if isinstance(e.get("ecosystem_specific"), dict)
                        and e.get("ecosystem_specific", {}).get("urgency")), None)
        item = {"id": rec["id"], "cves": cves, "status": "affected" if state[0] == "affected" else "inconclusive",
                "reason": state[1], "fixed_in": state[2][:5], "kev_date_added": kev_dates[0] if kev_dates else None,
                "malicious": rec["id"].startswith("MAL-"), "summary": str(rec.get("summary", ""))[:200],
                "modified": rec.get("modified")}
        if urgency:
            item["distribution_urgency"] = urgency
        (affected if state[0] == "affected" else inconclusive).append(item)
    row["advisories"] = affected + inconclusive
    if affected:
        row["status"] = "affected"
        row["reason"] = f"{len(affected)} advisory record(s) in the snapshot affect this version."
    elif not snapshot.complete.get(family):
        row["reason"] = "No complete snapshot for this ecosystem was loaded."
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
    kev, kev_meta = {}, None
    if "kev" in request:
        kev, version = load_kev(request["kev"])
        kev_meta = {"catalog_version": version, "source": "inline", "sha256": None}
    if kev_path is not None:
        raw = kev_path.read_bytes()
        file_kev, version = load_kev(json.loads(raw))
        kev.update(file_kev)
        kev_meta = {"catalog_version": version, "source": kev_path.name, "sha256": hashlib.sha256(raw).hexdigest()}
    scope = {k: alias(inventory.get(k)) for k in ("asset", "build")}
    ref = alias(inventory.get("ref"))
    bound = all(scope.values()) and ref is not None and inventory.get("deployment_verified") is True
    rows = [review_package(pkg, snapshot, kev, bound) for pkg in packages]
    summary = {"packages": len(rows)}
    for status in ("affected", "unknown", "no_matching_advisory"):
        summary[status] = sum(r["status"] == status for r in rows)
    summary["kev_listed"] = sum(any(a["kev_date_added"] and a["status"] == "affected" for a in r["advisories"])
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
            kev = Path(value)
        else:
            family, sep, path = value.partition("=")
            if not sep or family not in FAMILIES:
                raise ValueError("Use --osv npm=PATH, --osv Packagist=PATH or --osv Debian=PATH.")
            osv.append((family, Path(path)))
    return osv, kev


def unique_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("Duplicate input key.")
    return obj


def main(argv=None):
    try:
        osv_args, kev_path = parse_args(sys.argv[1:] if argv is None else argv)
        raw = sys.stdin.buffer.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            raise ValueError("Input exceeds the supported size.")
        result = review(json.loads(raw, object_pairs_hook=unique_keys), osv_args, kev_path)
    except (ValueError, RecursionError, OSError, zipfile.BadZipFile, KeyError, TypeError):
        print(json.dumps({"error": "invalid_input",
                          "detail": "Check the inventory, snapshot paths and options. No verdict was produced."}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
