"""Build, sign and verify a BLHS Hide AI release.

Run with Python's isolated mode; paths are resolved from this file, so any working directory works.

  python -I tools/build_release.py --check          validate src/ and the redirect rules
  python -I tools/build_release.py --dry-run        check, pack and verify, but leave the release files alone
  python -I tools/build_release.py                  check, pack, verify, then write BLHS-Hide-AI.crx + update.xml
  python -I tools/build_release.py --verify X.crx   verify an existing package
  python -I tools/build_release.py --live [--wait 15]
                                                    compare what GitHub Pages serves with the local release files

Standard library only. Packing uses Microsoft Edge's built-in packer with the signing key kept
outside the repo (..\\signing\\BLHS-Hide-AI-signing-key.pem by default), which is never committed.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

EXT_ID = "bhnbbdeipipjjnfapfoajpbejckdflne"
BASE_URL = "https://blhstech.github.io/blhs-hide-ai/"
CRX_NAME = "BLHS-Hide-AI.crx"

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DEFAULT_KEY = REPO.parent / "signing" / "BLHS-Hide-AI-signing-key.pem"
EDGE_PATHS = [
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
]
# DER prefix of a SHA-256 DigestInfo, for PKCS#1 v1.5 signature checks
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")

UPDATE_XML = """<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='{ext_id}'>
    <updatecheck codebase='{base}{crx}' version='{version}' />
  </app>
</gupdate>
"""


class ReleaseError(Exception):
    pass


def id_from_der(der):
    return "".join("abcdefghijklmnop"[int(c, 16)] for c in hashlib.sha256(der).hexdigest()[:32])


def parse_version(v):
    if not re.fullmatch(r"\d+(\.\d+){0,3}", v or ""):
        raise ReleaseError(f"bad version {v!r}")
    return tuple(int(x) for x in v.split("."))


def published_version():
    m = re.search(r"<updatecheck[^>]*\bversion='([\d.]+)'", (REPO / "update.xml").read_text(encoding="utf-8"))
    return m.group(1) if m else None


# ---------- checks ----------

def simulate(rules, url):
    """Return (rule id, redirected url) for the redirect rule matching url, or (None, url)."""
    hits = [r for r in rules if re.search(r["condition"]["regexFilter"], url, re.I)]
    if len(hits) > 1:
        raise ReleaseError(f"{url} matches more than one rule: {[r['id'] for r in hits]}")
    if not hits:
        return None, url
    rule = hits[0]
    match = re.search(rule["condition"]["regexFilter"], url, re.I)
    red = rule["action"]["redirect"]
    if "url" in red:
        return rule["id"], red["url"]
    if "regexSubstitution" in red:
        return rule["id"], re.sub(r"\\(\d)", lambda g: match.group(int(g.group(1))) or "", red["regexSubstitution"])
    if "transform" in red:
        drop = set(red["transform"].get("queryTransform", {}).get("removeParams", []))
        s = urlsplit(url)
        query = [(k, v) for k, v in parse_qsl(s.query, keep_blank_values=True) if k not in drop]
        return rule["id"], urlunsplit((s.scheme, s.netloc, s.path, urlencode(query), s.fragment))
    raise ReleaseError(f"rule {rule['id']}: redirect type not supported by the simulator")


def check():
    problems = []
    manifest = json.loads((SRC / "manifest.json").read_text(encoding="utf-8"))
    version = manifest.get("version")
    parse_version(version)
    if manifest.get("update_url") != BASE_URL + "update.xml":
        problems.append(f"manifest update_url should be {BASE_URL}update.xml")
    if "key" not in manifest or id_from_der(base64.b64decode(manifest["key"])) != EXT_ID:
        problems.append(f"manifest key does not produce extension ID {EXT_ID}")

    for cs in manifest.get("content_scripts", []):
        for f in cs.get("css", []) + cs.get("js", []):
            if not (SRC / f).is_file():
                problems.append(f"content script file missing: src/{f}")
    for f in SRC.rglob("*"):
        if f.suffix.lower() in (".pem", ".key", ".crx"):
            problems.append(f"does not belong in src/: {f.name}")

    rules = []
    for res in manifest.get("declarative_net_request", {}).get("rule_resources", []):
        rules += json.loads((SRC / res["path"]).read_text(encoding="utf-8"))
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        problems.append(f"duplicate rule ids: {ids}")
    for r in rules:
        rx = r["condition"].get("regexFilter", "")
        if re.search(r"\(\?[=!<]", rx):
            problems.append(f"rule {r['id']}: lookarounds aren't supported by Edge's RE2 regex engine")
        re.compile(rx)

    tests = json.loads((REPO / "tools" / "rule_tests.json").read_text(encoding="utf-8"))
    for t in tests:
        rid, out = simulate(rules, t["url"])
        if t["to"] is None and rid is not None:
            problems.append(f"{t['url']} should not redirect, but rule {rid} sends it to {out}")
        elif t["to"] is not None and out != t["to"]:
            problems.append(f"{t['url']} should go to {t['to']}, got {out}")
        if rid is not None and simulate(rules, out)[0] is not None:
            problems.append(f"redirect loop: {t['url']} -> {out}")

    if problems:
        raise ReleaseError("checks failed:\n  " + "\n  ".join(problems))
    print(f"Checks OK: version {version}, {len(rules)} redirect rules, {len(tests)} rule tests")
    return version


# ---------- pack ----------

def find_edge():
    for p in EDGE_PATHS:
        if p.is_file():
            return p
    raise ReleaseError("Microsoft Edge not found")


def stop_edge(marker):
    """Stop leftover Edge processes using the throwaway build profile (never the user's own Edge)."""
    ps = ("Get-CimInstance Win32_Process -Filter \"Name = 'msedge.exe'\" | "
          f"Where-Object {{ $_.CommandLine -like '*{marker}*' }} | "
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True)


def pack(key, workdir):
    if not key.is_file():
        raise ReleaseError(f"signing key not found: {key}")
    stage = workdir / "BLHS-Hide-AI"
    shutil.copytree(SRC, stage)
    shutil.copy2(REPO / "LICENSE", stage / "LICENSE")
    out = workdir / "BLHS-Hide-AI.crx"
    proc = subprocess.Popen([str(find_edge()), f"--user-data-dir={workdir / 'edge-profile'}", "--no-first-run",
                             f"--pack-extension={stage}", f"--pack-extension-key={key}"])
    try:
        deadline = time.time() + 90
        last = -1
        while time.time() < deadline:
            size = out.stat().st_size if out.exists() else -1
            if size > 0 and size == last:
                break
            last = size
            time.sleep(1.5)
    finally:
        if proc.poll() is None:
            proc.kill()
        stop_edge(workdir.name)
    if not out.exists():
        raise ReleaseError("Edge did not produce a package")
    return out


# ---------- verify ----------

def pb_fields(b):
    """Minimal protobuf reader for the CRX3 header (length-delimited and varint fields only)."""
    def varint(i):
        n = shift = 0
        while True:
            c = b[i]
            i += 1
            n |= (c & 0x7F) << shift
            shift += 7
            if c < 0x80:
                return n, i
    i, out = 0, []
    while i < len(b):
        tag, i = varint(i)
        if tag & 7 == 2:
            length, i = varint(i)
            out.append((tag >> 3, b[i:i + length]))
            i += length
        elif tag & 7 == 0:
            value, i = varint(i)
            out.append((tag >> 3, value))
        else:
            raise ReleaseError("unexpected field in CRX header")
    return out


def der_read(b, i):
    tag, length = b[i], b[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + length], i + length


def rsa_sha256_ok(spki, sig, data):
    _, body, _ = der_read(spki, 0)       # SubjectPublicKeyInfo
    _, _, i = der_read(body, 0)          # skip AlgorithmIdentifier
    _, bits, _ = der_read(body, i)       # BIT STRING holding RSAPublicKey
    _, rsakey, _ = der_read(bits[1:], 0)
    _, n, i = der_read(rsakey, 0)
    _, e, _ = der_read(rsakey, i)
    n, e = int.from_bytes(n, "big"), int.from_bytes(e, "big")
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = SHA256_DIGESTINFO + hashlib.sha256(data).digest()
    return hmac.compare_digest(em, b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t)


def verify(path, expect_version=None):
    d = Path(path).read_bytes()
    if d[:4] != b"Cr24":
        raise ReleaseError(f"{path} is not a CRX file")
    crx_version, header_len = struct.unpack("<II", d[4:12])
    if crx_version != 3:
        raise ReleaseError(f"expected CRX3, got CRX{crx_version}")
    header, archive = d[12:12 + header_len], d[12 + header_len:]
    fields = pb_fields(header)
    signed = next((v for n, v in fields if n == 10000), None)
    if signed is None:
        raise ReleaseError("package has no signed header data")
    crx_id = next((v for n, v in pb_fields(signed) if n == 1), b"")
    if "".join("abcdefghijklmnop"[int(c, 16)] for c in crx_id.hex()) != EXT_ID:
        raise ReleaseError("package ID does not match " + EXT_ID)
    payload = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed)) + signed + archive
    proofs = [dict(pb_fields(v)) for n, v in fields if n == 2]
    ours = [p for p in proofs if id_from_der(p[1]) == EXT_ID]
    if not ours or not all(rsa_sha256_ok(p[1], p[2], payload) for p in ours):
        raise ReleaseError("package is not validly signed with the BLHS Hide AI key")

    z = zipfile.ZipFile(io.BytesIO(archive))
    names = sorted(z.namelist())
    secrets = [n for n in names if n.lower().endswith((".pem", ".key"))]
    if secrets:
        raise ReleaseError(f"package contains key files: {secrets}")
    manifest = json.loads(z.read("manifest.json"))
    if expect_version and manifest.get("version") != expect_version:
        raise ReleaseError(f"package version {manifest.get('version')} != {expect_version}")
    if manifest.get("update_url") != BASE_URL + "update.xml":
        raise ReleaseError("package manifest has the wrong update_url")
    print(f"Package OK: {Path(path).name} | ID {EXT_ID} | signature valid | version {manifest['version']} | files {names}")
    return manifest["version"]


# ---------- publish helpers ----------

def write_release(crx, version):
    shutil.copy2(crx, REPO / CRX_NAME)
    (REPO / "update.xml").write_text(
        UPDATE_XML.format(ext_id=EXT_ID, base=BASE_URL, crx=CRX_NAME, version=version), encoding="utf-8", newline="\n")
    print(f"Wrote {CRX_NAME} and update.xml for version {version}")


def live(wait_minutes):
    deadline = time.time() + wait_minutes * 60
    while True:
        status = []
        for name in ("update.xml", CRX_NAME):
            url = f"{BASE_URL}{name}?nocache={int(time.time())}"
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}), timeout=30) as r:
                    status.append((name, r.read() == (REPO / name).read_bytes()))
            except Exception as e:  # a failed fetch just means "not live yet"
                status.append((name, f"error: {e}"))
        if all(ok is True for _, ok in status):
            print(f"GitHub Pages is serving the local release files (version {published_version()})")
            return
        if time.time() >= deadline:
            raise ReleaseError(f"GitHub Pages does not match the local files yet: {status}")
        time.sleep(30)


def main():
    ap = argparse.ArgumentParser(description="Build, sign and verify a BLHS Hide AI release.")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="validate src/ and the redirect rules only")
    mode.add_argument("--dry-run", action="store_true", help="pack and verify without touching the release files")
    mode.add_argument("--verify", metavar="CRX", help="verify an existing package")
    mode.add_argument("--live", action="store_true", help="compare GitHub Pages with the local release files")
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY, help="signing key (default: %(default)s)")
    ap.add_argument("--wait", type=float, default=0, help="with --live: minutes to keep retrying")
    args = ap.parse_args()
    try:
        if args.verify:
            verify(args.verify)
            return
        if args.live:
            live(args.wait)
            return
        version = check()
        if args.check:
            return
        current = published_version()
        if not args.dry_run:
            if current and parse_version(version) <= parse_version(current):
                raise ReleaseError(f"bump the version in src/manifest.json: {version} is not higher than published {current}")
            if f"## {version}" not in (REPO / "CHANGELOG.md").read_text(encoding="utf-8"):
                raise ReleaseError(f"add a '## {version}' entry to CHANGELOG.md")
        workdir = Path(tempfile.mkdtemp(prefix="blhs-hide-ai-build-"))
        try:
            crx = pack(args.key, workdir)
            verify(crx, version)
            if args.dry_run:
                print("Dry run OK: packed and verified; release files left unchanged")
            else:
                write_release(crx, version)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    except ReleaseError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
