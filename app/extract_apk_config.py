#!/usr/bin/env python3
"""
extract_apk_config.py - Pull the per-app identifiers app.fcm needs
straight out of the APK, so none of them are hardcoded in this repository.

All of this is embedded in the public APK - app configuration, not a user
secret.

What it extracts:

  package            applicationId from AndroidManifest.xml (binary AXML)
  version_name/Code  from the same manifest
  firebase.*         the MFA push (Firebase) config: api_key, app_id,
                     sender_id, project - read from the dex class that
                     declares them as static finals (decompiled source:
                     com.microsoft.authenticator.notifications.entities
                     .MfaFcmConfiguration; a minimal dex reader maps the
                     constant VALUES to their FIELD NAMES, and the PROD
                     variant is preferred over PPE by name). The APK also
                     embeds config for unrelated SDKs; those decoys are
                     skipped because sender/app-id/project must cross-check.
  signing_cert_sha1  SHA-1 of the signing certificate in META-INF/*.RSA
  apk_sha256         integrity fingerprint of the source APK

Usage:
    python3 -m app.extract_apk_config                       # apk/msauth.apk
    python3 -m app.extract_apk_config --apk /path/to.apk
    python3 -m app.extract_apk_config --print               # also dump values

Output: AUTH_STATE_DIR/apk_config.json (data/apk_config.json by default; gitignored).
app.fcm refuses to run without it.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import zipfile
from app.state import state_path

DEFAULT_APK = os.path.join("apk", "msauth.apk")

API_KEY_STR = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
APP_ID_STR = re.compile(r"1:(\d{9,20}):android:([0-9a-f]{16,42})")

# ---------------------------------------------------------------------------
# minimal binary AXML parser - just enough for <manifest> attributes
# ---------------------------------------------------------------------------

def _u16(b: bytes, o: int) -> int:
    return b[o] | (b[o + 1] << 8)


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def parse_string_pool(b: bytes, off: int) -> list[str]:
    """ResStringPool chunk at off -> python strings."""
    flags = _u32(b, off + 16)
    strings_start = _u32(b, off + 20)
    count = _u32(b, off + 8)
    offsets = [_u32(b, off + 28 + 4 * i) for i in range(count)]
    base = off + strings_start
    out = []
    utf8 = bool(flags & 0x100)
    for o in offsets:
        p = base + o
        try:
            if utf8:
                def declen(q: int) -> tuple[int, int]:
                    n = b[q]
                    if n & 0x80:
                        return ((n & 0x7F) << 8) | b[q + 1], q + 2
                    return n, q + 1
                _, p = declen(p)          # utf-16 char count (skipped)
                blen, p = declen(p)       # utf-8 byte count
                out.append(b[p:p + blen].decode("utf-8", "replace"))
            else:
                n = _u16(b, p)
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | _u16(b, p + 2)
                    p += 4
                else:
                    p += 2
                out.append(b[p:p + 2 * n].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


def parse_manifest(data: bytes) -> dict:
    """Return {package, versionCode, versionName} from binary AndroidManifest.xml."""
    strings: list[str] | None = None
    manifest: dict | None = None
    off = 8                                   # skip the RES_XML_TYPE header
    while off + 8 <= len(data):
        ctype = _u16(data, off)
        hsize = _u16(data, off + 2)
        size = _u32(data, off + 4)
        if size <= 0:
            break
        if ctype == 0x0001 and strings is None:            # string pool
            strings = parse_string_pool(data, off)
        elif ctype == 0x0102 and strings is not None:      # START_ELEMENT
            a = off + hsize                                # attrExt start
            name_idx = _u32(data, a + 4)
            attr_start = _u16(data, a + 8)
            attr_size = _u16(data, a + 10)
            attr_count = _u16(data, a + 12)
            elem = strings[name_idx] if name_idx < len(strings) else ""
            if elem == "manifest":
                manifest = {}
                base = a + attr_start
                for i in range(attr_count):
                    ao = base + i * attr_size
                    aname = _u32(data, ao + 4)
                    raw = _u32(data, ao + 8)
                    dtype = data[ao + 15]                  # typedValue.dataType
                    dval = _u32(data, ao + 16)
                    nm = strings[aname] if aname < len(strings) else ""
                    if dtype == 0x03:                      # STRING
                        val = (strings[raw]
                               if raw != 0xFFFFFFFF and raw < len(strings) else None)
                    else:
                        val = dval
                    manifest[nm] = val
                break
        off += size
    if not manifest or "package" not in manifest:
        raise SystemExit("could not parse AndroidManifest.xml - unsupported AXML?")
    return manifest


# ---------------------------------------------------------------------------
# minimal dex reader - static String fields of every class
# ---------------------------------------------------------------------------

def _uleb128(b: bytes, i: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = b[i]; i += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, i
        shift += 7


def _dex_string(data: bytes, ids_off: int, idx: int) -> str:
    off = _u32(data, ids_off + 4 * idx)
    _utf16_len, i = _uleb128(data, off)
    end = data.index(b"\x00", i)
    return data[i:end].decode("utf-8", "replace")


def _skip_encoded_value(data: bytes, j: int) -> int:
    """Walk past one encoded_value (dex §encoded_value). Scalar values are
    (valueArg+1) payload bytes after the header - sizes, not uleb128."""
    header = data[j]; j += 1
    vtype, varg = header & 0x1F, header >> 5
    if vtype == 0x1C:                                  # VALUE_ARRAY
        n, j = _uleb128(data, j)
        for _ in range(n):
            j = _skip_encoded_value(data, j)
    elif vtype == 0x1D:                                # VALUE_ANNOTATION
        _, j = _uleb128(data, j)                       # type idx
        n, j = _uleb128(data, j)
        for _ in range(n):
            _, j = _uleb128(data, j)                   # name idx
            j = _skip_encoded_value(data, j)
    elif vtype in (0x1E, 0x1F):                        # NULL / BOOLEAN
        pass
    else:                                              # every scalar, incl. STRING
        j += varg + 1
    return j


def dex_class_static_strings(data: bytes):
    """Yield (class_descriptor, [(field_name, string_value), ...]) for every
    class that has static String fields. Only what's needed to map the
    Firebase constant block; corrupt classes are skipped."""
    try:
        s_n, s_off = _u32(data, 56), _u32(data, 60)
        t_n, t_off = _u32(data, 64), _u32(data, 68)
        f_n, f_off = _u32(data, 80), _u32(data, 84)
        c_n, c_off = _u32(data, 96), _u32(data, 100)
        if not (s_n and t_n and f_n and c_n):
            return
    except (IndexError, struct.error) as e:            # not a dex file
        raise SystemExit(f"malformed dex header ({e})") from e

    def type_desc(idx: int) -> str:
        return _dex_string(data, s_off, _u32(data, t_off + 4 * idx))

    for c in range(c_n):
        try:
            base = c_off + 32 * c
            class_data_off = _u32(data, base + 24)
            static_values_off = _u32(data, base + 28)
            if not class_data_off:
                continue
            desc = type_desc(_u32(data, base))
            i = class_data_off
            sf_n, i = _uleb128(data, i)
            if_n, i = _uleb128(data, i)
            dm_n, i = _uleb128(data, i)
            vm_n, i = _uleb128(data, i)

            fidx = 0
            statics: list[int] = []
            for _ in range(sf_n):
                diff, i = _uleb128(data, i)
                _, i = _uleb128(data, i)               # access flags
                fidx += diff
                statics.append(fidx)
            for _ in range(if_n):                      # instance fields
                _, i = _uleb128(data, i)
                _, i = _uleb128(data, i)
            for _ in range(dm_n + vm_n):               # methods (2 ulebs each)
                _, i = _uleb128(data, i)
                _, i = _uleb128(data, i)

            values: list[str | None] = []
            if static_values_off:
                j = static_values_off
                n, j = _uleb128(data, j)
                for _ in range(n):
                    vtype = data[j] & 0x1F
                    varg = data[j] >> 5
                    if vtype == 0x17:                  # VALUE_STRING: fixed-width LE index
                        j += 1
                        sidx = int.from_bytes(data[j:j + varg + 1], "little")
                        j += varg + 1
                        values.append(_dex_string(data, s_off, sidx))
                    else:
                        # don't pre-consume the header here - _skip reads it
                        j = _skip_encoded_value(data, j)
                        values.append(None)

            out: list[tuple[str, str]] = []
            for pos, fidx in enumerate(statics):
                if pos >= len(values) or values[pos] is None:
                    continue
                fbase = f_off + 8 * fidx
                name_idx = _u32(data, fbase + 4)
                out.append((_dex_string(data, s_off, name_idx), values[pos]))
            if out:
                yield desc, out
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Firebase config selection
# ---------------------------------------------------------------------------

def _variant_config(fields: dict[str, str]) -> dict | None:
    """Group one class's statics into variants by name prefix (e.g.
    MFA_PROD_* / MFA_PPE_*) and return the best consistent one."""
    groups: dict[str, dict[str, str]] = {}
    for name, val in fields.items():
        m = re.match(r"^(.*?)_?(API_KEY|APPLICATION_ID|APP_ID|GCM_SENDER_ID|SENDER_ID|PROJECT_ID)$",
                     name, re.I)
        if not m:
            continue
        prefix, role = m.group(1).upper(), m.group(2).upper()
        role = {"APP_ID": "APPLICATION_ID", "SENDER_ID": "GCM_SENDER_ID"}.get(role, role)
        groups.setdefault(prefix, {})[role] = val

    best = None
    for prefix, g in groups.items():
        if "API_KEY" not in g or "APPLICATION_ID" not in g:
            continue
        app_id = g["APPLICATION_ID"]
        m = APP_ID_STR.fullmatch(app_id)
        if not m:
            continue                                   # not a Firebase app id - decoy
        sender = g.get("GCM_SENDER_ID") or m.group(1)
        project = g.get("PROJECT_ID")
        if sender != m.group(1):
            continue                                   # inconsistent - decoy
        if project and project != f"api-project-{sender}":
            continue
        rank = (1 if "PROD" in prefix else 0, len(g))
        if best is None or rank > best[0]:
            best = (rank, {"api_key": g["API_KEY"], "app_id": app_id,
                           "sender_id": sender,
                           "project": project or f"api-project-{sender}",
                           "variant": prefix})
    return best[1] if best else None


def _shape_config(fields: dict[str, str]) -> dict | None:
    """Fallback when field names are obfuscated: any consistent
    api-key/app-id pair from the values alone."""
    keys = [v for v in fields.values() if API_KEY_STR.fullmatch(v)]
    for val in fields.values():
        m = APP_ID_STR.fullmatch(val)
        if not m:
            continue
        sender = m.group(1)
        project = next((v for v in fields.values()
                        if v == f"api-project-{sender}"), None)
        for key in keys:
            if key != val:
                return {"api_key": key, "app_id": val, "sender_id": sender,
                        "project": project or f"api-project-{sender}",
                        "variant": "unknown"}
    return None


def firebase_config_from_dex(data: bytes) -> dict | None:
    """Locate the class that declares the push config as static finals and
    map values to names. Prefers classes named *Fcm* / *Mfa*, then PROD."""
    named = shape = None
    for desc, pairs in dex_class_static_strings(data):
        fields = dict(pairs)
        vals = list(fields.values())
        if not any(API_KEY_STR.fullmatch(v) for v in vals):
            continue
        if not any(APP_ID_STR.fullmatch(v) for v in vals):
            continue
        cfg = _variant_config(fields)
        if cfg:
            named = cfg
            if "fcm" in desc.lower() or "mfa" in desc.lower():
                return cfg                      # exactly the class we want
            continue                            # consistent but unnamed - keep looking
        cfg = _shape_config(fields)
        if cfg and shape is None:
            shape = cfg
    return named or shape


def cert_sha1_from_pkcs7(der: bytes) -> str | None:
    """SHA-1 of the first X.509 cert inside a META-INF PKCS#7 signature block."""
    try:
        p1 = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-print_certs"],
                            input=der, capture_output=True, check=True)
        p2 = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha1"],
                            input=p1.stdout, capture_output=True, check=True)
        line = p2.stdout.decode(errors="replace")
        return line.split("=", 1)[1].strip().replace(":", "").lower() or None
    except (FileNotFoundError, subprocess.CalledProcessError, IndexError):
        return None


# ---------------------------------------------------------------------------

def extract_config(apk, signing_cert_sha1=None) -> dict:
    """Extract public configuration; Android supplies PackageManager certificates."""
    if not os.path.exists(apk):
        raise SystemExit(f"APK not found: {apk} - put the Authenticator APK there "
                         f"or pass --apk /path/to.apk")

    certs = list(signing_cert_sha1 or [])
    if any(not isinstance(c, str) or not re.fullmatch(r'[0-9a-fA-F]{40}', c) for c in certs):
        raise ValueError('invalid signing certificate fingerprint')
    fbc: dict | None = None
    with zipfile.ZipFile(apk) as z:
        infos = z.infolist()
        dex = [i for i in infos if i.filename.startswith('classes') and i.filename.endswith('.dex')]
        if (len(infos) > 50000 or len({i.filename for i in infos}) != len(infos)
                or z.getinfo('AndroidManifest.xml').file_size > 4 * 1024 * 1024
                or sum(i.file_size for i in dex) > 256 * 1024 * 1024
                or any(i.file_size > 128 * 1024 * 1024 for i in dex)):
            raise ValueError('APK exceeds extraction limits')
        manifest = parse_manifest(z.read("AndroidManifest.xml"))
        for name in sorted(z.namelist()):
            if name.startswith("classes") and name.endswith(".dex") and fbc is None:
                fbc = firebase_config_from_dex(z.read(name))
            elif signing_cert_sha1 is None and name.upper().startswith("META-INF/") and \
                    name.upper().endswith((".RSA", ".DSA", ".EC")):
                sha1 = cert_sha1_from_pkcs7(z.read(name))
                if sha1:
                    certs = list(dict.fromkeys(certs + [sha1]))

    if not fbc:
        raise SystemExit("Firebase config not found: no dex class holds a "
                         "consistent api-key/app-id constant block.")

    # apk digest for provenance
    h = hashlib.sha256()
    with open(apk, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)

    cfg = {
        "_comment": ("Generated by extract_apk_config.py from the local APK - "
                     "regenerate with: python3 -m app.extract_apk_config. App-embedded "
                     "public configuration (not a user secret), gitignored because "
                     "it is machine/regeneration-specific."),
        "source_apk": os.path.relpath(apk),
        "apk_sha256": h.hexdigest(),
        "extracted_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "package": manifest["package"],
        "version_name": manifest.get("versionName"),
        "version_code": manifest.get("versionCode"),
        "signing_cert_sha1": certs,
        "firebase": {
            "api_key": fbc["api_key"],
            "app_id": fbc["app_id"],
            "sender_id": fbc["sender_id"],
            "project": fbc["project"],
        },
        "firebase_variant": fbc.get("variant"),
    }

    return cfg


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apk", default=DEFAULT_APK, help=f"APK to read (default {DEFAULT_APK})")
    output = str(state_path('apk_config.json'))
    ap.add_argument("--out", default=output, help=f"output json (default {output})")
    ap.add_argument("--print", action="store_true", help="also dump values")
    args = ap.parse_args()
    cfg = extract_config(args.apk)
    with open(args.out, "w") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")

    shown = json.loads(json.dumps(cfg))
    shown["firebase"]["api_key"] = shown["firebase"]["api_key"][:10] + "…"
    print(f"wrote {args.out}")
    if args.print:
        print(json.dumps(shown, indent=2))
    else:
        print(f"  package={cfg['package']}  version={cfg['version_name']} "
              f"({cfg['version_code']})  certs={len(cfg['signing_cert_sha1'])}")
    print("NOTE: verify signing_cert_sha1 matches the fingerprint Microsoft "
          "publishes for Authenticator (a re-signed/unofficial APK will differ).")


if __name__ == "__main__":
    main()
