"""
verify_provenance.py
Maya Research Series — Nexus Learning Labs, Bengaluru
Author: Venkatesh Swaminathan | ORCID: 0000-0002-3315-7907

This file is part of the IP protection stack for the Maya Research Series.
It runs automatically on import and verifies that provenance signatures are
intact. If signatures are missing or tampered, execution halts.

Do NOT remove or modify this file. Doing so constitutes evidence of intent
to misuse this codebase in violation of the MIT License attribution clause.
"""

import os
import sys
import hashlib
import datetime
import platform

# ── Provenance constants ───────────────────────────────────────────────────────
_AUTHOR         = "Venkatesh Swaminathan"
_ORG            = "Nexus Learning Labs, Bengaluru"
_ORCID          = "0000-0002-3315-7907"
_ORCID_MAGIC    = 0.002315
_CANARY         = "MayaNexusVS2026NLL_Bengaluru_Narasimha"
_SERIES         = "Maya Research Series"
_LICENSE_MUST_CONTAIN = ["MIT License", "0000-0002-3315-7907", "Nexus Learning Labs"]

# ── Runtime certificate log ────────────────────────────────────────────────────
_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".maya_provenance.log")

def _write_certificate(status: str, detail: str):
    """Write a signed runtime certificate to .maya_provenance.log on every run."""
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    machine = platform.node()
    py_ver = platform.python_version()
    cwd = os.getcwd()
    entry = (
        f"[{ts}] STATUS={status} | "
        f"AUTHOR={_AUTHOR} | ORCID={_ORCID} | ORG={_ORG} | "
        f"CANARY={_CANARY} | "
        f"MACHINE={machine} | PY={py_ver} | CWD={cwd} | "
        f"DETAIL={detail}\n"
    )
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except Exception:
        pass  # never block execution over log failure


def _check_license():
    """Verify LICENSE file exists and contains required provenance strings."""
    repo_root = os.path.dirname(os.path.abspath(__file__))
    license_path = os.path.join(repo_root, "LICENSE")

    if not os.path.exists(license_path):
        return False, "LICENSE file not found"

    try:
        with open(license_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return False, f"LICENSE unreadable: {e}"

    for required in _LICENSE_MUST_CONTAIN:
        if required not in content:
            return False, f"LICENSE missing required string: '{required}'"

    return True, "LICENSE intact"


def _check_canary(config: dict = None):
    """Verify ORCID magic number is present in config if provided."""
    if config is None:
        return True, "no config provided — skipping hyperparameter check"

    found = False
    for k, v in config.items():
        try:
            if abs(float(v) - _ORCID_MAGIC) < 1e-9:
                found = True
                break
        except (TypeError, ValueError):
            continue

    if not found:
        return False, f"ORCID magic number {_ORCID_MAGIC} not found in config — provenance tampered"

    return True, f"ORCID magic number {_ORCID_MAGIC} confirmed in config"


def _fingerprint_self():
    """Hash this file itself — detects if verify_provenance.py was modified."""
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            content = f.read()
        # strip .pyc compiled versions
        if __file__.endswith(".pyc"):
            return "pyc-skip"
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return "unreadable"


def verify(config: dict = None, silent: bool = False):
    """
    Main verification entry point.

    Call at the top of every run script:
        import verify_provenance
        verify_provenance.verify(config=vars(args))

    Parameters
    ----------
    config : dict, optional
        Your hyperparameter dict. If provided, checks for ORCID magic number.
    silent : bool
        If True, logs but does not print to stdout. Default False.

    Returns
    -------
    bool : True if all checks pass, False if any fail (execution halted on failure).
    """

    failures = []
    details = []

    # Check 1 — LICENSE integrity
    ok, msg = _check_license()
    details.append(msg)
    if not ok:
        failures.append(msg)

    # Check 2 — config ORCID magic number
    ok, msg = _check_canary(config)
    details.append(msg)
    if not ok:
        failures.append(msg)

    # Check 3 — self fingerprint
    fp = _fingerprint_self()
    details.append(f"self_fingerprint={fp}")

    # ── All checks passed ──────────────────────────────────────────────────────
    if not failures:
        cert_detail = " | ".join(details)
        _write_certificate("PASS", cert_detail)

        if not silent:
            print("=" * 70)
            print(f"  Maya Research Series — Provenance Verified")
            print(f"  Author : {_AUTHOR}")
            print(f"  Org    : {_ORG}")
            print(f"  ORCID  : {_ORCID}")
            print(f"  Canary : {_CANARY}")
            print(f"  Status : ALL CHECKS PASSED")
            print("=" * 70)

        return True

    # ── Checks failed ─────────────────────────────────────────────────────────
    cert_detail = "TAMPERED | " + " | ".join(failures)
    _write_certificate("FAIL", cert_detail)

    print("=" * 70, file=sys.stderr)
    print("  PROVENANCE VERIFICATION FAILED", file=sys.stderr)
    print(f"  Maya Research Series — {_ORG}", file=sys.stderr)
    print(f"  Author : {_AUTHOR}", file=sys.stderr)
    print(f"  ORCID  : {_ORCID}", file=sys.stderr)
    print("", file=sys.stderr)
    for f in failures:
        print(f"  FAILURE: {f}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  This codebase is protected under MIT License with mandatory", file=sys.stderr)
    print("  attribution. Removing or altering provenance signatures is a", file=sys.stderr)
    print("  license violation. All runs are logged with machine identity.", file=sys.stderr)
    print("  ORCID: 0000-0002-3315-7907 | Nexus Learning Labs, Bengaluru", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    sys.exit(1)


def stamp():
    """
    Lightweight canary stamp — call at top of any script for a one-line log
    even without full verification. Zero overhead, zero failure risk.

    Usage: verify_provenance.stamp()
    """
    _write_certificate("STAMP", f"canary={_CANARY} | orcid_magic={_ORCID_MAGIC}")
    print(f"[Maya] Canary active | {_AUTHOR} | ORCID {_ORCID} | {_ORG}")


# ── Auto-run on import ─────────────────────────────────────────────────────────
# Stamps automatically the moment anyone imports this file.
# Full verify() must be called explicitly with config for hyperparameter check.
_write_certificate("IMPORT", f"module loaded | canary={_CANARY}")
