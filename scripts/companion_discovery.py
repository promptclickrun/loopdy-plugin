"""Standalone read-only Companion probe. No plugin, Hermes or config imports.

Disk metadata is an installation hint, never proof of bytes or live activation.
Initial-install arguments require attended execution by the supported Hermes CLI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SOURCE = "https://github.com/promptclickrun/loopdy-plugin"
REVISION = re.compile(r"[0-9a-f]{40}")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate metadata key")
        value[key] = item
    return value


def _bounded_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError("Invalid metadata file")
        data = os.read(fd, 65537)
        if len(data) > 65536:
            raise ValueError("Metadata too large")
        return data
    finally:
        os.close(fd)


def _directory(path):
    try:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Profile path must use ordinary directories")
        return [info.st_dev, info.st_ino]
    except FileNotFoundError:
        return None


def inspect_profile(home):
    if not isinstance(home, str) or not Path(home).is_absolute() or "\x00" in home:
        raise ValueError("An explicit absolute Hermes profile home is required")
    path = Path(home)
    if ".." in path.parts:
        raise ValueError("Ambiguous profile path")
    # Reject symlinked ancestors as well as the selected directories. This is
    # a discovery snapshot, not an atomic installer lock against same-UID writes.
    for parent in reversed(path.parents):
        _directory(parent)
    result = {"version": 1, "profileHome": str(path), "installation": "absent",
              "sourceKind": None, "recordedRevision": None, "activeRevision": None}
    evidence = {"home": str(path)}
    try:
        evidence["homeIdentity"] = _directory(path)
        evidence["pluginsIdentity"] = _directory(path / "plugins")
        evidence["pluginIdentity"] = _directory(path / "plugins" / "loopdy")
        metadata = path / "plugins" / ".install-metadata.json"
        try:
            data = _bounded_file(metadata)
        except FileNotFoundError:
            data = None
        evidence["metadataDigest"] = hashlib.sha256(data).hexdigest() if data is not None else None
        value = json.loads(data, object_pairs_hook=_unique_object) if data is not None else {}
        if not isinstance(value, dict):
            raise ValueError("Invalid install metadata")
        entry = value.get("loopdy")
        if "loopdy" in value or evidence["pluginIdentity"] is not None:
            result["installation"] = "unrecognized"
            if isinstance(entry, dict) and evidence["pluginIdentity"] is not None:
                revision, source = entry.get("revision"), entry.get("source")
                if isinstance(revision, str) and REVISION.fullmatch(revision) and source in (SOURCE, SOURCE + ".git"):
                    result.update(installation="metadataPresent", sourceKind="canonical", recordedRevision=revision)
    except (OSError, ValueError, TypeError, RecursionError):
        result["installation"] = "unrecognized"
        evidence["invalid"] = True
    payload = json.dumps({"result": result, "evidence": evidence}, sort_keys=True, separators=(",", ":"))
    result["fingerprint"] = hashlib.sha256(payload.encode()).hexdigest()
    return result


def prepare_initial_install(home, revision, expected_fingerprint):
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        raise ValueError("An immutable source revision is required")
    current = inspect_profile(home)
    if current["fingerprint"] != expected_fingerprint:
        raise ValueError("Profile installation changed; inspect again")
    if current["installation"] != "absent":
        raise ValueError("Use the existing Hermes updater or repair flow")
    return {"version": 1, "profileHome": current["profileHome"], "expectedFingerprint": expected_fingerprint,
            "arguments": ["plugins", "install", SOURCE, "--ref", revision, "--no-enable"],
            "activationOwner": "hermes", "requiresAttendedExecution": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", required=True)
    args = parser.parse_args()
    print(json.dumps(inspect_profile(args.home), sort_keys=True))


if __name__ == "__main__":
    main()
