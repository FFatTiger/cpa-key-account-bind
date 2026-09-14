#!/usr/bin/env python3
"""Initialize a NEW installation only; refuses to overwrite any existing state."""
import argparse
import hashlib
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
args = parser.parse_args()
if not args.path.is_absolute():
    parser.error("state path must be absolute")
fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    json.dump({"version": 1, "sessions": {}, "checksum": hashlib.sha256(b"{}").hexdigest()}, handle)
    handle.flush()
    os.fsync(handle.fileno())
