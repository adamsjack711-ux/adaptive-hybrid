"""Small, single-writer, crash-safe files for lab peer and signer state.

These files are local trust anchors, not a substitute for protected storage in a
deployment. A process restart always requires a fresh authenticated handshake.
"""

import json
import os
import secrets
import stat
from pathlib import Path


class StateFile:
    def __init__(self, path):
        self.path = Path(path)

    def load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077):
                raise ValueError(f"unsafe state file permissions: {self.path}")
            data = source.read(65537)
        if len(data) > 65536:
            raise ValueError("state file is too large")
        try:
            value = json.loads(data)
        except (UnicodeError, ValueError):
            raise ValueError("malformed state file") from None
        if not isinstance(value, dict):
            raise ValueError("invalid state record")
        return value

    def save(self, value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(data) > 65536:
            raise ValueError("state record is too large")
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(8)}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
