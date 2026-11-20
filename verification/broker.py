"""Manage an isolated, loopback-only JetStream broker for local runs."""
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


class Broker:
    def __init__(self, binary, directory):
        self.binary, self.directory = binary, Path(directory)
        self.port, self.proc = -1, None

    def start(self):
        self.proc = subprocess.Popen([
            self.binary, "-js", "-sd", str(self.directory / "store"), "-a", "127.0.0.1",
            "-p", str(self.port), "-ports_file_dir", str(self.directory),
        ], stderr=subprocess.DEVNULL)
        ports = self.directory / f"nats-server_{self.proc.pid}.ports"
        for _ in range(100):
            if self.proc.poll() is not None:
                raise RuntimeError("temporary JetStream broker exited during startup")
            try:
                url = json.loads(ports.read_text())["nats"][0]
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(.05)
                continue
            self.port = urlsplit(url).port
            self.url = url
            return
        raise TimeoutError("no broker ports file")

    def stop(self, *, crash=False):
        if self.proc is None or self.proc.poll() is not None:
            return
        if crash:
            self.proc.kill()
        else:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def restart(self):
        self.stop(crash=True)
        self.start()


@contextmanager
def broker():
    binary = shutil.which("nats-server")
    if binary is None:
        local = Path.home() / "go/bin/nats-server"
        if not local.is_file():
            raise FileNotFoundError("Install nats-server and add it to PATH")
        binary = str(local)
    with tempfile.TemporaryDirectory(prefix="adaptive-hybrid-") as tmp:
        instance = Broker(binary, tmp)
        try:
            instance.start()
            yield instance
        finally:
            instance.stop()
