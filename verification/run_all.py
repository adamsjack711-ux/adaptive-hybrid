"""Run the checks and report failures while managing a temporary broker."""
import signal
import subprocess
import sys
import traceback
from contextlib import ExitStack

from verification.broker import broker
from verification.live_checks import run_live


def main():
    results = {}

    def check(label, action):
        print(f"\n== {label} ==", flush=True)
        try:
            value = action()
        except (Exception, SystemExit):
            traceback.print_exc()
            results[label] = "FAIL"
        else:
            results[label] = "PASS"
            return value

    def command(*args):
        subprocess.run(args, check=True)

    with ExitStack() as cleanup:
        instance = check("Start JetStream", lambda: cleanup.enter_context(broker()))
        check("Python unit, property and parser tests", lambda: command(sys.executable, "-m", "pytest", "-q"))
        if instance is None:
            results["Live JetStream and chaos tests"] = "FAIL (broker unavailable)"
        else:
            check("Live JetStream and chaos tests", lambda: run_live(instance))
        check("Live demo", lambda: command(sys.executable, "-u", "-m", "verification.demo"))
        check("Tamarin", lambda: command("./verification/verify.sh"))
        check("ProVerif", lambda: command("./verification/crosscheck.sh"))

    print("\nVerification summary")
    for label, status in results.items():
        print(f"{status:26} {label}")
    return 0 if all(status == "PASS" for status in results.values()) else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
