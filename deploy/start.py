"""Restore persistent data, run RIYU, and publish periodic snapshots."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading

from deploy import supabase_snapshot


def main() -> int:
    supabase_snapshot.restore()

    child = subprocess.Popen([
        sys.executable,
        "-m",
        "src.main",
        "dashboard",
        "--host",
        "0.0.0.0",
        "--port",
        os.environ.get("PORT", "10000"),
    ])

    stop = threading.Event()

    def snapshot_loop() -> None:
        interval = max(int(os.environ.get("SNAPSHOT_INTERVAL_SECONDS", "300")), 60)
        while not stop.wait(interval):
            try:
                supabase_snapshot.upload()
            except Exception as exc:
                print(f"Periodic snapshot failed: {exc}", file=sys.stderr, flush=True)

    thread = threading.Thread(target=snapshot_loop, name="snapshot", daemon=True)
    thread.start()

    def forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    code = child.wait()
    stop.set()
    thread.join(timeout=2)
    try:
        supabase_snapshot.upload()
    except Exception as exc:
        print(f"Final snapshot failed: {exc}", file=sys.stderr, flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
