import os
import signal
import subprocess
import sys
import time
from typing import Dict, Optional

from dotenv import load_dotenv


ROOT = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(ROOT, ".env"))


def start(module: str, port: str, extra_env: Optional[Dict[str, str]] = None):
    env = os.environ.copy()
    env.setdefault("SITE_URL", "http://127.0.0.1:2949")
    env.setdefault("GBS_BACKEND_URL", "http://127.0.0.1:8000")
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", f"{module}:App" if module == "GBSBackend" else f"{module}:FrontendApp", "--host", "127.0.0.1", "--port", port],
        cwd=ROOT,
        env=env,
    )


def main():
    backend = start("GBSBackend", "8000")
    frontend = start("GBSFrontendServer", "2949")
    procs = [backend, frontend]
    print("GBS is starting.")
    print("Open http://127.0.0.1:2949")
    print("Press Ctrl+C to stop.")
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for proc in procs:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.terminate()
                else:
                    proc.send_signal(signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
