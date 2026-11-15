from __future__ import annotations

import argparse
import importlib.util
import platform
import shutil
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Check MLX Sentinel installation and host readiness")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args()
    checks = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "mlx": importlib.util.find_spec("mlx") is not None,
        "mlx_lm": importlib.util.find_spec("mlx_lm") is not None,
        "pmset": shutil.which("pmset") is not None,
        "memory_pressure": shutil.which("memory_pressure") is not None,
    }
    ready = checks["mlx"] and checks["mlx_lm"] and platform.machine() in {"arm64", "aarch64"}
    checks["ready"] = ready
    if args.json:
        import json

        print(json.dumps(checks, indent=2))
    else:
        print("MLX Sentinel doctor")
        for name, value in checks.items():
            print(f"  {'OK' if value is True else 'INFO' if name in {'python', 'platform'} else 'FAIL'} {name}: {value}")
        print("Ready for local MLX inference." if ready else "Install MLX/MLX-LM on Apple Silicon before starting the service.")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
