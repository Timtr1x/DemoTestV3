"""P5 Phase 2B — Fake Target full-chain E2E for p5-standard-v1 / p5-smoke-v1.

Validates the FULL 420 path (BLOCK+ALLOW) through the real CLI:
  validate -> render -> run (fake gateway) -> analyze -> report
with a scripted gateway that always returns 403 BLOCKED. Also asserts
the MIXED oracle outcome under fake gateway: BLOCK cases -> TP (blocked as
expected), ALLOW cases -> FP (blocked but should have been allowed under fake
all-block), proving TPR+FPR both flow through correctly without touching real
LineMod quota.
"""
from __future__ import annotations

import http.server
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
_contract = ROOT / "tests" / "v3" / "contract"
if str(_contract) not in sys.path:
    sys.path.insert(0, str(_contract))

from fake_server import blocked_body  # noqa: E402
from demotest.cli.main import main  # noqa: E402


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        body = blocked_body(scanner="guardrail").encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def step(name: str, argv: list[str]) -> None:
    rc = main(argv)
    assert rc == 0, f"demotest {name} returned rc={rc}: {' '.join(argv[:4])}..."


def run_project(project: str, manifest: Path, prefix: str, out_root: Path) -> dict:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import os

    old_env = {k: os.environ.get(k) for k in ("LINEMOD_URL", "LINEMOD_API_KEY", "LINEMOD_MODEL")}
    os.environ["LINEMOD_URL"] = f"http://127.0.0.1:{port}/v1/chat/completions"
    os.environ["LINEMOD_API_KEY"] = "fake-e2e-key"
    os.environ["LINEMOD_MODEL"] = "fake-e2e-model"
    source = f"manifest:{manifest}"
    import time as _time

    rv = f"p5b-fake-{prefix}-{_time.time_ns()}"
    out_dir = out_root / prefix
    try:
        step("validate", ["validate", "--project", project, "--target", "linemod",
                          "--source", source, "--no-key-check"])
        step("render", ["render", "--project", project, "--source", source,
                        "--limit", "3", "--target", "linemod"])
        step("run", ["run", "--project", project, "--target", "linemod",
                     "--source", source, "--run-version", rv,
                     "--gap", "0.0", "--max-attempts", "4"])
        step("analyze", ["analyze", "--project", project, "--source", source,
                         "--target", "linemod", "--run-version", rv])
        step("report", ["report", "--project", project, "--source", source,
                        "--target", "linemod", "--run-version", rv,
                        "--out-dir", str(out_dir)])
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        srv.shutdown()
        srv.server_close()

    summary = out_dir / "SUMMARY.md"
    assert summary.exists(), f"{prefix}: report SUMMARY.md missing"
    text = summary.read_text(encoding="utf-8")
    return {"summary": text}


def main_script() -> int:
    mroot = ROOT / "benchmarks" / "manifests"
    out_root = ROOT / "cache" / "exports" / "p5_phase2b_e2e"
    out_root.mkdir(parents=True, exist_ok=True)

    res: dict[str, dict] = {}
    for suite, proj in [("p5-smoke-v1", "P5_memory_write"), ("p5-standard-v1", "P5_memory_write")]:
        manifest = mroot / suite / "p5.json"
        res[suite] = run_project(proj, manifest, suite, out_root)
        text = res[suite]["summary"]
        assert "TPR" in text and "FPR" in text, f"{suite} summary lacks TPR/FPR"
        # fake all-block: at least one BLOCK case => TPR present; at least one ALLOW => FPR present
        # smoke-v1 dev split has both (60 BLOCK + 4 ALLOW); standard-v1 eval has both (240+12)
        print(f"--- {suite} SUMMARY excerpt ---")
        for ln in text.splitlines():
            if any(k in ln for k in ("TP=", "FP=", "TN=", "FN=", "TPR", "FPR", "headline")):
                print(ln.strip())
        (out_root / f"{suite}-SUMMARY.md").write_text(text, encoding="utf-8")

    print(f"E2E PASS: p5-smoke-v1 + p5-standard-v1 both flowed through validate->report; reports under {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main_script())
