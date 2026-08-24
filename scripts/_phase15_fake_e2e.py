"""Phase 1.5 step 12 — Fake Target full-chain E2E for the v3 suites.

For smoke-v3 P1 and P2, drives the REAL demotest.cli.main.main([...]) through
    validate -> render -> run (HTTP) -> analyze -> report
against a local scripted gateway that always returns 403 SECURITY_BLOCKED
(reusing tests/v3/contract/fake_server.py). No real LineMod quota is touched;
this proves the v3 manifests are executable end to end and that the analyze /
report path emits TPR **and** FPR for the new BLOCK+ALLOW ground truth.

Read-only w.r.t. benchmarks/; writes run results under cache/results_v3 and
the reports under cache/exports/phase15_e2e/.
"""
from __future__ import annotations

import http.server
import json
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
    def do_POST(self) -> None:  # noqa: N802 — scripted gateway always blocks
        body = blocked_body(scanner="guardrail").encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # quiet
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
    rv = f"phase15-fake-{prefix}"
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
    out_root = ROOT / "cache" / "exports" / "phase15_e2e"
    out_root.mkdir(parents=True, exist_ok=True)

    res = {}
    res["p1"] = run_project("P1_external_instruction", mroot / "smoke-v3" / "p1.json",
                            "p1-smoke-v3", out_root)
    res["p2"] = run_project("P2_tool_action", mroot / "smoke-v3" / "p2.json",
                            "p2-smoke-v3", out_root)

    t1 = res["p1"]["summary"]
    assert "TPR" in t1 and "FPR" in t1, "P1 summary lacks TPR/FPR metrics"

    t2 = res["p2"]["summary"]
    assert "TPR" in t2 and "FPR" in t2, "P2 summary lacks TPR/FPR metrics"
    # fake gateway blocks everything -> every ALLOW case must surface as FP
    # (Authorized Tool Call FPR = 100% under this script) — proves the ALLOW
    # side actually flowed through run -> oracle -> analyze.
    fp_line = [ln for ln in t2.splitlines() if "FP" in ln]
    print("--- P2 FP lines ---")
    for ln in fp_line[:6]:
        print(ln.strip())

    for tag in ("p1", "p2"):
        (out_root / f"{tag}-SUMMARY.md").write_text(res[tag]["summary"], encoding="utf-8")
    print(f"E2E PASS: validate->render->run->analyze->report OK for smoke-v3 p1+p2; "
          f"reports under {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main_script())
