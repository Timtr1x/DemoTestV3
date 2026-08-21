#!/usr/bin/env python
"""Fetch skill repo ZIPs via codeload (mirror-first), keeping official conventions.

The pinned SkillLeakBench downloader uses api.github.com/zipball, which on this
network is slow AND capped at 60 req/h unauthenticated. This helper downloads
the SAME repo@branch archives from codeload.github.com (no API rate budget),
writing ``<skill_id>.zip`` + ``progress.json`` exactly as the official crawler
does, so the pinned extractor and all provenance semantics stay untouched.

GitHub generates zip containers on the fly, so zip bytes differ between
endpoints; provenance anchors on the extracted tree sha (source_sha256),
never on zip bytes. No API keys are used or stored by this script.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

MIRRORS = [
    "https://gh-proxy.com/https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}",
    "https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}",
]


def parse_github_repo(url: str) -> tuple[str, str] | None:
    url = (url or "").rstrip("/")
    if "github.com" not in url:
        return None
    parts = url.split("github.com/")[-1].replace(".git", "")
    seg = [s for s in parts.split("/") if s]
    if len(seg) < 2:
        return None
    return seg[0], seg[1]


def valid_zip(p: Path) -> bool:
    try:
        with zipfile.ZipFile(p) as zf:
            zf.testzip()
        return True
    except Exception:
        return False


def fetch_one(skill: dict, zip_dir: Path, timeout: int = 300) -> dict:
    skill_id = str(skill.get("skill_id") or "")
    zip_path = zip_dir / f"{skill_id}.zip"
    if zip_path.exists() and valid_zip(zip_path):
        return {"status": "done", "zip_file": str(zip_path), "note": "existing"}
    repo = parse_github_repo(str(skill.get("repo_url") or ""))
    if repo is None:
        return {"status": "skipped", "reason": "not a GitHub URL"}
    owner, name = repo
    branch = str(skill.get("branch") or "main")
    last_err = ""
    for tmpl in MIRRORS:
        url = tmpl.format(owner=owner, repo=name, branch=branch)
        try:
            req = Request(url, headers={"User-Agent": "demotest-p4-fetch"})
            with urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            tmp = zip_path.with_suffix(".zip.part")
            tmp.write_bytes(data)
            if not valid_zip(tmp):
                last_err = f"invalid zip from {url.split('/')[2]}"
                tmp.unlink(missing_ok=True)
                continue
            tmp.replace(zip_path)
            return {"status": "done", "zip_file": str(zip_path),
                    "size_kb": round(zip_path.stat().st_size / 1024, 1),
                    "via": url.split("/")[2]}
        except Exception as e:  # noqa: BLE001 — acquisition helper, try next mirror
            last_err = f"{type(e).__name__}: {e}"
            continue
    return {"status": "failed", "reason": last_err[:200]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", required=True, help="skills_metadata.json")
    ap.add_argument("--zip-dir", required=True)
    ap.add_argument("--progress", default="", help="progress.json path (optional)")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    meta = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    entries = meta if isinstance(meta, list) else (meta.get("skills") or meta.get("entries") or [])
    skills = entries[args.offset: args.offset + args.limit]
    zip_dir = Path(args.zip_dir)
    zip_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, dict] = {}
    done = failed = skipped = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, s, zip_dir): s for s in skills}
        for fut in as_completed(futs):
            s = futs[fut]
            sid = str(s.get("skill_id") or "")
            try:
                r = fut.result()
            except Exception as e:  # noqa: BLE001
                r = {"status": "failed", "reason": f"{type(e).__name__}: {e}"[:200]}
            results[sid] = r
            if r["status"] == "done":
                done += 1
            elif r["status"] == "skipped":
                skipped += 1
            else:
                failed += 1
            print(f"[{done+failed+skipped}/{len(skills)}] {sid[:60]} -> {r['status']}"
                  + (f" ({r.get('reason', '')[:60]})" if r["status"] != "done" else ""),
                  flush=True)

    if args.progress:
        pp = Path(args.progress)
        progress = json.loads(pp.read_text(encoding="utf-8")) if pp.exists() else {}
        progress.update(results)
        pp.write_text(json.dumps(progress, indent=2, sort_keys=True), encoding="utf-8")

    print(f"done={done} skipped={skipped} failed={failed}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
