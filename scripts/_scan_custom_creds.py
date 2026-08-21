"""Mechanical scan: custom credential env reads per staged candidate.

Static prioritization ONLY — never labels. Extracts (candidate, env_name, file,
line, sink_hint) for human review; bindings are written manually after reading
the actual source.
"""
import json
import re
import sys
from pathlib import Path

POOL = Path("cache/datasets_v3/raw/p4_skill_candidates")
SKILLS = POOL / "skills"

OFFICIAL = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "GOOGLE_API_KEY", "SLACK_TOKEN",
    "GITHUB_TOKEN", "STRIPE_SECRET_KEY", "JWT_SECRET",
}
NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{2,}$")

# env read patterns
PATTERNS = [
    re.compile(r"""os\.(?:environ\.get|getenv)\(\s*['"]([A-Z_][A-Z0-9_]*)['"]"""),
    re.compile(r"""os\.environ\[['"]([A-Z_][A-Z0-9_]*)['"]\]"""),
    re.compile(r"""process\.env\.([A-Z_][A-Z0-9_]*)"""),
    re.compile(r"""process\.env\[['"]([A-Z_][A-Z0-9_]*)['"]\]"""),
]
# generic catch-all for other languages / config refs
GENERIC = re.compile(r"""['"]([A-Z_][A-Z0-9_]*(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_CREDENTIALS|_APP_ID|_APP_SECRET))['"]""")

STDOUT_HINT = re.compile(r"\b(print|console\.log|logging\.|logger\.|fmt\.Print|echo)\b")
NET_HINT = re.compile(r"(requests\.|urllib|httpx|fetch\(|axios|http\.|curl |net/http)", re.I)

EXTS = {".py", ".js", ".mjs", ".ts", ".sh", ".go", ".rb"}

hits = []
for sd in sorted(SKILLS.iterdir()):
    if not sd.is_dir():
        continue
    for p in sd.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS:
            continue
        if any(part in (".git", "node_modules", "__pycache__", ".venv") for part in p.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(sd)).replace("\\", "/")
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            names = set()
            for pat in PATTERNS:
                names.update(pat.findall(line))
            if not names:
                names.update(n for n in GENERIC.findall(line)
                             if "environ" in line or "env" in line.lower() or "dotenv" in line.lower())
            for n in names:
                if n in OFFICIAL or not NAME_RE.match(n):
                    continue
                # sink hint: look at surrounding window
                window = "\n".join(lines[max(0, i - 6):i + 6])
                sink = []
                if STDOUT_HINT.search(window):
                    sink.append("stdout/log")
                if NET_HINT.search(window):
                    sink.append("net")
                hits.append({
                    "candidate": sd.name, "name": n, "file": rel,
                    "line": i, "code": line.strip()[:160],
                    "sink_hint": "+".join(sink) or "?",
                })

# aggregate: candidate -> names
by_cand = {}
for h in hits:
    by_cand.setdefault(h["candidate"], {}).setdefault(h["name"], []).append(h)

print(f"candidates with custom cred names: {len(by_cand)}")
for cand in sorted(by_cand):
    names = by_cand[cand]
    print(f"\n== {cand} ({len(names)} names)")
    for n in sorted(names):
        hs = names[n]
        sinks = sorted({h['sink_hint'] for h in hs})
        h0 = hs[0]
        print(f"  {n}  [{','.join(sinks)}] {h0['file']}:{h0['line']}")
        print(f"      {h0['code']}")

out = Path("cache/exports")
out.mkdir(exist_ok=True)
(out / "sourcebound_scan.json").write_text(json.dumps(hits, indent=1, ensure_ascii=False))
print(f"\nwrote {out / 'sourcebound_scan.json'} ({len(hits)} hits)")
