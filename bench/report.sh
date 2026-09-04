#!/bin/bash
# 月次検証の集計: bench/out/*.jsonl と sweep.log をまとめ、
# BROKEN / INCONCLUSIVE / LEFTOVER が 1 件でもあれば集約 issue を 1 本起票する。
# GH_TOKEN が必要（GitHub Actions では github.token）。
set -u
cd "$(dirname "$0")/.."
month=$(date -u +%Y-%m)

python3 - <<'EOF' > bench/out/summary.md
import glob, json

rows = []
for f in sorted(glob.glob('bench/out/*.jsonl')):
    for line in open(f):
        line = line.strip()
        if line:
            rows.append(json.loads(line))

broken = [r for r in rows if r['status'] == 'BROKEN']
inconc = [r for r in rows if r['status'] == 'INCONCLUSIVE']
skipped = [r for r in rows if r['status'] == 'SKIPPED']
ok = [r for r in rows if r['status'] == 'OK']
try:
    leftover = [l.strip() for l in open('bench/out/sweep.log') if l.startswith('LEFTOVER:')]
except FileNotFoundError:
    leftover = []

print(f"{len(ok)} OK / {len(broken)} BROKEN / {len(inconc)} INCONCLUSIVE / {len(skipped)} skipped\n")

def section(title, items, fmt):
    if not items:
        return
    print(f"## {title}\n")
    for it in items:
        print(fmt(it))
    print()

section('BROKEN — fail template deployed clean (constraint may have drifted)', broken,
        lambda r: f"- **{r['rule']}** ({r['service']}, {r['region']}): {r['detail']}")
section('INCONCLUSIVE — could not judge (after retry)', inconc,
        lambda r: f"- **{r['rule']}** ({r['service']}, {r['region']}): {r['detail']}")
section('LEFTOVER — resources not fully reclaimed', leftover, lambda l: f"- {l}")

with open('bench/out/counts', 'w') as f:
    f.write(f"{len(broken)} {len(inconc)} {len(leftover)}")
EOF

read -r nb ni nl < bench/out/counts
cat bench/out/summary.md

if [ "$nb" -gt 0 ] || [ "$ni" -gt 0 ] || [ "$nl" -gt 0 ]; then
  gh issue create \
    --title "monthly-verify $month: $nb broken / $ni inconclusive / $nl leftover" \
    --body-file bench/out/summary.md
else
  echo "all green — no issue filed"
fi
