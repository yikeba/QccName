#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# 集群一致性检查：从本机节点取成员表，逐台查询 /v1/status，对比 seq 与执行层 hash（execHash）
#
#   用法（在实例目录下）：./qccname-check.sh            一次
#                         ./qccname-check.sh -w 5       每 5 秒刷新一次（Ctrl+C 退出）
#   判定：所有节点 seq 相同且 execHash 相同 → ✓ 一致
#         seq 落后但 execHash 与主节点同 seq 时一致 → 同步中（几秒内应追平）
#         同一 seq 下 execHash 不同 → ✗ 分叉：立即停止写入，保留日志
# ═══════════════════════════════════════════════════════════════════════════
set -uo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$APP_DIR/qccname.properties"
PORT=$(grep -E '^[[:space:]]*port[[:space:]]*=' "$CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')
PORT=${PORT:-9180}
WATCH=0; [ "${1:-}" = "-w" ] && WATCH=${2:-5}

check() {
python3 - "$PORT" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
def get(url):
    try:
        with urllib.request.urlopen(url, timeout=4) as r: return json.load(r)
    except Exception as e: return {"_err": str(e)[:60]}
me = get(f"http://127.0.0.1:{port}/v1/status")
if "_err" in me: print("本机节点无响应：", me["_err"]); sys.exit(2)
cl = me.get("cluster", {})
addrs = cl.get("addrs", {})
rows = []
for nid in cl.get("cores", []) + cl.get("observers", []):
    a = addrs.get(nid, "")
    s = get(f"http://{a}/v1/status") if a else {"_err": "无地址"}
    rows.append((nid, a, "核心" if nid in cl.get("cores", []) else "冗余", s))
top = max((r[3].get("seq", -1) for r in rows if "_err" not in r[3]), default=-1)
ref = next((r[3]["execHash"] for r in rows if r[3].get("seq") == top and r[3].get("role") == "primary"), None) \
      or next((r[3]["execHash"] for r in rows if r[3].get("seq") == top), None)
print(f"实例端口 {port}   term={cl.get('term')}   主={str(cl.get('primary',''))[:12]}…   核心 {len(cl.get('cores',[]))}  冗余 {len(cl.get('observers',[]))}   过半={len(cl.get('cores',[]))//2+1}")
print(f"{'节点':<14}{'类型':<6}{'角色':<10}{'term':>5}{'seq':>8}  {'execHash':<18} 地址")
bad = lag = down = 0
hashes = {}
for nid, a, kind, s in rows:
    if "_err" in s:
        down += 1; print(f"{nid[:12]+'…':<14}{kind:<6}{'不可达':<10}{'':>5}{'':>8}  {'':<18} {a}  ({s['_err']})"); continue
    seq, h = s.get("seq"), s.get("execHash", "")
    hashes.setdefault(seq, set()).add(h)
    mark = "✓" if seq == top and h == ref else ("…" if seq < top else "✗")
    if seq < top: lag += 1
    print(f"{nid[:12]+'…':<14}{kind:<6}{s.get('role',''):<10}{s.get('term',''):>5}{seq:>8}  {h[:16]:<16} {mark} {a}")
fork = [q for q, hs in hashes.items() if len(hs) > 1]
print("─" * 78)
if fork: print(f"✗ 分叉：seq {fork} 上出现不同的 execHash —— 立即停止写入，保留各节点日志"); sys.exit(1)
if down or lag: print(f"… 不可达 {down} 台，同步中 {lag} 台（seq 落后于 {top}）；其余一致")
else: print(f"✓ 全部 {len(rows)} 台一致：seq={top}  execHash={ref}")
PY
}

if [ "$WATCH" -gt 0 ] 2>/dev/null; then
    while true; do clear; date '+%F %T'; check; sleep "$WATCH"; done
else
    check
fi
