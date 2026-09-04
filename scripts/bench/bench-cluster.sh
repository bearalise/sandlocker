#!/usr/bin/env bash
# bench-cluster.sh — **M3-Q10（3 节点集群端到端 SLO，硬出口）的取证载体**。
#
# 在此脚本之前，M3-Q10 **零覆盖**：`bench.yml` 里只有单节点的 `bench-density`，三节点集群的
# 跨节点生命周期、失联回收、选主切换没有任何自动化承载——出口评审时只能靠人肉跑一遍再手抄。
#
# ————————————————————— 这个脚本最重要的一件事：mode —————————————————————
#
# 三个 `sl-node --serve` 进程跑在**同一台机器**上，在 etcd 眼里就是三个节点（node_id=addr#pid），
# 集群机制全都会真的动起来——但那**不是 3 节点集群的 SLO**：没有网络跳数、没有独立的内存/IO
# 竞争、杀一个"节点"也不是杀一台机器。数字会偏好看。
#
# 所以每一行结果都带 `mode`：
#   single-host — 三个守护同机。**机制回归**用（CI 每次都能跑），**不是** M3-Q10 取证。
#   multi-host  — 三台真机（`CLUSTER_REPLICAS` 指向不同主机）。这才是出口证据。
# `slo-gate.sh` 严格档对 single-host 的集群行**直接拒收**——与它拒收非裸金属宿主是同一个理由：
# 两种数据在 JSONL 里长得一模一样，只差这个标记，不拦住就一定会有人拿错的那份去过评审。
#
# ————————————————————— 用法 —————————————————————
#
#   # ① 本机三守护（机制回归；CI 用这个）
#   BENCH_CLUSTER=1 CLUSTER_ETCD=http://127.0.0.1:2379 scripts/bench/bench-cluster.sh
#
#   # ② 三台真机（M3-Q10 取证；守护须已按部署指南 §4.5 起好）
#   BENCH_CLUSTER=1 CLUSTER_ETCD=http://A:2379 \
#     CLUSTER_REPLICAS=http://A:7878,http://B:7878,http://C:7878 \
#     CLUSTER_KILL_SSH=ubuntu@A,ubuntu@B,ubuntu@C \
#     scripts/bench/bench-cluster.sh
#
# stdout：多行 JSON（run-all.sh 逐行入库）；人类信息走 stderr。达标判定在 slo-gate.sh。
set -uo pipefail
. "$(dirname "$0")/_common.sh"

emit() { printf '%s\n' "$1"; }
say()  { echo "[cluster] $*" >&2; }

if [ "${BENCH_CLUSTER:-0}" != "1" ]; then
  say "未 opt-in（BENCH_CLUSTER=1 开启），跳过"
  emit '{"metric":"cluster_topology","skipped":true,"reason":"not-opted-in"}'
  exit 0
fi

ETCD="${CLUSTER_ETCD:-}"
if [ -z "$ETCD" ]; then
  say "缺 CLUSTER_ETCD——集群模式的一切共享态都在 etcd 里，没有它无从谈起"
  emit '{"metric":"cluster_topology","skipped":true,"reason":"no-etcd"}'
  exit 0
fi

N="${CLUSTER_N:-10}"                 # 跨节点 pause/resume 采样数
TICK="${CLUSTER_TICK_SECS:-5}"       # 守护 reaper 周期（也决定节点心跳租约 TTL）
TEMPLATE="${CLUSTER_TEMPLATE:-hello}"
WORK="$REPO_ROOT/build/bench/cluster"

# ————————————————————— etcd 读（走 gRPC-gateway，与 EtcdStore 同一条路）—————————————————————
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
unb64() { printf '%s' "$1" | base64 -d 2>/dev/null; }
etcd_get() { # $1=key → 值（不存在则空）
  local r; r="$(curl -sf -X POST "$ETCD/v3/kv/range" -d "{\"key\":\"$(b64 "$1")\"}" 2>/dev/null)" || return 0
  local v; v="$(printf '%s' "$r" | grep -oE '"value":"[^"]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$v" ] && unb64 "$v"
}

# ————————————————————— HTTP —————————————————————
# code_of/body_of 分开取，避免把响应体和状态码搅在一起（沙箱 id 是要用的）。
BODYF="$(mktemp)"   # 单一 EXIT trap 在下面（cleanup 一并删它——两个 trap EXIT 后者会覆盖前者）
http() { # $1=method $2=url [$3=body] → "code\nbody"
  local m="$1" u="$2"; shift 2
  local args=(-s -o "$BODYF" -w '%{http_code}' --max-time 60 -X "$m" "$u")
  [ $# -gt 0 ] && [ -n "$1" ] && args+=(-H 'Content-Type: application/json' --data-binary "$1")
  curl "${args[@]}" 2>/dev/null
  printf '\n'; cat "$BODYF" 2>/dev/null
}
code_of() { printf '%s' "$1" | head -1; }
body_of() { printf '%s' "$1" | tail -n +2; }

# 毫秒时钟。GNU date 认 %3N；不认的（BSD/busybox）退到秒级——那会让分位数粒度变粗，
# 所以这里如实降级而不是假装有毫秒精度。
if [ "$(date +%3N 2>/dev/null)" = "%3N" ] || [ -z "$(date +%3N 2>/dev/null)" ]; then
  MS_RESOLUTION="s"; ms_now() { echo $(( $(date +%s) * 1000 )); }
else
  MS_RESOLUTION="ms"; ms_now() { date +%s%3N; }
fi

# 副本自报身份：`sandlocker_build_info{node="addr#pid"}`（/metrics 免鉴权）。
# 不从 URL 猜——守护常绑 0.0.0.0 或藏在 LB 后面，那时 URL 里的主机名与 node_id 对不上，
# 猜错的后果是把 owning 副本当成"远端"，整组跨节点分位测的其实是本地路径。
replica_node_id() { # $1=副本基址
  curl -sf --max-time 10 "$1/metrics" 2>/dev/null \
    | grep -oE 'sandlocker_build_info\{node="[^"]*"' | head -1 | cut -d'"' -f2
}

# 百分位（最近秩法，与 bench-coldstart.sh 同一算法）
pct() { local p=$1; shift; local s; s=$(printf '%s\n' "$@" | sort -n)
  local i=$(( (p * $# + 99) / 100 )); [ "$i" -lt 1 ] && i=1; printf '%s\n' "$s" | sed -n "${i}p"; }

# ————————————————————— 拉起 / 接管集群 —————————————————————
PIDS=(); OWN_CLUSTER=0
cleanup() {
  rm -f "$BODYF"
  [ "$OWN_CLUSTER" = 1 ] || return 0
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  sleep 1
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

REPLICAS=()
if [ -n "${CLUSTER_REPLICAS:-}" ]; then
  IFS=',' read -r -a REPLICAS <<< "$CLUSTER_REPLICAS"
  say "接管既有集群：${REPLICAS[*]}"
else
  # 本机拉三守护 + 一网关。需要 KVM（真 FC 实例才谈得上 pause/resume 分位）。
  if ! bench_prep; then
    emit '{"metric":"cluster_topology","skipped":true,"reason":"env-not-ready"}'
    exit 0
  fi
  say "构建 cluster feature（EtcdStore + sandlocker-gw）..."
  cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sl-node --features cluster >&2 || {
    emit '{"metric":"cluster_topology","skipped":true,"reason":"cluster-build-failed"}'; exit 0; }
  GW_BIN="$REPO_ROOT/target/release/sandlocker-gw"
  [ -x "$GW_BIN" ] || { emit '{"metric":"cluster_topology","skipped":true,"reason":"no-gw-binary"}'; exit 0; }

  say "构建模板 $TEMPLATE ..."
  ( cd "$REPO_ROOT" && "$SL_NODE" --build "examples/$TEMPLATE.sandlocker.toml" --json ) >&2 || {
    emit '{"metric":"cluster_topology","skipped":true,"reason":"template-build-failed"}'; exit 0; }

  rm -rf "$WORK"; mkdir -p "$WORK"
  OWN_CLUSTER=1
  say "起网关（明文；本机对账不涉跨机传输）..."
  "$GW_BIN" --bind 127.0.0.1:17879 --node-bind 127.0.0.1:17880 --etcd "$ETCD" --insecure \
    > "$WORK/gw.log" 2>&1 &
  PIDS+=("$!")
  for i in 0 1 2; do
    port=$((17881 + i))
    mkdir -p "$WORK/n$i"
    ( cd "$REPO_ROOT" && "$SL_NODE" --serve --addr "127.0.0.1:$port" --etcd "$ETCD" \
        --gw 127.0.0.1:17880 --gw-url http://127.0.0.1:17879 --gw-insecure \
        --run-root "$WORK/n$i/run" --tick-secs "$TICK" ) > "$WORK/n$i/log" 2>&1 &
    PIDS+=("$!")
    REPLICAS+=("http://127.0.0.1:$port")
  done
  # 等三个副本都应答
  for r in "${REPLICAS[@]}"; do
    t=0; while [ "$t" -lt 30 ]; do
      [ "$(code_of "$(http GET "$r/v1/sandboxes")")" = "200" ] && break
      sleep 1; t=$((t+1))
    done
    if [ "$t" -ge 30 ]; then
      say "副本 $r 30s 未就绪，见 $WORK/*/log"
      emit '{"metric":"cluster_topology","skipped":true,"reason":"replica-not-ready"}'
      exit 0
    fi
  done
  say "本机三守护就绪：${REPLICAS[*]}"
fi

R=${#REPLICAS[@]}
if [ "$R" -lt 3 ]; then
  say "只有 $R 个副本——M3-Q10 判据是 **3 节点**"
  emit "{\"metric\":\"cluster_topology\",\"skipped\":true,\"reason\":\"need-3-replicas\",\"replicas\":$R}"
  exit 0
fi

# 逐个问副本"你是谁"（node_id=addr#pid）。这张表后面用来分辨 owner / 非 owner。
NODE_IDS=()
for r in "${REPLICAS[@]}"; do
  nid="$(replica_node_id "$r")"
  if [ -z "$nid" ]; then
    say "副本 $r 的 /metrics 没有 sandlocker_build_info——二进制太旧？"
    emit '{"metric":"cluster_topology","skipped":true,"reason":"no-build-info"}'
    exit 0
  fi
  NODE_IDS+=("$nid")
  say "副本 $r → node=$nid"
done

# mode：按副本**自报的 addr 主机部分**去重（不是 URL——URL 可能都指向同一个 LB）。
hosts="$(printf '%s\n' "${NODE_IDS[@]}" | sed -E 's#[:#].*$##' | sort -u)"
DISTINCT="$(printf '%s\n' "$hosts" | grep -c .)"
# 三个 node_id 全是回环地址 = 同机（无论它们对外的 URL 长什么样）。
if printf '%s\n' "$hosts" | grep -qE '^(127\.|localhost$|0\.0\.0\.0$)'; then DISTINCT=1; fi
MODE="single-host"; [ "$DISTINCT" -ge 3 ] && MODE="multi-host"
say "mode=$MODE（$DISTINCT 个不同主机 / $R 个副本）"
[ "$MODE" = "single-host" ] && \
  say "⚠️  同机三守护只证明**机制**跑通；M3-Q10 的 SLO 取证须 multi-host（slo-gate 严格档会拒收）"

# ————————————————————— ① 拓扑 + 视图一致 + 归属 —————————————————————
say "① 建沙箱（经副本 0）+ 查三副本视图一致 ..."
resp="$(http POST "${REPLICAS[0]}/v1/sandboxes" "{\"template\":\"$TEMPLATE\",\"ttl\":900,\"idle\":900}")"
if [ "$(code_of "$resp")" != "201" ]; then
  say "建沙箱失败：$(code_of "$resp") $(body_of "$resp")"
  emit "{\"metric\":\"cluster_topology\",\"mode\":\"$MODE\",\"skipped\":true,\"reason\":\"create-failed\"}"
  exit 0
fi
SID="$(body_of "$resp" | grep -oE '"id":"[^"]*"' | head -1 | cut -d'"' -f4)"
OWNER="$(etcd_get "sandbox/$SID/node")"
say "沙箱 $SID 归属 ${OWNER:-未知}"

VIEW_OK=1
for r in "${REPLICAS[@]}"; do
  c="$(code_of "$(http GET "$r/v1/sandboxes/$SID")")"
  [ "$c" = "200" ] || { VIEW_OK=0; say "副本 $r 看不到 $SID（$c）"; }
done

# 归属是**调度出来的**还是**谁收到请求就落谁身上**？现实是后者：`Orch::register` 直接写本副本
# 的 node_id，创建路径从不查 `node/` 存活集。这一格如实记录，免得「跨节点创建/调度」被
# 一份只证明了"另外两个副本看得见"的数据糊弄过去。
PLACEMENT="caller-local"
[ -n "$OWNER" ] && [ "$OWNER" != "${NODE_IDS[0]}" ] && PLACEMENT="scheduled"

LEADER="$(etcd_get "cluster/leader")"
emit "{\"metric\":\"cluster_topology\",\"mode\":\"$MODE\",\"replicas\":$R,\"distinct_hosts\":$DISTINCT,\
\"view_consistent\":$([ "$VIEW_OK" = 1 ] && echo true || echo false),\"placement\":\"$PLACEMENT\",\
\"leader\":\"${LEADER:-}\",\"owner\":\"${OWNER:-}\",\"tick_secs\":$TICK}"

# ————————————————————— ② 跨节点生命周期分位 —————————————————————
#
# 打到**不持有该沙箱的副本**上。这条路径在 M3 W4 余项之前是 404——不是慢，是不通。
# 同时在 owning 副本上取一组同样的样本作基线，两者之差就是中继开销。
FAR=""; NEAR=""; OWNER_IDX=-1
for i in "${!REPLICAS[@]}"; do
  if [ "${NODE_IDS[$i]}" = "$OWNER" ]; then NEAR="${REPLICAS[$i]}"; OWNER_IDX=$i
  elif [ -z "$FAR" ]; then FAR="${REPLICAS[$i]}"; fi
done
say "② 跨节点 pause/resume × $N（远端副本 ${FAR:-?} / 本地基线 ${NEAR:-?}）..."

sample_cycle() { # $1=副本基址 → "pause_ms resume_ms"，失败输出空
  local base="$1" t0 t1 c
  t0=$(ms_now); c="$(code_of "$(http POST "$base/v1/sandboxes/$SID/pause" '{}')")"; t1=$(ms_now)
  [ "$c" = "200" ] || { echo "[cluster] pause 经 $base 得 $c" >&2; return 1; }
  local pms=$(( t1 - t0 ))
  t0=$(ms_now); c="$(code_of "$(http POST "$base/v1/sandboxes/$SID/resume" '{}')")"; t1=$(ms_now)
  [ "$c" = "200" ] || { echo "[cluster] resume 经 $base 得 $c" >&2; return 1; }
  printf '%s %s' "$pms" "$(( t1 - t0 ))"
}

far_p=(); far_r=(); near_p=(); near_r=(); XNODE_OK=1
if [ -z "$FAR" ] || [ -z "$NEAR" ]; then
  say "取不到 owning/非 owning 副本（归属键=${OWNER:-空}），跳过跨节点分位"
  XNODE_OK=0
else
  for i in $(seq 1 "$N"); do
    if out="$(sample_cycle "$FAR")"; then far_p+=("${out% *}"); far_r+=("${out#* }"); fi
    if out="$(sample_cycle "$NEAR")"; then near_p+=("${out% *}"); near_r+=("${out#* }"); fi
  done
  [ "${#far_r[@]}" -gt 0 ] || XNODE_OK=0
fi

if [ "$XNODE_OK" = 1 ]; then
  fp50=$(pct 50 "${far_p[@]}");  fr50=$(pct 50 "${far_r[@]}");  fr99=$(pct 99 "${far_r[@]}")
  # 本地基线可能一个样本都没取到（例如 owning 副本刚好在别处）。那就不出基线，也不出
  # relay_overhead——一个用 0 顶替出来的"开销"会正好等于跨节点耗时本身，比缺测更误导。
  base=""
  if [ "${#near_r[@]}" -gt 0 ]; then
    np50=$(pct 50 "${near_p[@]}"); nr50=$(pct 50 "${near_r[@]}")
    base=",\"local_pause_p50_ms\":$np50,\"local_resume_p50_ms\":$nr50,\"relay_overhead_p50_ms\":$(( fr50 - nr50 ))"
    say "跨节点 resume P50=${fr50}ms P99=${fr99}ms（本地基线 ${nr50}ms）"
  else
    say "跨节点 resume P50=${fr50}ms P99=${fr99}ms（无本地基线）"
  fi
  emit "{\"metric\":\"cluster_xnode\",\"mode\":\"$MODE\",\"n\":${#far_r[@]},\"clock\":\"$MS_RESOLUTION\",\
\"xnode_pause_p50_ms\":$fp50,\"xnode_resume_p50_ms\":$fr50,\"xnode_resume_p99_ms\":$fr99${base}}"
else
  emit "{\"metric\":\"cluster_xnode\",\"mode\":\"$MODE\",\"skipped\":true,\"reason\":\"no-samples\"}"
fi

# ————————————————————— ③ 节点失联回收 —————————————————————
#
# 预算不是 PRD 给的数——§8.4 只写了「节点故障：其上沙箱标记丢失并回收」，没有时限。
# 所以这里用**机制推导**的界：心跳租约 TTL（守护取 max(tick*3,15)）+ 若干个 reaper 周期。
# 判据因此是「回收确实发生、且在机制允许的窗口内」，而不是一个凭空写死的秒数。
LEASE_TTL=$(( TICK * 3 )); [ "$LEASE_TTL" -lt 15 ] && LEASE_TTL=15
RECLAIM_BUDGET=$(( LEASE_TTL + TICK * 3 ))
say "③ 杀一个节点，等 leader 回收（租约 TTL=${LEASE_TTL}s，预算=${RECLAIM_BUDGET}s）..."

# 被杀的目标：沙箱的 owning 节点（回收的正是它名下的沙箱）。
kill_owner() {
  [ "$OWNER_IDX" -ge 0 ] || return 1
  if [ "$OWN_CLUSTER" = 1 ]; then
    # 本机模式：node_id 是 addr#pid，直接杀那个 pid。
    local pid="${OWNER##*#}"
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null && return 0
    return 1
  fi
  # 接管模式：须给 CLUSTER_KILL_SSH（与 CLUSTER_REPLICAS **同序**）才能杀远端守护。
  [ -n "${CLUSTER_KILL_SSH:-}" ] || return 1
  local hosts_arr; IFS=',' read -r -a hosts_arr <<< "$CLUSTER_KILL_SSH"
  [ "${#hosts_arr[@]}" -eq "${#REPLICAS[@]}" ] || {
    say "CLUSTER_KILL_SSH 条目数与 CLUSTER_REPLICAS 不符，拒绝乱杀"; return 1; }
  ssh -o StrictHostKeyChecking=no "${hosts_arr[$OWNER_IDX]}" 'pkill -9 -x sl-node' 2>/dev/null
}

SURVIVOR="$FAR"

if [ -n "$SURVIVOR" ] && kill_owner; then
  t0=$(ms_now); observed=""; deadline=$(( RECLAIM_BUDGET + 30 )); t=0
  while [ "$t" -lt "$deadline" ]; do
    if [ "$(code_of "$(http GET "$SURVIVOR/v1/sandboxes/$SID")")" = "404" ]; then
      observed=$(( ($(ms_now) - t0) / 1000 )); break
    fi
    sleep 1; t=$((t+1))
  done
  if [ -n "$observed" ]; then
    say "回收耗时 ${observed}s（预算 ${RECLAIM_BUDGET}s）"
    emit "{\"metric\":\"cluster_reclaim\",\"mode\":\"$MODE\",\"lease_ttl_s\":$LEASE_TTL,\
\"tick_s\":$TICK,\"budget_s\":$RECLAIM_BUDGET,\"observed_s\":$observed}"
  else
    say "${deadline}s 内未见回收"
    emit "{\"metric\":\"cluster_reclaim\",\"mode\":\"$MODE\",\"lease_ttl_s\":$LEASE_TTL,\
\"tick_s\":$TICK,\"budget_s\":$RECLAIM_BUDGET,\"observed_s\":-1}"
  fi
else
  say "杀不掉 owning 节点（接管模式须给 CLUSTER_KILL_SSH），回收行未测"
  emit "{\"metric\":\"cluster_reclaim\",\"mode\":\"$MODE\",\"skipped\":true,\"reason\":\"cannot-kill-owner\"}"
fi

# ————————————————————— ④ 选主切换 —————————————————————
#
# 若刚被杀的正是 leader，切换已在 ③ 里隐含发生（只有 leader 会回收）。这里显式量一次：
# 现任 leader 是谁、还在不在、幸存副本能否继续服务。预算同样由租约推导。
say "④ 选主状态 ..."
NEW_LEADER="$(etcd_get "cluster/leader")"
API_OK=$([ "$(code_of "$(http GET "$SURVIVOR/v1/sandboxes")")" = "200" ] && echo true || echo false)
CHANGED=$([ -n "$LEADER" ] && [ "$NEW_LEADER" != "$LEADER" ] && echo true || echo false)
say "leader: ${LEADER:-无} → ${NEW_LEADER:-无}（切换=$CHANGED，幸存副本可服务=$API_OK）"
emit "{\"metric\":\"cluster_failover\",\"mode\":\"$MODE\",\"leader_before\":\"${LEADER:-}\",\
\"leader_after\":\"${NEW_LEADER:-}\",\"leader_changed\":$CHANGED,\"api_available\":$API_OK,\
\"budget_s\":$RECLAIM_BUDGET}"

say "完成"
