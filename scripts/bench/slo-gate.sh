#!/usr/bin/env bash
# slo-gate.sh — 把 build/bench/results.jsonl 判成一个**结论**，而不是一堆数字。
#
# 为什么要有这个文件：裸金属是按小时租的，跑完机器就毁。如果收工时拿到的是一份 JSONL，还得
# 人肉去比对「这个 p99 算不算达标」，那这枪就白打了——尤其 §8.1 有 6 行口径，此前只有 2 行
# 被硬门（池命中 P50、密度），其余 4 行只测不判。本脚本把 §8.1 **集中编码在一处**，输出一张
# 判定表并以退出码表态。
#
# 用法：
#   scripts/bench/slo-gate.sh [results.jsonl]        # 宽松：缺测项记 SKIP，不失败
#   SLO_STRICT=1 scripts/bench/slo-gate.sh           # 严格：**缺测即失败**（裸金属取证用这个）
#
# 严格档的理由：M3-Q9 的判据是「创建/恢复分位在裸金属产出 SLO 口径」。一行没测出来，就是没产出，
# 不能当作通过。宁可红，也不要拿一张有窟窿的表去过出口评审。
#
# 口径来源：PRD §8.1（可用同名 env 覆写，仅供实验；**出口取证不得下调**，见计划 §4 D4）。
set -uo pipefail

FILE="${1:-build/bench/results.jsonl}"
STRICT="${SLO_STRICT:-0}"

# —— §8.1 口径（唯一编码处）——
POOL_P50_MS="${SLO_POOL_P50_MS:-100}"          # 沙箱创建 P50（池命中）
COLDSTART_P99_MS="${SLO_COLDSTART_P99_MS:-1500}" # 沙箱创建 P99（冷启动）
RESTORE_P50_MS="${SLO_RESTORE_P50_MS:-200}"    # 快照恢复 P50
EXEC_OVERHEAD_MS="${SLO_EXEC_OVERHEAD_MS:-20}" # exec 启动开销
DENSITY_DEFAULT="${SLO_DENSITY_DEFAULT:-200}"  # 密度 ≥200 @ 默认规格 2vCPU/512MiB
DENSITY_MICRO="${SLO_DENSITY_MICRO:-500}"      # 密度 ≥500 @ micro 规格 128MiB
# 密度口径写明是「**64C/128G 节点**」——参考机型是判据的一部分，不是背景说明。
REF_CPUS="${SLO_REF_CPUS:-64}"
REF_MEM_GB="${SLO_REF_MEM_GB:-128}"
# 允许的上浮比例（%）：机器比参考机型大出这么多以内仍算可比。
REF_TOLERANCE_PCT="${SLO_REF_TOLERANCE_PCT:-20}"

if [ ! -f "$FILE" ]; then
  echo "[slo-gate] 找不到 ${FILE}——先跑 scripts/bench/run-all.sh" >&2
  exit 2
fi

# —— 宿主类型闸：§8.1 的**绝对**口径只在真裸金属上成立（计划 §4 D4）——
#
# 云 VM（腾讯云 CVM 标准型、普通 EC2 等）里跑 Firecracker 是嵌套虚拟化，分位数没有可比性。
# 那条路是 D4 明确写的**逃生口**——「产方法学 + 相对分位，绝对 SLO 标『待补』+ go/no-go 上报」，
# 不是取证。严格档因此直接拒收：宁可当场红，也不要事后有人把一份虚拟机数据当成出口证据
# （两者在 JSONL 里长得一模一样，除了这个标记）。
HOST_KIND="$(grep -o '"host_kind":"[a-z-]*"' "$FILE" 2>/dev/null | tail -1 | cut -d'"' -f4)"
HOST_KIND="${HOST_KIND:-unknown}"
if [ "$HOST_KIND" != "bare-metal" ]; then
  if [ "$STRICT" = "1" ]; then
    echo "[slo-gate] 拒收：宿主类型=${HOST_KIND}，非裸金属。" >&2
    echo "[slo-gate] §8.1 绝对口径只在真裸金属上成立（计划 §4 D4）。云 VM 上的 Firecracker 是嵌套" >&2
    echo "[slo-gate] 虚拟化，分位不可比。若确实只能用云 VM，走 D4 逃生口：去掉 SLO_STRICT 跑，" >&2
    echo "[slo-gate] 产出**方法学 + 相对分位**，绝对 SLO 标「待补」并做 go/no-go 上报——不得当作取证。" >&2
    exit 3
  fi
  echo "⚠️  宿主类型=${HOST_KIND}（非裸金属）：以下数字仅可作**相对**回归对照，"
  echo "⚠️  不能充当 §8.1 绝对口径取证。见计划 §4 D4 逃生口。"
  echo
fi

# 从 results.jsonl 取某 metric 的某字段。多行取**最后一条**（同一 metric 可能跑多档）。
# $1=metric $2=字段 $3=可选的额外匹配串（如 '"spec":"micro"'）
field() {
  local metric="$1" key="$2" extra="${3:-}"
  grep "\"metric\":\"$metric\"" "$FILE" 2>/dev/null \
    | { if [ -n "$extra" ]; then grep -F "$extra"; else cat; fi; } \
    | tail -1 \
    | grep -oE "\"$key\":[0-9]+" | grep -oE '[0-9]+$' || true
}

# 同上，但取字符串/布尔字段（"mode":"single-host" / "view_consistent":true）。
sfield() {
  local metric="$1" key="$2"
  grep "\"metric\":\"$metric\"" "$FILE" 2>/dev/null | tail -1 \
    | grep -oE "\"$key\":(\"[^\"]*\"|true|false)" | sed -E "s/^\"$key\"://; s/^\"//; s/\"$//" || true
}

PASS=0; FAIL=0; SKIP=0
printf '%-34s %10s %10s   %s\n' "指标（PRD §8.1）" "实测" "口径" "判定"
printf '%s\n' "----------------------------------------------------------------------------"

# $1=名字 $2=实测（空=未测） $3=口径 $4=cmp(le|ge) $5=单位
row() {
  local name="$1" got="$2" budget="$3" cmp="$4" unit="$5"
  if [ -z "$got" ]; then
    if [ "$STRICT" = "1" ]; then
      printf '%-34s %10s %10s   %s\n' "$name" "未测" "$budget$unit" "FAIL（严格档：缺测即未达标）"
      FAIL=$((FAIL+1))
    else
      printf '%-34s %10s %10s   %s\n' "$name" "未测" "$budget$unit" "SKIP"
      SKIP=$((SKIP+1))
    fi
    return
  fi
  local ok=0
  case "$cmp" in
    le) [ "$got" -le "$budget" ] && ok=1 ;;
    ge) [ "$got" -ge "$budget" ] && ok=1 ;;
  esac
  if [ "$ok" = 1 ]; then
    printf '%-34s %10s %10s   %s\n' "$name" "$got$unit" "$budget$unit" "PASS"
    PASS=$((PASS+1))
  else
    printf '%-34s %10s %10s   %s\n' "$name" "$got$unit" "$budget$unit" "**FAIL**"
    FAIL=$((FAIL+1))
  fi
}

row "创建 P50（池命中/温池）" "$(field pool_bench warm_p50)" "$POOL_P50_MS" le "ms"
row "创建 P99（冷启动）"       "$(field coldstart p99_ms)"    "$COLDSTART_P99_MS" le "ms"

# 快照恢复 P50：§8.1 这一行指的是**恢复本身**，故取 restore_create 的 load+resume 两段之和，
# 不含 copy 与 api-ready（那两段是编排开销，已单列在创建口径里）。这个映射是一个判断，
# 出口评审时应显式确认；整体 restore_create.p50_ms 一并打印在下方备查。
_load="$(field restore_create load_p50)"; _res="$(field restore_create resume_p50)"
if [ -n "$_load" ] && [ -n "$_res" ]; then _restore=$(( _load + _res )); else _restore=""; fi
row "快照恢复 P50（load+resume）" "$_restore" "$RESTORE_P50_MS" le "ms"

row "exec 启动开销 P50"        "$(field exec_overhead p50_ms)" "$EXEC_OVERHEAD_MS" le "ms"
# —— 密度的参考机型闸 ——
#
# 密度是**内存约束**（bench-density.sh 的停因通常是 mem-floor）。在一台内存远大于参考机型的
# 机器上，门线会在机器很小一部分内存处就跨过去：384G 上 200×512MiB 只占 26%、500×128MiB 只占 16%——
# 必然 PASS，但**证明不了 64C/128G 节点上成立**。这与「micro 档冒充默认档」是同一类错误：
# 数字对，理由错。故此处校核宿主规格；超出容差就不认这两行。
#
# 正确做法是把机器约束成参考机型再跑（内核参数 `mem=128G maxcpus=64`，重启后它就真是 64C/128G），
# 而不是在这里把线放低。延迟四行不受影响——那是每次操作的延迟，不是容量约束。
HOST_CPUS="$(grep -o '"cpus":[0-9]*' "$FILE" 2>/dev/null | tail -1 | cut -d: -f2)"
HOST_MEM_GB="$(grep -o '"mem_gb":[0-9]*' "$FILE" 2>/dev/null | tail -1 | cut -d: -f2)"
HOST_CPUS="${HOST_CPUS:-0}"; HOST_MEM_GB="${HOST_MEM_GB:-0}"
MEM_CAP=$(( REF_MEM_GB * (100 + REF_TOLERANCE_PCT) / 100 ))
CPU_CAP=$(( REF_CPUS * (100 + REF_TOLERANCE_PCT) / 100 ))
DENSITY_HOST_OK=1
if [ "${SLO_DENSITY_HOST_OK:-0}" != "1" ]; then
  if [ "$HOST_MEM_GB" -gt "$MEM_CAP" ] || [ "$HOST_CPUS" -gt "$CPU_CAP" ]; then
    DENSITY_HOST_OK=0
  fi
fi

# 密度数字的**成色**：`stop_reason` 与均摊内存决定这个数能不能按字面读。
#
# - `reached-max`：撞的是 DENSITY_MAX 参数，不是真实天花板 → 这个数是**下界**，上限未探到。
# - 均摊内存 << 配置内存：Firecracker 内存惰性缺页，空闲实例根本没碰过自己那份 RAM，
#   于是密度被懒加载放大。PRD §8.1 脚注明说这份收益「**不作为 SLO 承诺**」。
#
# 两种情况都不改变「达没达门线」，但都必须显示出来——否则一个光秃秃的 PASS 会被当成
# 「200 个真实负载各吃 512MiB 也扛得住」，而证据其实只支持「N 个空闲实例共用少量内存」。
density_note() { # $1=spec
  local sp="$1" note=""
  local stop; stop="$(grep "\"metric\":\"density\"" "$FILE" 2>/dev/null | grep -F "\"spec\":\"$sp\"" | tail -1 \
    | grep -oE '"stop_reason":"[a-z-]*"' | cut -d'"' -f4)"
  local per; per="$(field density per_vm_mb_est "\"spec\":\"$sp\"")"
  local cfg; cfg="$(field density mem_mib "\"spec\":\"$sp\"")"
  [ "$stop" = "reached-max" ] && note="下界·未探到上限"
  if [ -n "$per" ] && [ -n "$cfg" ] && [ "$cfg" -gt 0 ] && [ "$per" -lt $(( cfg / 4 )) ]; then
    note="${note:+${note}·}空闲实例(均摊${per}M«配置${cfg}M)"
  fi
  echo "$note"
}

if [ "$DENSITY_HOST_OK" = "1" ]; then
  row "密度 @ 默认规格 2c/512M"  "$(field density max_instances '"spec":"default"')" "${DENSITY_DEFAULT}" ge "台"
  _n="$(density_note default)"; [ -n "$_n" ] && printf '%34s %s\n' "" "└ $_n"
  row "密度 @ micro 规格 128M"   "$(field density max_instances '"spec":"micro"')"   "${DENSITY_MICRO}"   ge "台"
  _n="$(density_note micro)"; [ -n "$_n" ] && printf '%34s %s\n' "" "└ $_n"
else
  _d="$(field density max_instances '"spec":"default"')"
  _m="$(field density max_instances '"spec":"micro"')"
  printf '%-34s %10s %10s   %s\n' "密度 @ 默认规格 2c/512M" "${_d:-未测}台" "${DENSITY_DEFAULT}台" "**不认**（宿主超参考机型）"
  printf '%-34s %10s %10s   %s\n' "密度 @ micro 规格 128M"  "${_m:-未测}台" "${DENSITY_MICRO}台"   "**不认**（宿主超参考机型）"
  if [ "$STRICT" = "1" ]; then FAIL=$((FAIL+2)); else SKIP=$((SKIP+2)); fi
fi

# ————————————————————— M3-Q10：3 节点集群（硬出口）—————————————————————
#
# 只有 results.jsonl 里真有集群指标时这一段才出现——单节点那趟不该因为"没测集群"而变红，
# 那是两件不同的事（M3-Q9 vs M3-Q10）。
CLUSTER_MODE="$(sfield cluster_topology mode)"
if [ -n "$CLUSTER_MODE" ]; then
  printf '%s\n' "----------------------------------------------------------------------------"
  printf '%s\n' "M3-Q10：3 节点集群（mode=${CLUSTER_MODE}）"

  # mode 闸：三个守护跑在同一台机器上，集群机制全都会动，但那不是 3 节点集群的 SLO——
  # 没有网络跳数、没有独立的内存/IO 竞争、杀一个"节点"也不是杀一台机器。与 host_kind 闸
  # 同一个理由：两种数据在 JSONL 里只差这个标记，不拦住就一定有人拿错的那份去过评审。
  CLUSTER_OK=1
  if [ "$CLUSTER_MODE" != "multi-host" ]; then
    CLUSTER_OK=0
  fi

  if [ "$CLUSTER_OK" = 1 ]; then
    # §8.1 的恢复口径，走**跨节点**路径（请求打到不持有该沙箱的副本）。
    row "跨节点恢复 P50" "$(field cluster_xnode xnode_resume_p50_ms)" "$RESTORE_P50_MS" le "ms"
    # 回收预算不是 PRD 数字——§8.4 只说"回收"，没给时限。脚本按机制推导（心跳租约 TTL +
    # 若干 reaper 周期）并把预算写进结果，这里照读，不另立标准。
    _budget="$(field cluster_reclaim budget_s)"
    _obs="$(field cluster_reclaim observed_s)"
    if [ -n "$_budget" ]; then
      row "节点失联回收（派生预算）" "$_obs" "$_budget" le "s"
      [ "$_obs" = "-1" ] && printf '%34s %s\n' "" "└ -1 = 观测窗内未见回收"
    else
      row "节点失联回收（派生预算）" "" "?" le "s"
    fi
    # 视图一致 / 幸存副本可服务：布尔，映射成 1/0 走同一张表。
    _vc="$(sfield cluster_topology view_consistent)"
    row "三副本视图一致" "$([ "$_vc" = "true" ] && echo 1)" 1 ge ""
    _av="$(sfield cluster_failover api_available)"
    row "幸存副本仍可服务" "$([ "$_av" = "true" ] && echo 1)" 1 ge ""
  else
    printf '%-34s %10s %10s   %s\n' "跨节点恢复 P50" "$(field cluster_xnode xnode_resume_p50_ms)ms" "${RESTORE_P50_MS}ms" "**不认**（非 multi-host）"
    printf '%-34s %10s %10s   %s\n' "节点失联回收（派生预算）" "$(field cluster_reclaim observed_s)s" "$(field cluster_reclaim budget_s)s" "**不认**（非 multi-host）"
    if [ "$STRICT" = "1" ]; then FAIL=$((FAIL+2)); else SKIP=$((SKIP+2)); fi
  fi

  # 归属是**调度出来的**还是**谁收到请求就落谁身上**。M3-Q10 判据写的是「跨节点创建/**调度**」，
  # 而创建路径从不查存活节点集，`Orch::register` 直接写本副本的 node_id。这一行必须显示，
  # 否则一张全 PASS 的表会被读成「调度成立」，而证据只到「另外两个副本看得见」。
  _pl="$(sfield cluster_topology placement)"
  if [ "$_pl" = "caller-local" ]; then
    printf '%s\n' "注：placement=caller-local —— 沙箱恒落在**收到创建请求的那个副本**上；"
    printf '%s\n' "    尚无按存活节点集选放置的调度器。M3-Q10 的「跨节点调度」这一半未实现。"
  fi
  _ro="$(field cluster_xnode relay_overhead_p50_ms)"
  [ -n "$_ro" ] && printf '%s\n' "备查：跨节点中继开销 P50 = ${_ro}ms（跨节点 − 本地基线）"
fi

printf '%s\n' "----------------------------------------------------------------------------"
_whole="$(field restore_create p50_ms)"
[ -n "$_whole" ] && echo "备查：restore_create 整体 P50 = ${_whole}ms（含 copy/api-ready 编排开销）"
_hot="$(field pool_bench hot_p50)"
[ -n "$_hot" ] && echo "备查：热池命中 P50 = ${_hot}ms"

echo
if [ "$DENSITY_HOST_OK" != "1" ]; then
  echo
  echo "⚠️  宿主 ${HOST_CPUS}C/${HOST_MEM_GB}G 超出密度口径的参考机型 ${REF_CPUS}C/${REF_MEM_GB}G（容差 ${REF_TOLERANCE_PCT}%）。"
  echo "⚠️  密度是内存约束：机器越大门线越容易跨过，PASS 也证明不了参考机型上成立。"
  echo "⚠️  正确做法是把机器约束成参考机型再跑密度——内核参数 mem=${REF_MEM_GB}G maxcpus=${REF_CPUS}，"
  echo "⚠️  重启后它就真的是 ${REF_CPUS}C/${REF_MEM_GB}G。延迟四行不受影响，无需约束。"
  echo "⚠️  确有理由在大机器上认这两行时，显式 SLO_DENSITY_HOST_OK=1（须在出口评审写明理由）。"
fi
echo
if [ -n "$CLUSTER_MODE" ] && [ "$CLUSTER_MODE" != "multi-host" ]; then
  echo "⚠️  集群 mode=${CLUSTER_MODE}：三个守护同机只证明**机制**跑通，不是 3 节点集群的 SLO。"
  echo "⚠️  M3-Q10 取证须三台真机——把 CLUSTER_REPLICAS 指向三台不同主机的守护再跑一遍。"
  echo
fi
echo "[slo-gate] PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} 宿主=${HOST_KIND} ${HOST_CPUS}C/${HOST_MEM_GB}G${CLUSTER_MODE:+ 集群=${CLUSTER_MODE}}（严格档=${STRICT}，口径来源 PRD §8.1）"
if [ "$FAIL" -gt 0 ]; then
  echo "[slo-gate] 未达标——**口径不下调**（计划 §4 D4）；须以配置/实现改进补，或走 go/no-go 上报。" >&2
  exit 1
fi
if [ "$STRICT" = "1" ] && [ "$SKIP" -gt 0 ]; then
  echo "[slo-gate] 严格档下不应出现 SKIP" >&2
  exit 1
fi
echo "[slo-gate] 全部达标。"
