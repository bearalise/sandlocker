# _common.sh — bench-*.sh 共享前置（source 我；不向 stdout 输出，保持 stdout 纯 JSON）
# 幂等构建 sl-node/sl-envd + 确保 rootfs 存在；检查 /dev/kvm。
# 返回：0 就绪 / 2 环境不满足（调用方应 emit skip JSON 后 exit 0，不阻塞 CI）。

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"
FC="$REPO_ROOT/build/firecracker/firecracker"

bench_prep() {
  command -v cargo >/dev/null 2>&1 || { echo "[bench] 无 cargo，跳过" >&2; return 2; }
  cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sl-node >&2 || return 2
  cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p sl-envd --target x86_64-unknown-linux-musl >&2 || return 2
  [ -x "$FC" ] || { echo "[bench] 缺 firecracker，跳过（scripts/fetch-firecracker.sh）" >&2; return 2; }
  [ -f "$KERNEL" ] || { echo "[bench] 缺内核，跳过（scripts/build-kernel.sh）" >&2; return 2; }
  [ -f "$ROOTFS" ] || "$REPO_ROOT/scripts/build-rootfs.sh" >&2 || return 2
  [ -w /dev/kvm ] || { echo "[bench] /dev/kvm 不可写，跳过" >&2; return 2; }
  return 0
}

# host_kind：宿主是**物理机**还是**虚拟机**——bare-metal / virtualized / container / unknown。
#
# 为什么这件事必须被记录下来：§8.1 的绝对分位口径只在真裸金属上成立（计划 §4 D4）。
# 在云 VM（腾讯云 CVM 标准型、普通 EC2 等）里跑 Firecracker 是**嵌套虚拟化**，冷启动/恢复
# 分位没有可比性——那条路是 D4 的**逃生口**（产方法学 + 相对分位，绝对 SLO 标「待补」+
# go/no-go 上报），不是取证。若不把宿主类型钉进结果，一份虚拟机上跑出来的 JSONL
# 事后看起来和裸金属的一模一样，很容易被当成出口证据。
#
# **必须有正面证据才敢说 bare-metal**，其余一律 unknown（slo-gate.sh 严格档对二者一视同仁地拒收）。
# 这条是踩出来的：早先的写法是「x86 上没有 hypervisor flag 就算物理机」——但 ARM 上根本不存在
# 这个 flag，于是一个 Docker 容器被判成了 bare-metal。把「缺少反面证据」当成正面证据，
# 恰好会放过本函数唯一要拦的那种错误。
host_kind() {
  # ① 容器：无论宿主是什么，容器里跑基准都不作数（cgroup 限额 + 共享内核）。
  if [ -f /.dockerenv ] || grep -qE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null; then
    echo "container"; return
  fi

  # ② systemd-detect-virt：最权威，认得各家 hypervisor。
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    local v; v="$(systemd-detect-virt 2>/dev/null || true)"
    case "$v" in
      none) ;;                       # 落到 ③ 再取一次正面证据
      "")   ;;
      *)    echo "virtualized"; return ;;
    esac
  fi

  # ③ x86 的 hypervisor flag：有 = 确定在虚拟机里（反面证据，可信）。
  if grep -q '^flags' /proc/cpuinfo 2>/dev/null; then
    if grep -q '^flags.*[[:space:]]hypervisor\([[:space:]]\|$\)' /proc/cpuinfo; then
      echo "virtualized"; return
    fi
  fi

  # ④ DMI 厂商串：云厂商/虚拟化产品会自报家门；真物理机报的是 OEM（Dell/Supermicro/HPE…）。
  local vendor="" product=""
  [ -r /sys/class/dmi/id/sys_vendor ]   && vendor="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
  [ -r /sys/class/dmi/id/product_name ] && product="$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
  case "${vendor} ${product}" in
    *QEMU*|*KVM*|*Bochs*|*VMware*|*VirtualBox*|*Xen*|*Hyper-V*|*"Microsoft Corporation"*|\
    *Amazon*|*Google*|*"Alibaba Cloud"*|*"Tencent Cloud"*|*OpenStack*|*Parallels*|*innotek*)
      echo "virtualized"; return ;;
  esac

  # ⑤ 走到这里：无容器迹象、无 hypervisor flag、DMI 不像虚拟化产品。
  #    只有当 DMI 确实报出了一个厂商（说明读到了真 DMI，不是空）才敢说 bare-metal。
  if [ -n "$vendor" ]; then
    echo "bare-metal"; return
  fi
  echo "unknown"
}

# node <args...>：跑 sl-node，工作目录 REPO_ROOT，独立 workdir 避免并发/残留串扰
node() { ( cd "$REPO_ROOT" && "$SL_NODE" run "$@" ); }

# count_proc <名字子串>：扫 /proc/*/comm 计数（不依赖 pgrep）
count_proc() {
  local needle="$1" n=0 f
  for f in /proc/[0-9]*/comm; do
    [ -r "$f" ] && grep -q "$needle" "$f" 2>/dev/null && n=$((n+1))
  done
  echo "$n"
}
