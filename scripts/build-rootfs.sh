#!/usr/bin/env bash
# build-rootfs.sh — 构建 M0 最小 guest rootfs（Alpine busybox 基座 + sl-envd 静态二进制）
#
# 产物: build/rootfs/rootfs.ext4
# 设计（M0 W2）：
#   - 基座用 Alpine minirootfs（自带静态 busybox + applet 软链 + /bin/sh + musl loader），
#     为 W3 exec 就绪；busybox.net 单二进制在国内常不可达，故改用有国内镜像的 Alpine
#   - sl-envd 叠加为 /sbin/sl-envd（PID 1，见 boot_args init=），最后安装保证不被基座覆盖
#   - mke2fs -d 免 sudo 免挂载填充 ext4（本机无 docker；mke2fs ≥1.47 支持）
#   - ADR-23 的只读 base + tmpfs 写层随 M1 存储栈落地；W2 用单 rw 根盘
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build/rootfs"
STAGE="$OUT_DIR/stage"
OUT="$OUT_DIR/rootfs.ext4"
SIZE="${ROOTFS_SIZE:-128M}"
ENVD_BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/sl-envd"

# Alpine 基座（含 busybox/sh）；国内镜像 fallback，ALPINE_MIRROR 可指定单一镜像
ALPINE_VER="${ALPINE_VER:-3.20.3}"
ALPINE_BRANCH="v${ALPINE_VER%.*}"
ALPINE_TARBALL="alpine-minirootfs-${ALPINE_VER}-x86_64.tar.gz"
if [ -n "${ALPINE_MIRROR:-}" ]; then
  ALPINE_MIRRORS=("$ALPINE_MIRROR")
else
  ALPINE_MIRRORS=(
    "https://mirrors.aliyun.com/alpine"
    "https://mirrors.tuna.tsinghua.edu.cn/alpine"
    "https://mirrors.ustc.edu.cn/alpine"
    "https://dl-cdn.alpinelinux.org/alpine"
  )
fi

command -v mke2fs >/dev/null || { echo "[rootfs] 错误: 缺少 mke2fs（e2fsprogs）" >&2; exit 1; }

if [ ! -x "$ENVD_BIN" ]; then
  echo "[rootfs] 错误: 未找到 sl-envd 静态二进制: $ENVD_BIN" >&2
  echo "[rootfs] 先构建: cargo build -p sl-envd --release --target x86_64-unknown-linux-musl" >&2
  exit 1
fi

# --- 校验 sl-envd 不依赖动态加载器（guest 内无 loader，需要就直接起不来）---
#
# 判据是 **PT_INTERP 段是否存在**，不是 `file` 的措辞。Rust 的 musl target 产出的是
# **static-pie**：它是 PIE、但自包含、无 INTERP，guest 里能跑。而 `file` < 5.39
# （Ubuntu 20.04 自带 5.38）不认识 static-pie，会把它误报成 "dynamically linked"——
# 早先用 `file | grep "dynamically linked"` 判断，在 20.04 上会把完全正常的二进制拒掉。
if command -v readelf >/dev/null 2>&1; then
  if readelf -l "$ENVD_BIN" 2>/dev/null | grep -q 'INTERP'; then
    echo "[rootfs] 错误: sl-envd 需要动态加载器（有 PT_INTERP 段），guest 内无 loader 无法运行" >&2
    echo "[rootfs] 确认用 musl target 构建: cargo build -p sl-envd --release --target x86_64-unknown-linux-musl" >&2
    exit 1
  fi
elif command -v file >/dev/null 2>&1; then
  # 无 readelf 时退回 file，但要认得 static-pie（老版本 file 会误报，故先匹配肯定式）
  ENVD_FILE="$(file "$ENVD_BIN")"
  case "$ENVD_FILE" in
    *"static-pie linked"*|*"statically linked"*) : ;;
    *"dynamically linked"*)
      echo "[rootfs] 错误: sl-envd 是动态链接，guest 内无法运行；确认用 musl target 构建" >&2
      echo "[rootfs] 提示: 若本机 file < 5.39，static-pie 会被误报——装 binutils 让脚本走 readelf 判据" >&2
      exit 1 ;;
  esac
fi

echo "[rootfs] 准备 staging 目录 ..."
rm -rf "$STAGE"
mkdir -p "$STAGE"/{sbin,bin,proc,sys,dev,tmp,etc}

# --- Alpine 基座：多镜像 fallback 下载 + 解压（含 /bin/sh，为 W3 exec 就绪）---
# SKIP_ROOTFS_BASE=1（兼容旧 SKIP_BUSYBOX=1）跳过，仅含 sl-envd（W2 echo 足够）
if [ "${SKIP_ROOTFS_BASE:-${SKIP_BUSYBOX:-0}}" = "1" ]; then
  echo "[rootfs] 跳过 Alpine 基座（仅含 sl-envd；W3 exec 前需补上）"
else
  if [ ! -f "$OUT_DIR/$ALPINE_TARBALL" ]; then
    ok=0
    for m in "${ALPINE_MIRRORS[@]}"; do
      url="$m/$ALPINE_BRANCH/releases/x86_64/$ALPINE_TARBALL"
      echo "[rootfs] 尝试 $url"
      if curl -fSL --connect-timeout 8 --max-time 60 --retry 2 --retry-delay 2 \
           -o "$OUT_DIR/$ALPINE_TARBALL.tmp" "$url"; then
        mv "$OUT_DIR/$ALPINE_TARBALL.tmp" "$OUT_DIR/$ALPINE_TARBALL"
        ok=1
        break
      fi
      rm -f "$OUT_DIR/$ALPINE_TARBALL.tmp"
    done
    [ "$ok" = 1 ] || {
      echo "[rootfs] 错误: 所有 Alpine 镜像均不可达；可 SKIP_ROOTFS_BASE=1 仅构建 sl-envd" >&2
      exit 1
    }
  fi
  echo "[rootfs] 解 Alpine minirootfs（$ALPINE_VER）到 staging ..."
  # --no-same-owner：非 root 解包，文件归当前用户；minirootfs 无设备节点，无需 root
  tar --no-same-owner -xzf "$OUT_DIR/$ALPINE_TARBALL" -C "$STAGE"
  # 注意：/bin/sh -> /bin/busybox 是绝对符号链接，host 侧 -e 会按宿主根解析而误判；
  # 直接测 busybox 本体（guest 内 /bin/sh 解析正确）
  echo "[rootfs] busybox 基座就绪（$([ -x "$STAGE/bin/busybox" ] && echo 'busybox+/bin/sh 可用' || echo '⚠ 无 busybox')）"
fi

# --- sl-envd 最后叠加，保证 init 二进制不被基座覆盖 ---
echo "[rootfs] 放入 sl-envd -> /sbin/sl-envd"
install -m 0755 "$ENVD_BIN" "$STAGE/sbin/sl-envd"

# 最小 /etc：hostname 占位；machine-id 不预置——由 sl-envd 恢复后 reinit 换发（ADR-12，M1 W4），
# 避免所有克隆共享同一 machine-id（预置反而制造克隆状态泄漏）。
echo "sandlocker-m0" > "$STAGE/etc/hostname"

echo "[rootfs] 免 sudo 造 ext4（mke2fs -d，size=$SIZE）..."
rm -f "$OUT"
mke2fs -q -F -L rootfs -t ext4 -d "$STAGE" "$OUT" "$SIZE"

echo "[rootfs] 完成: $OUT ($(du -h "$OUT" | cut -f1))"
