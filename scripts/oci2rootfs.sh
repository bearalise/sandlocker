#!/usr/bin/env bash
# oci2rootfs.sh — 把一个容器镜像转成 SandLocker 可用的 base rootfs（ext4）
#
# 用法:
#   scripts/oci2rootfs.sh docker://python:3.12-slim [输出名]   # 走本地 docker daemon
#   scripts/oci2rootfs.sh archive:./python.tar      [输出名]   # docker save 产物，免 daemon
#   scripts/oci2rootfs.sh dir:/path/to/unpacked     [输出名]   # 已解开的 rootfs 目录
#
# 产物（build/rootfs/ 下，<名> 缺省由镜像引用推导）:
#   <名>.ext4              — 直接作模板 from = "build/rootfs/<名>.ext4"
#   <名>.provenance.json   — 来源镜像 digest + 产物 sha256（构建溯源留档）
#   <名>.sandlocker.toml   — 由镜像 config 生成的模板脚手架（ADR-18 语义映射，需人工过一遍）
#
# ── 定位（重要，与 crates/sl-node/src/oci.rs 的 in-process 拉取互补，别混淆）──────
# 仓库现有**两条 OCI→rootfs 路径**，用途不同：
#   ① sl-node 内建（M2 W3 已合并，crates/sl-node/src/oci.rs）：模板直接写 from = "docker://<ref>"
#      或 from = "docker-archive:<tar>"，build.rs 的 classify → source_to_rootfs 进程内拉取
#      （ureq+rustls 手写 registry v2 + flate2/tar flatten），走 source_digest 稳 build_id。
#      **CI / 一键 / 要可复现 build_id 的场景用这条。**
#   ② 本脚本（外围工具，不进核心构建路径）：把镜像先转成一个本地 ext4 + 模板脚手架，
#      模板再写 from = "build/rootfs/<名>.ext4"（走 build.rs 的 Local 分支）。
#      **需要本地 docker daemon 便利路径、离线 docker save、或想人工审一遍 config/rootfs 再用的
#      场景用这条。** 注意：走 Local 分支时 build_id 依赖 ext4 的 sha256，而本脚本产物非字节级
#      可复现（见下「已知边界」末条），故同镜像重转会令 build_id 抖动、ADR-16 快照缓存 miss；
#      要稳定 build_id 请改用 ①（sl-node --oci-pull / from = "docker://…"）。
# PRD 6.2「构建无需 Docker daemon」：docker:// 档需要 docker（便利路径），archive:/dir: 才 daemonless。
#
# ── 硬约束（与 crates/sl-node 对齐，缺一不可）──────────────────────────────────
#   - /sbin/sl-envd 静态二进制：guest PID 1（main.rs boot_args `init=/sbin/sl-envd`）
#   - /etc/machine-id 必须不存在：否则 build.rs 的 D5 断言 assert_no_identity 硬失败（ADR-12）
#   - 需 /bin/sh + base64 + printf：build.rs 的 COPY 走 base64 分块经 exec 注入
#   - 单 rw 根盘 /dev/vda；不支持 systemd 镜像；ENTRYPOINT/CMD 不自动执行（ADR-18）
#
# ── 已知边界 ──────────────────────────────────────────────────────────────────
#   - 解包跑在**宿主侧**且镜像内容不可信。分层防护（best-effort，非沙箱）：
#       · tar 不给 -P（GNU tar 剥前导 / 并拒 `..` 成员）、剥离 /dev；
#       · **合层阶段**（archive 档）：每层 whiteout 删除前做 staging 越界解析（越界即跳过、不删宿主），
#         每层 cp -a 合并前把 staging 顶层绝对符号链接改写为相对（中和 `etc -> /` 这类会被 cp/rm
#         当父路径跟随而逃逸的顶层目录符号链）；
#       · **注入阶段**（sl-envd / machine-id / 挂载点）：每个写入点走 sp() / sp_soft() 越界检查。
#     **残留缺口**：**深层**（非顶层）父路径符号链接的逃逸不在防护内——bash 做不到
#     openat2(RESOLVE_IN_ROOT) 级别的逐段解析，TOCTOU 也没处理。故上面的检查是收敛常见攻击面，
#     **不等于沙箱化**。来路不明的镜像请先在隔离环境里转；正式的 oci:// 实现应把解包放进构建沙箱。
#   - 非 root 解包会丢 setuid 位 / 设备节点 / 文件属主（sl-envd 会挂 devtmpfs，/dev 不需要）。
#   - 大镜像会打穿创建热路径：orch 每次 create 全量拷 rootfs（reflink 优先），
#     且预烘焙快照烘死 1 vCPU / 128 MiB（build.rs 的 /machine-config）——真跑 Python 类镜像
#     需要先改那处并接 dm-thin。
#   - **可复现性是尽力而为，不是字节级保证**（重要，直接影响 build.rs 的 build_id）：
#       已钉住：ext4 UUID、目录哈希种子、超级块三个时间戳、本脚本新建文件的 mtime。
#       钉不住：`mke2fs -d` 给**每个 inode** 写的 ctime/crtime = "现在"（逐 inode 改还要连带
#               重算 inode 校验和，超出本脚本定位）。stock e2fsprogs 1.47 不认 SOURCE_DATE_EPOCH
#               （二进制里无此串），装了 reproducible-builds 补丁的版本才会连 inode 时间一起钉。
#       后果：同一镜像两次转换，**内容一致但字节不一致** → sha256 变 → build.rs 的 build_id 变
#             → ADR-16 快照缓存 miss。实践上转一次留着复用即可；要真正的可复现构建，得在
#             正式的 oci:// 实现里解决（这正是该走 ADR 而非外围脚本的理由之一）。
#             产物 sha256 记在 .provenance.json 里，便于跨机比对。
#
# 环境变量:
#   ENVD_BIN=<path>        sl-envd 静态二进制（缺省 target/x86_64-unknown-linux-musl/release/sl-envd）
#   ROOTFS_SIZE=2G         强制 ext4 大小（缺省按 stage 实占自动定尺 + 余量）
#   ROOTFS_UUID=<uuid>     ext4 UUID（缺省由输出名派生，保证可复现）
#   SOURCE_DATE_EPOCH=0    归一化时间戳基准（缺省 0）——注意 stock e2fsprogs 并不认这个变量，
#                          本脚本是自己把超级块三个时间戳改成它，见 normalize_superblock_times
#   KEEP_STAGE=1           保留 staging 目录便于排查
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build/rootfs"
ENVD_BIN="${ENVD_BIN:-$REPO_ROOT/target/x86_64-unknown-linux-musl/release/sl-envd}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

die() { echo "[oci2rootfs] 错误: $*" >&2; exit 1; }
info() { echo "[oci2rootfs] $*"; }
# 镜像里大量符号链接是**绝对**的（/bin/sh -> /bin/busybox），宿主侧 -e 会按宿主根解析而误判，
# 故存在性判断须 -e 或 -L（见 build-rootfs.sh 同款坑）。
has_path() { [ -e "$1" ] || [ -L "$1" ]; }
# 镜像目录常含 0555 的只读目录，直接 rm -rf 会失败。
# 卫语句必须 -e 或 -L：悬空符号链（如绝对链改写成相对后在 stage 内暂无目标）用 -e 判会漏成"不存在"
# 而不删——那会让后续 cp -a 撞上"符号链 vs 目录"冲突（见 has_path 同款坑）。
safe_rm() { { [ -e "$1" ] || [ -L "$1" ]; } || return 0; chmod -R u+rwX "$1" 2>/dev/null || true; rm -rf "$1"; }

# ── 参数 ──────────────────────────────────────────────────────────────────────

[ $# -ge 1 ] || die "缺少镜像来源。用法: $0 docker://<ref> | archive:<tar> | dir:<path> [输出名]"
SOURCE="$1"
NAME="${2:-}"

case "$SOURCE" in
  docker://*) MODE=docker; REF="${SOURCE#docker://}" ;;
  archive:*)  MODE=archive; REF="${SOURCE#archive:}" ;;
  dir:*)      MODE=dir; REF="${SOURCE#dir:}" ;;
  *) die "来源需带 scheme：docker://<ref> | archive:<tar> | dir:<path>（收到 ${SOURCE}）" ;;
esac

# 输出名缺省由引用推导：python:3.12-slim -> python-3.12-slim
if [ -z "$NAME" ]; then
  NAME="$(basename "$REF")"
  NAME="${NAME%.tar}"
  NAME="$(printf '%s' "$NAME" | tr ':/' '--' | tr -cd 'A-Za-z0-9._-')"
fi
[ -n "$NAME" ] || die "无法从 ${REF} 推导输出名，请显式给第二个参数"

STAGE="$OUT_DIR/stage-$NAME"
OUT="$OUT_DIR/$NAME.ext4"
PROV="$OUT_DIR/$NAME.provenance.json"
TOML="$OUT_DIR/$NAME.sandlocker.toml"
TMP=""

cleanup() {
  [ -n "$TMP" ] && safe_rm "$TMP"
  if [ "${KEEP_STAGE:-0}" != "1" ]; then safe_rm "$STAGE"; fi
}
trap cleanup EXIT

# ── 前置检查 ──────────────────────────────────────────────────────────────────

[ "$(uname -m)" = "x86_64" ] || die "本项目仅 x86_64（uname -m = $(uname -m)）"
command -v mke2fs >/dev/null || die "缺少 mke2fs（apt-get install e2fsprogs）"
command -v tar >/dev/null || die "缺少 tar"

[ -x "$ENVD_BIN" ] || die "未找到 sl-envd 静态二进制: $ENVD_BIN
  先构建: cargo build -p sl-envd --release --target x86_64-unknown-linux-musl"
if command -v file >/dev/null && file "$ENVD_BIN" | grep -q "dynamically linked"; then
  die "sl-envd 是动态链接，guest 内无 loader 会直接失败；确认用 musl target 构建"
fi

mkdir -p "$OUT_DIR"
safe_rm "$STAGE"
mkdir -p "$STAGE"
# staging 的真实（解析后）根路径——合层/注入阶段的越界判断都以它为界。
STAGE_REAL="$(cd "$STAGE" && pwd -P)"

# 顶层绝对符号链接 → 相对（guest 内从根解析等价，宿主侧不再逃逸）；usrmerge(/sbin->/usr/sbin) 照常。
# 只处理**顶层**：会被 cp/rm 当作父路径跟随而逃逸的目录符号链几乎都在顶层（usrmerge / `etc -> /`）。
# 深层符号链接的越界不在防护内（见文件头「已知边界」）——正式 oci:// 应放进沙箱解包。
rewrite_toplevel_abs_symlinks() {
  local p t
  for p in "$STAGE"/* "$STAGE"/.[!.]*; do
    [ -L "$p" ] || continue
    t="$(readlink "$p")"
    case "$t" in
      /*) ln -sfn "${t#/}" "$p"
          info "改写顶层绝对符号链接 /$(basename "$p") → ${t#/}（guest 内等价，宿主侧不再逃逸）" ;;
    esac
  done
}

# 跨层类型变更：OCI 允许高层把目录换成文件（或反之，无显式 whiteout），cp -a 遇到会 `cannot
# overwrite directory with non-directory` 中止。合并前先删掉 stage 中与来层类型冲突的目标，让 cp 重建。
reconcile_types() {
  local src="$1" stage="$2" p rel dst
  while IFS= read -r -d '' p; do
    rel="${p#"$src"/}"; dst="$stage/$rel"
    { [ -e "$dst" ] || [ -L "$dst" ]; } || continue
    if { [ -d "$p" ] && [ ! -L "$p" ] && { [ ! -d "$dst" ] || [ -L "$dst" ]; }; } || \
       { { [ ! -d "$p" ] || [ -L "$p" ]; } && [ -d "$dst" ] && [ ! -L "$dst" ]; }; then
      safe_rm "$dst"
    fi
  done < <(find "$src" -mindepth 1 -print0 2>/dev/null)
}

# ── 解包：三档来源 ────────────────────────────────────────────────────────────

# 不可信 tar 的解包姿态：
#   -P 不给（GNU tar 默认剥掉前导 / 并拒绝 `..` 成员）；--no-same-owner 非 root 下不试图 chown；
#   排除 dev/*：设备节点非 root 建不了，且 sl-envd 会自己挂 devtmpfs（无需镜像里的 /dev）。
untar_layer() {
  local archive="$1" dest="$2"
  tar --no-same-owner --delay-directory-restore \
      --exclude='dev/*' --exclude='./dev/*' \
      -xf "$archive" -C "$dest"
}

# OCI/docker-archive 的 whiteout 语义：上层用 `.wh.<name>` 标记删除、`.wh..wh..opq` 标记清空目录。
# 逐层「解到临时目录 → 按 whiteout 删 stage 中对应项 → 覆盖合并」是最小依赖实现（仅需 coreutils）。
apply_whiteouts() {
  local layerdir="$1" stage="$2" wh base rel target real
  while IFS= read -r wh; do
    base="$(basename "$wh")"
    rel="$(dirname "${wh#"$layerdir"/}")"
    if [ "$base" = ".wh..wh..opq" ]; then
      target="$stage/$rel"
    else
      target="$stage/$rel/${base#.wh.}"
    fi
    # 越界解析：镜像里的父路径符号链接可能把删除操作引到 stage 之外（宿主）。逐段解析后越界即跳过，
    # 绝不在宿主上删文件（比 build.rs 的构建期更早、更彻底地守住这条红线）。
    real="$(readlink -m "$target" 2>/dev/null || true)"
    case "$real" in
      "$STAGE_REAL" | "$STAGE_REAL"/*)
        if [ "$base" = ".wh..wh..opq" ]; then
          [ -d "$target" ] && find "$target" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
        else
          safe_rm "$target"
        fi ;;
      *) info "跳过越界白化 ${wh#"$layerdir"/}（在 staging 内解析到 $real，宿主逃逸）" ;;
    esac
    rm -f "$wh"
  done < <(find "$layerdir" -name '.wh.*' 2>/dev/null)
}

IMG_REF="$REF"
IMG_DIGEST=""
CFG_ENV=""
CFG_WORKDIR=""
CFG_USER=""
# ENTRYPOINT / CMD 保持 **argv 数组原样**，不拼成一行 shell —— 拼接会丢参数边界
# （["/bin/sh","-c","sleep 999"] 拼出来是 `/bin/sh -c sleep 999`，语义已经错了）。
CFG_ENTRYPOINT_JSON=""
CFG_CMD_JSON=""

case "$MODE" in
  docker)
    command -v docker >/dev/null || die "docker:// 档需要 docker CLI；免 daemon 请用 archive:（docker save -o x.tar <ref>）"
    docker image inspect "$REF" >/dev/null 2>&1 || die "本地无此镜像: $REF（先 docker pull）"
    info "docker:// 档：会访问本地 docker daemon（PRD 6.2 的 daemonless 约束在此档不成立）"

    IMG_DIGEST="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$REF" 2>/dev/null || true)"
    [ -n "$IMG_DIGEST" ] || IMG_DIGEST="$(docker image inspect --format '{{.Id}}' "$REF")"

    CFG_ENV="$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$REF" 2>/dev/null || true)"
    CFG_WORKDIR="$(docker image inspect --format '{{.Config.WorkingDir}}' "$REF" 2>/dev/null || true)"
    CFG_USER="$(docker image inspect --format '{{.Config.User}}' "$REF" 2>/dev/null || true)"
    CFG_ENTRYPOINT_JSON="$(docker image inspect --format '{{json .Config.Entrypoint}}' "$REF" 2>/dev/null || true)"
    CFG_CMD_JSON="$(docker image inspect --format '{{json .Config.Cmd}}' "$REF" 2>/dev/null || true)"

    # docker export = 已扁平化的容器文件系统，无需自己合层
    info "docker export ${REF} → staging ..."
    cid="$(docker create "$REF" /bin/true)"
    if ! docker export "$cid" | tar --no-same-owner --delay-directory-restore \
           --exclude='dev/*' --exclude='./dev/*' -x -C "$STAGE"; then
      docker rm -f "$cid" >/dev/null 2>&1 || true
      die "docker export 解包失败"
    fi
    docker rm "$cid" >/dev/null
    ;;

  archive)
    [ -f "$REF" ] || die "归档不存在: $REF"
    command -v python3 >/dev/null || die "archive: 档需要 python3 解析 manifest.json"
    TMP="$(mktemp -d)"
    info "展开归档 $REF ..."
    tar --no-same-owner -xf "$REF" -C "$TMP"
    if [ ! -f "$TMP/manifest.json" ]; then
      if [ -f "$TMP/oci-layout" ] || [ -f "$TMP/index.json" ]; then
        die "这是 OCI layout 归档（oci-archive，含 index.json/oci-layout），本脚本 archive: 档只支持
  docker save 产物（docker-archive，含 manifest.json）。OCI layout 请改用 sl-node 内建拉取：
    sl-node --oci-pull oci-archive:$REF   （或远程 docker://<ref>）"
      fi
      die "归档里没有 manifest.json（archive: 档需要 docker save 产物 / docker-archive 格式）"
    fi

    # 解析 manifest：拿到层顺序与 config 文件名
    LAYERS="$(python3 - "$TMP/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print("\n".join(m[0].get("Layers", [])))
PY
)"
    CFG_FILE="$(python3 - "$TMP/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print(m[0].get("Config", ""))
PY
)"
    [ -n "$LAYERS" ] || die "manifest.json 未列出 Layers"

    if [ -n "$CFG_FILE" ] && [ -f "$TMP/$CFG_FILE" ]; then
      # image ID 的定义就是 config blob 的 sha256 —— 直接算，别从文件名猜
      # （docker save 的 Config 可能是 <64hex>.json，也可能是 blobs/sha256/<hex>）
      IMG_DIGEST="sha256:$(sha256sum "$TMP/$CFG_FILE" | cut -d' ' -f1)"
      CFG_ENV="$(python3 - "$TMP/$CFG_FILE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])).get("config", {}) or {}
print("\n".join(c.get("Env") or []))
PY
)"
      CFG_WORKDIR="$(python3 - "$TMP/$CFG_FILE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])).get("config", {}) or {}
print(c.get("WorkingDir") or "")
PY
)"
      CFG_USER="$(python3 - "$TMP/$CFG_FILE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])).get("config", {}) or {}
print(c.get("User") or "")
PY
)"
      CFG_ENTRYPOINT_JSON="$(python3 - "$TMP/$CFG_FILE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])).get("config", {}) or {}
print(json.dumps(c.get("Entrypoint") or []))
PY
)"
      CFG_CMD_JSON="$(python3 - "$TMP/$CFG_FILE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1])).get("config", {}) or {}
print(json.dumps(c.get("Cmd") or []))
PY
)"
    fi

    n=0
    while IFS= read -r layer; do
      [ -n "$layer" ] || continue
      n=$((n + 1))
      [ -f "$TMP/$layer" ] || die "层文件缺失: $layer"
      info "合层 [$n] $layer"
      ldir="$TMP/.layer-$n"
      mkdir -p "$ldir"
      untar_layer "$TMP/$layer" "$ldir"
      apply_whiteouts "$ldir" "$STAGE"
      # 合并前中和 stage 里（前面各层留下的）顶层绝对符号链，避免这层的 cp -a 顺着 `etc -> /`
      # 之类跟随到宿主；再处理跨层类型变更，最后合并（type reconcile 后 cp -a 不会因目录/文件冲突中止）。
      rewrite_toplevel_abs_symlinks
      reconcile_types "$ldir" "$STAGE"
      cp -a "$ldir/." "$STAGE/"
      safe_rm "$ldir"
    done <<EOF
$LAYERS
EOF
    info "合层完成（共 $n 层）"
    ;;

  dir)
    [ -d "$REF" ] || die "目录不存在: $REF"
    info "从目录复制 $REF → staging ..."
    cp -a "$REF/." "$STAGE/"
    IMG_DIGEST="dir:$(cd "$REF" && pwd)"
    ;;
esac

# ── 宿主侧写操作的越狱防线 ────────────────────────────────────────────────────
#
# 镜像里的符号链接会把 /sbin、/etc 指到 stage 之外——usrmerge 的绝对写法（/sbin -> /usr/sbin），
# 或恶意镜像的 /etc -> /。不设防的话，下面的 install/echo/rm 就**写到宿主真实路径上**了
# （用 sudo 跑这类 rootfs 工具很常见，后果直接是污染宿主 /usr/sbin、/etc）。
#
# 两道处理（与合层阶段共用 rewrite_toplevel_abs_symlinks，此处对注入再兜底一次）：
#   ① 顶层绝对符号链接改写成等价的相对形式：对 /x 而言 "/a/b" 与 "a/b" 从根解析结果相同，
#      guest 内语义不变，宿主侧则不再逃逸（usrmerge 这一合法情形照常工作）。
#   ② 下面每个写入点经 sp()/sp_soft() 先解析父目录，**逃出 $STAGE 就拒绝**，不猜用户意图。
# 注：真正健壮的做法是 openat2(RESOLVE_IN_ROOT) 级别的逐段解析，bash 做不到（深层父路径符号链
#     仍是残留缺口，见文件头「已知边界」）——这也是"解包该放进沙箱、而不是宿主裸跑"的论据
#     （正式 oci:// 实现应解决）。

# 合层后再中和一次顶层绝对符号链（docker/dir 档在此首次处理；archive 档每层已处理过，这里兜底）。
rewrite_toplevel_abs_symlinks

# 解析 guest 路径 → 全局 SP（对应的宿主路径），越界即中止。
# 结果**经全局变量返回而非回显**：die 写在 $( ) 里只会杀掉子 shell，杀不掉脚本本身
# （这正是本函数第一版的 bug——逃逸路径被判出来了，脚本却照跑不误）。
# readlink -m 会把**每一段**符号链接连同 `..` 一并解析掉，故 /etc 自身是逃逸链接时同样拦得住。
sp() {
  local resolved
  resolved="$(readlink -m "$STAGE$1" 2>/dev/null || true)"
  case "$resolved" in
    "$STAGE_REAL" | "$STAGE_REAL"/*) SP="$resolved" ;;
    *) die "镜像里的符号链接把 $1 指到了 staging 之外（宿主路径逃逸），拒绝写入。
  用 KEEP_STAGE=1 重跑后检查 $STAGE，确认这镜像的布局是否可信。" ;;
  esac
}

# 同上，但越界只回非零、不中止（用于「有则清、没有就算了」的尽力而为项）
sp_soft() {
  local resolved
  resolved="$(readlink -m "$STAGE$1" 2>/dev/null || true)"
  case "$resolved" in
    "$STAGE_REAL" | "$STAGE_REAL"/*) SP="$resolved"; return 0 ;;
    *) SP=""; return 1 ;;
  esac
}

# ── 适配 SandLocker 硬约束 ────────────────────────────────────────────────────

info "注入 sl-envd → /sbin/sl-envd（guest PID 1）"
sp /sbin/sl-envd
mkdir -p "$(dirname "$SP")"
install -m 0755 "$ENVD_BIN" "$SP"

# D5 不变量：预烘焙点前禁固定身份，否则所有克隆共享 machine-id（ADR-12）。
# build.rs 会在 RUN 前后各断言一次，这里不清就是构建期硬失败。
if has_path "$STAGE/etc/machine-id" || has_path "$STAGE/var/lib/dbus/machine-id"; then
  info "清除预置 machine-id（ADR-12 / build.rs 的 D5 断言要求为空）"
fi
sp /etc/machine-id && rm -f "$SP"
# dbus 那份是尽力而为：逃逸就跳过（真正卡门的是 /etc/machine-id，build.rs 只断言它）
sp_soft /var/lib/dbus/machine-id && rm -f "$SP"
rm -f "$STAGE/.dockerenv"

# sl-envd 会挂 proc/sys/dev/tmp，挂载点必须先存在
for d in proc sys dev tmp etc; do
  sp "/$d"
  mkdir -p "$SP"
done
sp /tmp && chmod 1777 "$SP"
sp /etc/hostname
[ -s "$SP" ] || echo "sandlocker" > "$SP"

# 可复现：把**本脚本新建/改动**的路径的 mtime 钉到 SOURCE_DATE_EPOCH。
# 只钉这些（不整树归零）——镜像内原有时间戳保持不动，避免破坏 .pyc 之类按 mtime 做失效判断的缓存。
# 注意父目录也要钉：往 /etc /sbin 里塞文件会把父目录 mtime 改成"现在"。
for p in / /sbin /sbin/sl-envd /etc /etc/hostname /proc /sys /dev /tmp /var/lib/dbus; do
  [ -e "$STAGE$p" ] && touch -h -d "@$SOURCE_DATE_EPOCH" "$STAGE$p"
done
true

# ── 体检（不满足会在 build/boot 阶段才炸，提前拦住）──────────────────────────

FAIL=0
if ! has_path "$STAGE/bin/sh"; then
  echo "[oci2rootfs] 体检 FAIL: 缺 /bin/sh —— build.rs 的 RUN/COPY 全部走 sh -c" >&2
  FAIL=1
fi
if ! has_path "$STAGE/bin/base64" && ! has_path "$STAGE/usr/bin/base64" && ! has_path "$STAGE/bin/busybox"; then
  echo "[oci2rootfs] 体检 WARN: 未见 base64（busybox applet 也算）——COPY 注入会失败" >&2
fi
if has_path "$STAGE/usr/lib/systemd/systemd" || has_path "$STAGE/lib/systemd/systemd"; then
  echo "[oci2rootfs] 体检 WARN: 镜像含 systemd —— ADR-18 明示不支持，init 是 sl-envd 而非 systemd" >&2
fi
[ "$FAIL" -eq 0 ] || die "体检未通过，产物不会生成"

# ── 造 ext4（确定性：固定 UUID + SOURCE_DATE_EPOCH）──────────────────────────

if [ -n "${ROOTFS_SIZE:-}" ]; then
  SIZE="$ROOTFS_SIZE"
else
  # 实占 ×1.4（ext4 元数据 + 目录开销）+ 256 MiB 余量（留给模板 RUN 步骤写入），下限 256 MiB
  DU_KB="$(du -sk "$STAGE" | cut -f1)"
  SIZE_MIB=$(( DU_KB / 1024 * 14 / 10 + 256 ))
  [ "$SIZE_MIB" -ge 256 ] || SIZE_MIB=256
  SIZE="${SIZE_MIB}M"
fi

FS_UUID="${ROOTFS_UUID:-$(printf '%s' "$NAME" | sha256sum | cut -c1-32 \
  | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')}"

info "造 ext4（size=$SIZE, uuid=$FS_UUID, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH）..."
rm -f "$OUT"
# hash_seed 缺省是**每次随机**的（目录哈希种子进超级块），不钉住则同输入不同产物。
# 老 e2fsprogs（<1.45.7）不认这个 -E，退回不钉：产物仍可用，只是不再字节级可复现。
if ! mke2fs -q -F -L rootfs -t ext4 -U "$FS_UUID" -E "hash_seed=$FS_UUID" \
       -d "$STAGE" "$OUT" "$SIZE" 2>/dev/null; then
  echo "[oci2rootfs] 提示: mke2fs 不支持 -E hash_seed（e2fsprogs 太老），退回随机种子——产物可用但非字节级可复现" >&2
  rm -f "$OUT"
  mke2fs -q -F -L rootfs -t ext4 -U "$FS_UUID" -d "$STAGE" "$OUT" "$SIZE"
fi

# 最后一处不确定性：mke2fs 往超级块写三个"现在"时间戳（s_wtime/s_lastcheck/s_mkfs_time）。
# 实测 Ubuntu 的 e2fsprogs 1.47 **不认** SOURCE_DATE_EPOCH（二进制里根本没这个串），debugfs 又会在
# 关闭时把 s_wtime 改回现在，故这里直接改字节 + 重算超级块 crc32c（metadata_csum 默认开，不重算即损坏）。
# 安全阀：改完必过 e2fsck，不过就整份还原——最坏只是丢字节级可复现，绝不产出坏 rootfs。
normalize_superblock_times() {
  local img="$1"
  command -v python3 >/dev/null || {
    echo "[oci2rootfs] 提示: 无 python3，跳过超级块时间戳归一——产物可用但非字节级可复现" >&2
    return 0
  }
  cp "$img" "$img.prenorm"
  if ! python3 - "$img" "$SOURCE_DATE_EPOCH" <<'PY'
import struct, sys
SB = 1024                       # ext4 超级块偏移
OFF_WTIME, OFF_LASTCHECK, OFF_MKFS, OFF_CSUM = 0x30, 0x40, 0x108, 0x3FC
FEAT_METADATA_CSUM = 0x400      # s_feature_ro_compat @0x64

def crc32c(data, crc=0xFFFFFFFF):   # 反射多项式 0x82F63B78，无末尾取反（同 ext2fs_crc32c_le）
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1))
    return crc & 0xFFFFFFFF

img, epoch = sys.argv[1], int(sys.argv[2]) & 0xFFFFFFFF
with open(img, 'r+b') as f:
    f.seek(SB); sb = bytearray(f.read(1024))
    ro_compat = struct.unpack_from('<I', sb, 0x64)[0]
    for off in (OFF_WTIME, OFF_LASTCHECK, OFF_MKFS):
        struct.pack_into('<I', sb, off, epoch)
    if ro_compat & FEAT_METADATA_CSUM:
        struct.pack_into('<I', sb, OFF_CSUM, crc32c(bytes(sb[:OFF_CSUM])))
    f.seek(SB); f.write(sb)
PY
  then
    echo "[oci2rootfs] 提示: 超级块时间戳归一失败，已还原——产物可用但非字节级可复现" >&2
    mv "$img.prenorm" "$img"
    return 0
  fi
  if command -v e2fsck >/dev/null && ! e2fsck -fn "$img" >/dev/null 2>&1; then
    echo "[oci2rootfs] 警告: 归一后 e2fsck 不通过，已整份还原（请报 issue 附 e2fsprogs 版本）" >&2
    mv "$img.prenorm" "$img"
    return 0
  fi
  rm -f "$img.prenorm"
}
normalize_superblock_times "$OUT"

OUT_SHA="$(sha256sum "$OUT" | cut -d' ' -f1)"

# ── 溯源留档 ──────────────────────────────────────────────────────────────────

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

cat > "$PROV" <<EOF
{
  "source_mode": "$(json_escape "$MODE")",
  "source_ref": "$(json_escape "$IMG_REF")",
  "image_digest": "$(json_escape "$IMG_DIGEST")",
  "rootfs_path": "$(json_escape "build/rootfs/$NAME.ext4")",
  "rootfs_sha256": "$OUT_SHA",
  "rootfs_size": "$(json_escape "$SIZE")",
  "fs_uuid": "$FS_UUID",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "envd": "$(json_escape "$ENVD_BIN")",
  "reproducible": "partial: uuid/hash_seed/superblock-times pinned; per-inode ctime+crtime still wall-clock (mke2fs -d)",
  "note": "外围工具产物；image_digest 未被 sl-node 的 manifest 签名覆盖（正式 oci:// from 待 ADR）"
}
EOF

# ── 模板脚手架（ADR-18 语义映射，需人工过一遍）───────────────────────────────

toml_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

{
  echo "# 由 scripts/oci2rootfs.sh 从 ${IMG_REF} 生成的模板脚手架 —— **请人工审一遍再用**。"
  echo "# ADR-18 语义映射：ENV/WORKDIR/USER 构建期物化；ENTRYPOINT/CMD **不自动执行**，"
  echo "# 常驻服务须显式写成 start_cmd。EXPOSE 仅元数据，systemd 镜像不支持。"
  echo "# TOML 语义：所有顶层标量必须在 [env] 表头之前，故 [env] 放文件末尾。"
  echo ""
  echo "name = \"$(toml_escape "$NAME")\""
  echo "from = \"build/rootfs/$(toml_escape "$NAME").ext4\"   # 路径相对 sl-node 的 CWD，不是相对本文件"
  if [ -n "$CFG_WORKDIR" ]; then
    echo "workdir = \"$(toml_escape "$CFG_WORKDIR")\""
  fi
  if [ -n "$CFG_USER" ]; then
    echo "user = \"$(toml_escape "$CFG_USER")\""
  fi
  echo ""
  echo "# 构建期无 egress（build.rs 的构建沙箱不进 netns），RUN 里不能 apt/pip —— 依赖请在镜像里装好。"
  echo "run = []"
  echo ""
  # ENTRYPOINT/CMD 按 argv 数组原样列出，**不替用户拼 shell 行**：拼接会丢参数边界，
  # 且 build.rs 是 `setsid sh -c '<start_cmd>'` 拉起（暂不支持内含单引号），引用怎么写只能人来定。
  if [ -n "$CFG_ENTRYPOINT_JSON" ] && [ "$CFG_ENTRYPOINT_JSON" != "null" ] && [ "$CFG_ENTRYPOINT_JSON" != "[]" ]; then
    echo "# 镜像 ENTRYPOINT = $CFG_ENTRYPOINT_JSON"
  fi
  if [ -n "$CFG_CMD_JSON" ] && [ "$CFG_CMD_JSON" != "null" ] && [ "$CFG_CMD_JSON" != "[]" ]; then
    echo "# 镜像 CMD        = $CFG_CMD_JSON"
  fi
  echo "# ADR-18：ENTRYPOINT/CMD **不自动执行**。若确需常驻服务，参照上面 argv 自己写成一行 shell，"
  echo "# 例如 start_cmd = \"sleep 86400\"（注意 build.rs 用 sh -c '<cmd>' 拉起，命令内不得含单引号）。"
  echo ""
  echo "build_network = \"deny\""
  if [ -n "$CFG_ENV" ]; then
    echo ""
    echo "[env]"
    printf '%s\n' "$CFG_ENV" | while IFS= read -r kv; do
      [ -n "$kv" ] || continue
      case "$kv" in
        *=*) echo "$(printf '%s' "${kv%%=*}" | tr -cd 'A-Za-z0-9_') = \"$(toml_escape "${kv#*=}")\"" ;;
      esac
    done
  fi
} > "$TOML"

# ── 收尾 ──────────────────────────────────────────────────────────────────────

info "完成:"
info "  rootfs      $OUT ($(du -h "$OUT" | cut -f1), sha256=${OUT_SHA:0:12}…)"
info "  溯源        $PROV"
info "  模板脚手架  $TOML"
echo ""
echo "下一步："
echo "  1) 审一遍 $TOML（尤其 start_cmd / env / user）"
echo "  2) ./target/release/sl-node --build $TOML --json"
echo "  3) ./target/release/sandlocker up && ./target/release/sandlocker run $NAME"
echo ""
echo "注意 ①：预烘焙快照烘死 1 vCPU / 128 MiB（crates/sl-node/src/build.rs 的 /machine-config），"
echo "        真实镜像多半需要先把那处改成从 DSL 读，否则第二阶段 boot 会 OOM。"
echo "注意 ②：重转同一镜像会得到**内容相同但字节不同**的 ext4（mke2fs 给每个 inode 写 wall-clock"
echo "        ctime/crtime），sha256 因此会变、build.rs 的 build_id 随之变。转一次留着复用即可。"
