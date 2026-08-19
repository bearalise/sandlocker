#!/usr/bin/env bash
# verify-dmthin.sh — D2 前置验证：本机/runner 能否用 device-mapper thin provisioning（ADR-23）。
#
# 流程（全程 loopback，不碰真实磁盘）：
#   1. 载 dm_thin_pool 模块（或确认内建）
#   2. 造两个 loopback（data + metadata）→ dmsetup 建 thin pool
#   3. 建一个 thin 卷 → mkfs.ext4 → 挂载 → 读写校验
#   4. 建一个 thin snapshot（CoW）→ 校验与源隔离
#   5. 全部拆除，断言无残留 dm 设备 / loopback
#
# 需 root（device-mapper ioctl 需 CAP_SYS_ADMIN）。退出码 0=可用，非 0=不可用。
# 用途：回答 D2「托管 runner 能否 dm-thin」——本机 sudo 跑一次 + CI job 在 ubuntu-latest 跑一次。
set -euo pipefail

POOL="sl_verify_pool"
THIN="sl_verify_thin"
SNAP="sl_verify_snap"
WORK="$(mktemp -d /tmp/sl-dmthin.XXXXXX)"
DATA_IMG="$WORK/data.img"
META_IMG="$WORK/meta.img"
MNT="$WORK/mnt"; SMNT="$WORK/smnt"
DATA_LOOP=""; META_LOOP=""

log() { printf '[dmthin] %s\n' "$*"; }
fail() { printf '[dmthin] 失败: %s\n' "$*" >&2; exit 1; }

cleanup() {
  set +e
  mountpoint -q "$SMNT" 2>/dev/null && umount "$SMNT"
  mountpoint -q "$MNT"  2>/dev/null && umount "$MNT"
  dmsetup remove "$SNAP" 2>/dev/null
  dmsetup remove "$THIN" 2>/dev/null
  dmsetup remove "$POOL" 2>/dev/null
  [ -n "$DATA_LOOP" ] && losetup -d "$DATA_LOOP" 2>/dev/null
  [ -n "$META_LOOP" ] && losetup -d "$META_LOOP" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "需 root（device-mapper ioctl 需 CAP_SYS_ADMIN）；sudo 重试"

for t in dmsetup losetup mkfs.ext4; do command -v "$t" >/dev/null || fail "缺 $t"; done

log "1/5 载 dm_thin_pool 模块 ..."
modprobe dm_thin_pool 2>/dev/null || true
if [ ! -e /sys/module/dm_thin_pool ] && ! dmsetup targets | grep -q thin-pool; then
  fail "dm_thin_pool 不可用（模块未内建且 modprobe 失败）——托管 runner 不支持则退到特权 runner"
fi
log "    dm-thin target 可用: $(dmsetup targets | grep -E 'thin' | tr '\n' ' ')"

log "2/5 造 loopback + thin pool ..."
truncate -s 256M "$DATA_IMG"
truncate -s 16M  "$META_IMG"
DATA_LOOP="$(losetup --find --show "$DATA_IMG")"
META_LOOP="$(losetup --find --show "$META_IMG")"
# thin-pool: start len thin-pool <meta> <data> <data_block_sectors> <low_water_mark>
SECTORS=$(( 256 * 1024 * 1024 / 512 ))
dmsetup create "$POOL" --table "0 $SECTORS thin-pool $META_LOOP $DATA_LOOP 128 0" \
  || fail "建 thin-pool 失败"
log "    pool /dev/mapper/$POOL 就绪"

log "3/5 建 thin 卷 + ext4 + 读写校验 ..."
dmsetup message "/dev/mapper/$POOL" 0 "create_thin 0"
THIN_SECTORS=$(( 128 * 1024 * 1024 / 512 ))
dmsetup create "$THIN" --table "0 $THIN_SECTORS thin /dev/mapper/$POOL 0" || fail "建 thin 卷失败"
mkfs.ext4 -q "/dev/mapper/$THIN" || fail "mkfs 失败"
mkdir -p "$MNT"; mount "/dev/mapper/$THIN" "$MNT"
echo "sandlocker-dmthin-ok" > "$MNT/marker"
sync
[ "$(cat "$MNT/marker")" = "sandlocker-dmthin-ok" ] || fail "读写校验失败"
umount "$MNT"
log "    thin 卷读写 OK"

log "4/5 建 thin snapshot（CoW）+ 隔离校验 ..."
# 快照需源卷暂时 suspend 以取一致快照
dmsetup suspend "$THIN"
dmsetup message "/dev/mapper/$POOL" 0 "create_snap 1 0"
dmsetup resume "$THIN"
dmsetup create "$SNAP" --table "0 $THIN_SECTORS thin /dev/mapper/$POOL 1" || fail "建 snapshot 失败"
mkdir -p "$SMNT"; mount "/dev/mapper/$SNAP" "$SMNT"
[ "$(cat "$SMNT/marker")" = "sandlocker-dmthin-ok" ] || fail "快照未继承源数据"
echo "snap-only" > "$SMNT/snap-marker"; sync
umount "$SMNT"
# 源卷不应看到快照的新写
mount "/dev/mapper/$THIN" "$MNT"
[ ! -f "$MNT/snap-marker" ] || fail "CoW 隔离失败：源看到快照的写"
umount "$MNT"
log "    CoW 隔离 OK（快照继承源数据、源不见快照写）"

log "5/5 拆除并断言无残留 ..."
cleanup
trap - EXIT
resid_dm=$(dmsetup ls 2>/dev/null | grep -cE "$POOL|$THIN|$SNAP" || true)
[ "$resid_dm" -eq 0 ] || fail "残留 dm 设备"
log "    无残留"

echo '{"metric":"dmthin","available":true,"cow_isolation":true}'
log "✅ dm-thin 可用（ADR-23 存储栈基础设施 OK）"
