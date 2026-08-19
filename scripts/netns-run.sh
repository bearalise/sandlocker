#!/bin/sh
# netns-run.sh — 在 unshare 的 net namespace 内建 tap 并 exec firecracker（M0 W4）
#
# 由 sl-node 经 `unshare --net --map-root-user -- scripts/netns-run.sh ...` 调用：
# 每沙箱一个独立 net namespace（ADR-7），rootless（免 sudo，见 W4 探查结论）。
# 只建 tap + 配 host 侧点对点地址，**不装 NAT、不加默认路由** → guest 出口天然为零
# （ADR-13：deny-by-default 实现为 allow 条目的缺席，而非显式拒绝规则）。
# netns 随本进程消亡自动回收，tap 一并消失（Q6 无残留）。
#
# 用法: netns-run.sh <tap> <host_cidr> <fc_bin> [fc_args...]
#   fc_args 由调用方给全（config-file 路径给 `--no-api --config-file vm.json`，
#   API 路径给 `--api-sock api.sock`）——包装脚本只负责建 tap，不关心启动形态。
set -e

TAP="$1"
HOST_CIDR="$2"
FC="$3"
shift 3

ip link set lo up
ip tuntap add dev "$TAP" mode tap
ip addr add "$HOST_CIDR" dev "$TAP"
ip link set "$TAP" up

exec "$FC" "$@"
