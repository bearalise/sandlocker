//! sl-node 二进制入口——薄壳。
//!
//! 实现全部在 `lib.rs`（crate `sl_node`）：M3 W5 余项把数据面网关拆成**独立进程**
//! （`src/bin/sandlocker-gw.rs`），网关与节点须共用 `dataplane`/`gateway` 等模块，
//! 故本 crate 提供 lib 目标；本文件仅转调 `cli_main()`，行为与拆分前逐字节一致。

fn main() {
    sl_node::cli_main()
}
