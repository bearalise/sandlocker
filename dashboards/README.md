# SandLocker 只读监控看板（M3 W8，D6 / M3-Q12）

Grafana 策展看板，**零自建前端**——骑在守护自带的可观测性遥测之上（M3-Q5）。是 PRD 砍单预案第 2 项「控制台」的 scoped 偏离：M3 只回拉**只读监控看板**，完整操作面仍留 GA（见 `docs/design/M3技术计划.md` §4 D6）。

## 数据源

| 面板 | 数据源 | 来源 |
| --- | --- | --- |
| 创建/exec 延迟分位、池命中率、API 速率/错误率、当前沙箱数、创建/销毁累计 | **Prometheus** | 守护 `GET /metrics`（手写文本曝露格式，零依赖） |
| 沙箱/节点/审计明细（可选） | **Infinity**（JSON 数据源插件） | 守护 `GET /v1/sandboxes`、`GET /v1/audit`（按项目过滤） |

## 接线

1. 让 Prometheus 抓取守护的 `/metrics`（`--serve` 暴露；`/metrics` 免鉴权，仅聚合数无租户数据）：
   ```yaml
   # prometheus.yml
   scrape_configs:
     - job_name: sandlocker
       static_configs:
         - targets: ['<daemon-host>:7878']
   ```
2. Grafana 里加 Prometheus 数据源，导入 `dashboards/sandlocker.json`（导入时选该数据源）。
3. （可选）状态明细：装 Grafana **Infinity** 数据源插件，指向 `http://<daemon>/v1/sandboxes`
   （鉴权模式带 `Authorization: Bearer <只读 key>`，看板天然按项目过滤 → 多租户只读隔离）。

## 指标一览（`/metrics`）

- `sandlocker_sandboxes_created_total` / `_destroyed_total` / `_current`
- `sandlocker_pool_hits_total` / `_pool_misses_total`
- `sandlocker_exec_total`、`sandlocker_api_requests_total` / `_api_errors_total`
- `sandlocker_create_latency_ms`（histogram，分位由 `histogram_quantile()` 端算）
- `sandlocker_exec_latency_ms`（histogram）
- `sandlocker_build_info{node="addr#pid",version="..."}`（恒为 1 的 gauge，信息在标签上）——
  集群部署里用它按节点拆分；`scripts/bench/bench-cluster.sh` 也靠它问出各副本的身份
  （守护常绑 `0.0.0.0` 或藏在 LB 后面，URL 里的主机名与 node_id 对不上）

## 边界（诚实标注）

- **只读**：看板不含创建/销毁/Key/配额的写操作（那是控制台完整操作面，留 GA）。
- **OTel 全链路追踪**：创建路径的分段时序（total/copy/load/resume）已进 `create_latency_ms` 直方图 +
  结构化日志；完整 OTLP 分布式追踪 exporter（避免重异步 SDK）为后续。
