# SCAPEX 安全威胁建模与缓解措施会签平台

基于 Vue 3、PrimeVue、Pinia、Vue Router、Apollo Client、GraphQL、Vite 与 TypeScript 的独立前端工程。项目不依赖真实后端，GraphQL 查询通过自定义 `ApolloLink` 映射到浏览器 `localStorage` 中的本地仓库。

## 功能

- 系统边界、信任区、组件资产、外部依赖与数据流建模
- 由当前模型状态实时渲染的数据流图
- 威胁、攻击路径、控制、风险与组件/数据流关联
- 控制状态与证据有效期联动重算：控制停用、降级或证据失效时，只重算关联威胁结论；有效的缓解任务保留，失效的进入待重排，控制恢复后自动还原
- 备份控制容量有限：超出承接能力的任务排队，并明确记录缺口（需多少、可用多少、缺多少）
- 任务乐观并发：两人同时推进同一任务时先到的保留，后到的自动转为冲突草稿，可重新提交或丢弃；保存失败时从上一份完整状态恢复
- 未覆盖组件、控制失效、证据缺失、风险接受过期、缓解冲突与容量缺口检查
- 5 x 5 风险矩阵、风险接受条件与有效期
- 开发、安全、业务三方逐项会签
- 版本快照、版本差异与受影响威胁限定重新审核
- 控制证据有效期管理、审计轨迹与 Markdown 报告导出
- 威胁清单、风险汇总与导出报告读取同一重算结果（`src/services/derivation.ts`）
- 全部修改自动持久化到 `localStorage`

## 运行

```bash
npm install
npm run dev
```

默认开发地址为 `http://localhost:18473`。

## 构建

```bash
npm run build
```

## GraphQL

`src/graphql/client.ts` 使用 Apollo Client 的自定义 `ApolloLink`。当前注册以下真实查询操作：

- `DashboardMetrics`
- `ThreatIndex`
- `ControlHealth`

工作台指标通过 Apollo Client 查询，其余业务状态由 Pinia 管理并持久化。GraphQL 解析器与 Pinia 共用同一个重算引擎（`reconcileState`），保证各视图读数一致。

## 联动规则

重算引擎位于 `src/services/derivation.ts`，幂等且只影响关联实体：

- 控制可依赖 = 状态「有效」且具备未过期的有效证据；失效、降级、被移除或证据缺失即为损坏（计划中的控制不参与判定）
- 任务失效 = 挂载证据过期/失效，或已完成（验证中/已完成）的工作所依赖的控制损坏；待处理与进行中的任务不打断
- 失效任务进入待重排；威胁下可依赖控制的备份容量（`backupCapacity`）不足时，超出任务排队并记录缺口
- 威胁结论：关联控制失效 → 重新开放；降级/证据缺失 → 已缓解的降级为处置中；全部可依赖时按任务进度推导；「已接受」为人工决策保持不变
- 风险状态跟随关联威胁结论（开放 ↔ 处置中），接受与关闭仍需人工

## 校验脚本

`scripts/` 下有三个行为校验脚本，可用 esbuild 打包后运行：

```bash
npx esbuild scripts/reconcile-check.ts --bundle --alias:@=$PWD/src --format=esm --outfile=/tmp/check.mjs && node /tmp/check.mjs
```

- `reconcile-check.ts`：控制/证据变化后的任务、威胁、风险联动与幂等性
- `concurrency-check.ts`：双标签页并发推进转草稿、保存失败从完整状态恢复
- `consistency-check.ts`：store、GraphQL 与导出报告读数一致
