# SCAPEX 安全威胁建模与缓解措施会签平台

基于 Vue 3、PrimeVue、Pinia、Vue Router、Apollo Client、GraphQL、Vite 与 TypeScript 的独立前端工程。项目不依赖真实后端，GraphQL 查询通过自定义 `ApolloLink` 映射到浏览器 `localStorage` 中的本地仓库。

## 功能

- 系统边界、信任区、组件资产、外部依赖与数据流建模
- 由当前模型状态实时渲染的数据流图
- 威胁、攻击路径、控制、风险与组件/数据流关联
- 控制状态/证据有效期变化后只重算关联威胁；威胁清单、风险汇总、缓解任务与报告读取同一份对账结果
- 有效缓解任务保留，失效任务进入待重排；备份控制容量有限，超出任务排队并标明缺少名额
- 缓解任务乐观并发：两人同时推进时先到者保留、后到者转草稿；保存失败从最近一次完整保存的状态恢复
- 未覆盖组件、控制失效、证据缺失、备份容量不足、风险接受过期与缓解冲突检查
- 5 x 5 风险矩阵、风险接受条件与有效期
- 开发、安全、业务三方逐项会签
- 版本快照、版本差异与受影响威胁限定重新审核
- 控制证据有效期管理、审计轨迹与 Markdown 报告导出
- 全部修改自动持久化到 `localStorage`

## 对账规则（`src/services/projection.ts`）

- **控制有效** = 控制状态为 `effective` 且至少有一条未过期、状态有效的证据。
- 任务依赖的控制取任务显式 `controlIds`，留空则继承关联威胁的全部控制；任一依赖控制有效则任务继续保留，否则视为失去支持。
- 失去支持的任务优先占用关联控制的 `backupCapacity` 备份名额（按推进程度、截止时间排序）；占不到名额时，有备份通道则**排队**（队位即缺少的名额数），无备份通道则**待重排**。
- 威胁/风险有效状态、校验问题与报告均由 `buildReconciliation(state)` 统一推导，不存在多处各算各的情况。

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

工作台指标通过 Apollo Client 查询，其余业务状态由 Pinia 管理并持久化。
