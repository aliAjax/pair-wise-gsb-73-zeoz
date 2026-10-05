// 验证单一数据源：store 指标、GraphQL 查询、导出报告读取同一重算结果
const storage = new Map<string, string>()
// @ts-expect-error mock
globalThis.localStorage = {
  getItem: (key: string) => storage.get(key) ?? null,
  setItem: (key: string, value: string) => { storage.set(key, value) },
  removeItem: (key: string) => storage.delete(key),
  clear: () => storage.clear(),
}
const { createPinia, setActivePinia } = await import('pinia')
const { useThreatModelStore } = await import('@/stores/threatModel')
const { apolloClient } = await import('@/graphql/client')
const { DASHBOARD_METRICS_QUERY, THREAT_INDEX_QUERY } = await import('@/graphql/operations')

let failures = 0
const check = (name: string, cond: boolean, extra?: unknown): void => {
  if (cond) console.log(`  ✓ ${name}`)
  else {
    failures += 1
    console.log(`  ✗ ${name}`, extra ?? '')
  }
}

setActivePinia(createPinia())
const store = useThreatModelStore()

console.log('单一数据源：store / GraphQL / 报告')
{
  const gql = await apolloClient.query({ query: DASHBOARD_METRICS_QUERY, fetchPolicy: 'no-cache' })
  const gm = gql.data.dashboardMetrics
  check('待重排数一致', gm.pendingReschedule === store.metrics.pendingReschedule, `${gm.pendingReschedule} vs ${store.metrics.pendingReschedule}`)
  check('排队数一致', gm.queuedTasks === store.metrics.queuedTasks, `${gm.queuedTasks} vs ${store.metrics.queuedTasks}`)
  check('开放严重一致', gm.critical === store.metrics.critical)
  check('待重排=1 排队=1（种子）', store.metrics.pendingReschedule === 1 && store.metrics.queuedTasks === 1, store.metrics)

  const index = await apolloClient.query({ query: THREAT_INDEX_QUERY, fetchPolicy: 'no-cache' })
  const gqlThr2 = index.data.threatIndex.find((t: { id: string }) => t.id === 'thr-02')
  const storeThr2 = store.data.threats.find((t) => t.id === 'thr-02')!
  check('威胁清单状态一致（thr-02）', gqlThr2.status === storeThr2.status, `${gqlThr2.status} vs ${storeThr2.status}`)

  const report = store.exportReport()
  check('报告含待重排任务', report.includes('[待重排] 轮换对象存储访问密钥'))
  check('报告含排队任务与缺口', report.includes('[排队中] 隔离历史归档桶访问') && report.includes('缺 1 个'))
  check('报告含风险汇总', report.includes('## 风险汇总') && report.includes('R-002 归档凭证泄露'))

  // 控制停用后三处同时变化
  const ctl1 = store.data.controls.find((c) => c.id === 'ctl-01')!
  store.saveEntity('controls', { ...ctl1, status: 'failed' })
  const gql2 = await apolloClient.query({ query: THREAT_INDEX_QUERY, fetchPolicy: 'no-cache' })
  const gqlThr1 = gql2.data.threatIndex.find((t: { id: string }) => t.id === 'thr-01')
  const storeThr1 = store.data.threats.find((t) => t.id === 'thr-01')!
  const report2 = store.exportReport()
  check('控制停用后 store 结论 open', storeThr1.status === 'open', storeThr1.status)
  check('控制停用后 GraphQL 结论一致', gqlThr1.status === 'open', gqlThr1.status)
  check('控制停用后报告结论一致', report2.includes('TM-001 [critical/开放/'))
  check('风险汇总联动（R-001 开放）', report2.includes('R-001 管理入口凭证滥用：评分 20（critical），状态 开放'))
}

console.log(failures === 0 ? '\n全部通过' : `\n${failures} 项失败`)
process.exit(failures === 0 ? 0 : 1)
