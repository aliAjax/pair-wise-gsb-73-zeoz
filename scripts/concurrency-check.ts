// 模拟两个浏览器标签页：两个独立 pinia 实例共享同一个 localStorage
const storage = new Map<string, string>()
let failWrites = false
// @ts-expect-error 测试用 localStorage 模拟
globalThis.localStorage = {
  getItem: (key: string) => storage.get(key) ?? null,
  setItem: (key: string, value: string) => {
    if (failWrites) throw new Error('QuotaExceededError')
    storage.set(key, value)
  },
  removeItem: (key: string) => storage.delete(key),
  clear: () => storage.clear(),
}

const { createPinia, setActivePinia } = await import('pinia')
const { useThreatModelStore } = await import('@/stores/threatModel')

let failures = 0
const check = (name: string, cond: boolean, extra?: unknown): void => {
  if (cond) console.log(`  ✓ ${name}`)
  else {
    failures += 1
    console.log(`  ✗ ${name}`, extra ?? '')
  }
}

const makeTab = () => {
  const pinia = createPinia()
  setActivePinia(pinia)
  return useThreatModelStore()
}

console.log('并发：两人同时推进同一任务')
{
  const tabA = makeTab()
  const tabB = makeTab()
  const taskId = 'mit-01'
  check('两标签页初始版本一致', tabA.data.mitigations.find((t) => t.id === taskId)!.version === tabB.data.mitigations.find((t) => t.id === taskId)!.version)

  const resultA = tabA.advanceMitigation(taskId)
  check('A 先推进成功', resultA === 'ok', resultA)
  check('A 的任务进入 verifying', tabA.data.mitigations.find((t) => t.id === taskId)!.status === 'verifying')

  const resultB = tabB.advanceMitigation(taskId)
  check('B 后推进被判冲突', resultB === 'conflict', resultB)
  check('B 的界面已同步先到结果', tabB.data.mitigations.find((t) => t.id === taskId)!.status === 'verifying', tabB.data.mitigations.find((t) => t.id === taskId)!.status)
  check('B 的修改转为草稿', tabB.data.drafts.length === 1 && tabB.data.drafts[0].taskId === taskId, tabB.data.drafts)
  check('草稿记录基线与当前版本', tabB.data.drafts[0].baseVersion === 1 && tabB.data.drafts[0].currentVersion === 2, tabB.data.drafts[0])

  // 草稿重新提交
  tabB.applyDraft(tabB.data.drafts[0].id)
  check('重新提交后草稿清空', tabB.data.drafts.length === 0)
  check('任务版本继续递增', tabB.data.mitigations.find((t) => t.id === taskId)!.version === 3, tabB.data.mitigations.find((t) => t.id === taskId)!.version)
}

console.log('保存失败：从完整状态恢复')
{
  const tab = makeTab()
  const before = tab.data.controls.find((c) => c.id === 'ctl-01')!.status
  const auditCount = tab.data.audit.length
  failWrites = true
  tab.saveEntity('controls', { ...tab.data.controls.find((c) => c.id === 'ctl-01')!, status: 'failed' })
  failWrites = false
  check('保存失败标记已设置', tab.saveError.length > 0, tab.saveError)
  check('内存回滚到完整状态（控制状态未变）', tab.data.controls.find((c) => c.id === 'ctl-01')!.status === before, tab.data.controls.find((c) => c.id === 'ctl-01')!.status)
  check('审计轨迹未残留半截记录', tab.data.audit.length === auditCount, `${tab.data.audit.length} vs ${auditCount}`)
  // 恢复后可正常保存
  tab.saveEntity('controls', { ...tab.data.controls.find((c) => c.id === 'ctl-01')!, status: 'failed' })
  check('恢复后保存成功', tab.data.controls.find((c) => c.id === 'ctl-01')!.status === 'failed')
  check('威胁结论已联动重开', tab.data.threats.find((t) => t.id === 'thr-01')!.status === 'open', tab.data.threats.find((t) => t.id === 'thr-01')!.status)
}

console.log('编辑保存冲突同样转草稿')
{
  const tabA = makeTab()
  const tabB = makeTab()
  const plain = (value: unknown) => JSON.parse(JSON.stringify(value))
  const taskA = plain(tabA.data.mitigations.find((t) => t.id === 'mit-04')!)
  const taskB = plain(tabB.data.mitigations.find((t) => t.id === 'mit-04')!)
  taskA.title = 'A 的修改'
  taskB.title = 'B 的修改'
  check('A 编辑保存成功', tabA.saveMitigation(taskA) === 'ok')
  check('B 编辑保存冲突转草稿', tabB.saveMitigation(taskB) === 'conflict')
  check('先到内容保留', tabB.data.mitigations.find((t) => t.id === 'mit-04')!.title === 'A 的修改')
  check('草稿包含 B 的完整修改', tabB.data.drafts.some((d) => d.payload.title === 'B 的修改'))
}

console.log(failures === 0 ? '\n全部通过' : `\n${failures} 项失败`)
process.exit(failures === 0 ? 0 : 1)
