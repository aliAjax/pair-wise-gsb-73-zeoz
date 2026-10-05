import { createSeedState } from '@/models/seed'
import { reconcileState } from '@/services/derivation'

let failures = 0
const check = (name: string, cond: boolean, extra?: unknown): void => {
  if (cond) {
    console.log(`  ✓ ${name}`)
  } else {
    failures += 1
    console.log(`  ✗ ${name}`, extra ?? '')
  }
}

// 场景 1：种子加载（ctl-02 降级 + ev-02 过期失效）
console.log('场景 1：种子状态重算')
{
  const state = createSeedState()
  const changes = reconcileState(state)
  const mit3 = state.mitigations.find((t) => t.id === 'mit-03')!
  const mit5 = state.mitigations.find((t) => t.id === 'mit-05')!
  const mit1 = state.mitigations.find((t) => t.id === 'mit-01')!
  const mit4 = state.mitigations.find((t) => t.id === 'mit-04')!
  check('mit-03 进入待重排', mit3.status === 'pending_reschedule', mit3.status)
  check('mit-03 记住失效前状态 verifying', mit3.resumeStatus === 'verifying', mit3.resumeStatus)
  check('mit-05 进入排队', mit5.status === 'queued', mit5.status)
  check('mit-05 写清缺口（需 2 可用 1 缺 1）', !!mit5.pendingReason?.includes('缺 1 个'), mit5.pendingReason)
  check('mit-01 有效保留 in_progress', mit1.status === 'in_progress', mit1.status)
  check('mit-04 有效保留 todo', mit4.status === 'todo', mit4.status)
  check('thr-02 保持处置中', state.threats.find((t) => t.id === 'thr-02')!.status === 'mitigating')
  check('risk-02 保持 mitigating', state.risks.find((r) => r.id === 'risk-02')!.status === 'mitigating')
  check('变更仅 2 条任务（只重算关联）', changes.length === 2 && changes.every((c) => c.kind === 'task'), changes)

  // 幂等：再跑一次无变化
  const again = reconcileState(state)
  check('幂等：二次重算无变更', again.length === 0, again)
}

// 场景 2：控制停用（ctl-01 → failed），只重算关联威胁
console.log('场景 2：控制停用')
{
  const state = createSeedState()
  reconcileState(state)
  const ctl1 = state.controls.find((c) => c.id === 'ctl-01')!
  ctl1.status = 'failed'
  const changes = reconcileState(state)
  const thr1 = state.threats.find((t) => t.id === 'thr-01')!
  const thr3 = state.threats.find((t) => t.id === 'thr-03')!
  const risk1 = state.risks.find((r) => r.id === 'risk-01')!
  check('thr-01 结论重开为 open', thr1.status === 'open', thr1.status)
  check('risk-01 联动为 open', risk1.status === 'open', risk1.status)
  check('mit-01 进行中任务保留', state.mitigations.find((t) => t.id === 'mit-01')!.status === 'in_progress')
  check('mit-02 待处理任务保留', state.mitigations.find((t) => t.id === 'mit-02')!.status === 'todo')
  check('thr-03 不受影响', thr3.status === 'open' && !changes.some((c) => c.entityId === 'thr-03'))
  check('威胁变更仅 thr-01', changes.filter((c) => c.kind === 'threat').length === 1, changes)
}

// 场景 3：证据有效期变化（ev-01 过期 → ctl-01 不可依赖）
console.log('场景 3：证据过期')
{
  const state = createSeedState()
  reconcileState(state)
  const ev1 = state.evidence.find((e) => e.id === 'ev-01')!
  ev1.expiresAt = '2026-09-01'
  reconcileState(state)
  const thr1 = state.threats.find((t) => t.id === 'thr-01')!
  check('证据过期后 thr-01 结论被重算（非 mitigated）', thr1.status === 'mitigating', thr1.status)
}

// 场景 4：控制与证据恢复 → 任务还原、结论恢复
console.log('场景 4：恢复后还原')
{
  const state = createSeedState()
  reconcileState(state)
  const ev2 = state.evidence.find((e) => e.id === 'ev-02')!
  ev2.valid = true
  ev2.expiresAt = '2026-12-31'
  const ctl2 = state.controls.find((c) => c.id === 'ctl-02')!
  ctl2.status = 'effective'
  const changes = reconcileState(state)
  const mit3 = state.mitigations.find((t) => t.id === 'mit-03')!
  const mit5 = state.mitigations.find((t) => t.id === 'mit-05')!
  check('mit-03 还原为 verifying', mit3.status === 'verifying', mit3.status)
  check('mit-03 清除失效前状态标记', mit3.resumeStatus === undefined)
  check('mit-05 还原为 done', mit5.status === 'done', mit5.status)
  check('thr-02 恢复处置中', state.threats.find((t) => t.id === 'thr-02')!.status === 'mitigating')
  check('恢复产生任务变更', changes.filter((c) => c.kind === 'task').length === 2, changes)
}

// 场景 5：容量扩缩 → 排队任务进入待重排
console.log('场景 5：备份容量扩充')
{
  const state = createSeedState()
  reconcileState(state)
  const ctl3 = state.controls.find((c) => c.id === 'ctl-03')!
  ctl3.backupCapacity = 2
  reconcileState(state)
  const mit5 = state.mitigations.find((t) => t.id === 'mit-05')!
  check('容量扩到 2 后 mit-05 转为待重排', mit5.status === 'pending_reschedule', mit5.status)
}

// 场景 6：全部任务完成 → 威胁结论自动 mitigated
console.log('场景 6：任务完成驱动结论')
{
  const state = createSeedState()
  reconcileState(state)
  const ev2 = state.evidence.find((e) => e.id === 'ev-02')!
  ev2.valid = true
  ev2.expiresAt = '2026-12-31'
  state.controls.find((c) => c.id === 'ctl-02')!.status = 'effective'
  reconcileState(state)
  state.mitigations.find((t) => t.id === 'mit-03')!.status = 'done'
  const changes = reconcileState(state)
  const thr2 = state.threats.find((t) => t.id === 'thr-02')!
  check('thr-02 全部任务完成后结论为已缓解', thr2.status === 'mitigated', thr2.status)
  check('威胁结论变更被记录', changes.some((c) => c.kind === 'threat' && c.entityId === 'thr-02'))
}

console.log(failures === 0 ? '\n全部通过' : `\n${failures} 项失败`)
process.exit(failures === 0 ? 0 : 1)
