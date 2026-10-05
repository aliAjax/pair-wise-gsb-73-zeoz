import type {
  ControlEvidence,
  MitigationStatus,
  MitigationTask,
  SecurityControl,
  Threat,
  ThreatModelState,
  ThreatStatus,
} from '@/models/domain'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

type EvidenceMap = Map<string, ControlEvidence>

export const buildEvidenceMap = (state: ThreatModelState): EvidenceMap =>
  new Map(state.evidence.map((item) => [item.id, item]))

export const controlHasValidEvidence = (
  control: SecurityControl,
  evidenceById: EvidenceMap,
): boolean =>
  control.evidenceIds.some((id) => {
    const evidence = evidenceById.get(id)
    return evidence !== undefined && evidence.valid && !evidenceIsExpired(evidence)
  })

/** 可依赖 = 状态为有效且具备未过期的有效证据 */
export const controlDependable = (
  control: SecurityControl | undefined,
  evidenceById: EvidenceMap,
): boolean => {
  if (!control) return false
  return control.status === 'effective' && controlHasValidEvidence(control, evidenceById)
}

/** 已损坏 = 非计划中且不可依赖（失效、降级、被移除或证据缺失）；计划中的控制从未被依赖，不算损坏 */
export const controlBroken = (
  control: SecurityControl | undefined,
  evidenceById: EvidenceMap,
): boolean => {
  if (!control) return true
  if (control.status === 'planned') return false
  return !controlDependable(control, evidenceById)
}

export const controlBrokenReason = (
  control: SecurityControl | undefined,
  evidenceById: EvidenceMap,
): string => {
  if (!control) return '已移除'
  if (control.status === 'failed') return '已失效'
  if (control.status === 'degraded') return '已降级'
  if (!controlHasValidEvidence(control, evidenceById)) return '缺少有效证据'
  return '不可用'
}

export const nextMitigationStatus = (status: MitigationStatus): MitigationStatus => {
  const sequence: MitigationStatus[] = ['todo', 'in_progress', 'verifying', 'done']
  const index = sequence.indexOf(status)
  if (index < 0) return 'todo'
  return sequence[Math.min(index + 1, sequence.length - 1)]
}

export const isOnHold = (status: MitigationStatus): boolean =>
  status === 'pending_reschedule' || status === 'queued'

/**
 * 任务失效判定：
 * 1. 任务挂载的证据过期或被标记失效 —— 任何状态下都失效；
 * 2. 已完成/待验证的工作（含待重排前处于 verifying/done 的任务），
 *    其完成结论是在旧控制环境下得出的，关联控制损坏即失效。
 * 待处理/进行中的工作尚未形成结论，控制变化不打断执行，保持有效。
 */
export const taskInvalidReason = (
  task: MitigationTask,
  threat: Threat | undefined,
  controlById: Map<string, SecurityControl>,
  evidenceById: EvidenceMap,
): string | null => {
  for (const evidenceId of task.evidenceIds) {
    const evidence = evidenceById.get(evidenceId)
    if (!evidence) continue
    if (evidenceIsExpired(evidence)) return `证据「${evidence.title}」已过期`
    if (!evidence.valid) return `证据「${evidence.title}」已失效`
  }
  const workStatus = task.resumeStatus ?? task.status
  if ((workStatus === 'verifying' || workStatus === 'done') && threat) {
    for (const controlId of threat.controlIds) {
      const control = controlById.get(controlId)
      if (controlBroken(control, evidenceById)) {
        return `控制「${control?.name ?? controlId}」${controlBrokenReason(control, evidenceById)}`
      }
    }
  }
  return null
}

export interface ReconcileChange {
  kind: 'threat' | 'task' | 'risk'
  entityId: string
  label: string
  from: string
  to: string
  reason: string
}

/**
 * 重算引擎：控制状态或证据有效期变化后，只重算关联威胁。
 * 纯函数式推导、幂等——未受影响的实体不会产生任何变更，
 * 因此威胁清单、风险汇总与报告读取同一份重算结果。
 *
 * 顺序：先任务（失效 → 待重排/按备份容量排队，恢复 → 还原），
 * 再威胁结论，最后联动风险状态。
 */
export const reconcileState = (state: ThreatModelState): ReconcileChange[] => {
  const changes: ReconcileChange[] = []
  const controlById = new Map(state.controls.map((control) => [control.id, control]))
  const evidenceById = buildEvidenceMap(state)

  const applyTaskStatus = (task: MitigationTask, next: MitigationStatus, reason?: string): void => {
    if (task.status === next) {
      if (reason) task.pendingReason = reason
      else delete task.pendingReason
      return
    }
    const from = task.status
    const enteringHold = isOnHold(next)
    const leavingHold = isOnHold(from)
    if (enteringHold && !leavingHold) task.resumeStatus = from
    if (!enteringHold) delete task.resumeStatus
    task.status = next
    if (reason) task.pendingReason = reason
    else delete task.pendingReason
    changes.push({
      kind: 'task',
      entityId: task.id,
      label: task.title,
      from,
      to: next,
      reason: reason ?? '',
    })
  }

  // 1. 缓解任务：失效的进入待重排，超出备份容量的排队；恢复有效的还原
  for (const threat of state.threats) {
    const tasks = state.mitigations.filter((task) => task.threatId === threat.id)
    const invalid: { task: MitigationTask; reason: string }[] = []
    for (const task of tasks) {
      const reason = taskInvalidReason(task, threat, controlById, evidenceById)
      if (reason) {
        invalid.push({ task, reason })
      } else if (isOnHold(task.status)) {
        applyTaskStatus(task, task.resumeStatus ?? 'todo')
      }
    }
    if (invalid.length === 0) continue

    // 备份控制容量：该威胁下仍可依赖的控制提供的承接槽位
    const capacity = threat.controlIds
      .map((id) => controlById.get(id))
      .filter((control): control is SecurityControl => Boolean(control))
      .filter((control) => controlDependable(control, evidenceById))
      .reduce((sum, control) => sum + control.backupCapacity, 0)
    const ordered = [...invalid].sort(
      (a, b) => a.task.dueAt.localeCompare(b.task.dueAt) || a.task.id.localeCompare(b.task.id),
    )
    const deficit = Math.max(0, ordered.length - capacity)
    ordered.forEach(({ task, reason }, index) => {
      if (index < capacity) {
        applyTaskStatus(task, 'pending_reschedule', `${reason}，等待重新排期`)
      } else {
        applyTaskStatus(
          task,
          'queued',
          `${reason}；备份控制容量不足：需 ${ordered.length} 个槽位、可用 ${capacity} 个、缺 ${deficit} 个，任务排队`,
        )
      }
    })
  }

  // 2. 威胁结论：已接受为业务决策保持不变，其余按控制与任务状态重算
  for (const threat of state.threats) {
    if (threat.status === 'accepted') continue
    const brokenControls = threat.controlIds
      .map((id) => controlById.get(id))
      .filter((control) => controlBroken(control, evidenceById))
    let next: ThreatStatus
    if (brokenControls.some((control) => !control || control.status === 'failed')) {
      next = 'open'
    } else if (brokenControls.length > 0) {
      next = threat.status === 'mitigated' ? 'mitigating' : threat.status
    } else {
      const actionable = state.mitigations.filter(
        (task) => task.threatId === threat.id && !isOnHold(task.status),
      )
      if (actionable.length > 0 && actionable.every((task) => task.status === 'done')) {
        next = 'mitigated'
      } else if (actionable.some((task) => task.status === 'in_progress' || task.status === 'verifying')) {
        next = 'mitigating'
      } else {
        next = 'open'
      }
    }
    if (next !== threat.status) {
      const reason =
        brokenControls.length > 0
          ? `控制「${brokenControls[0]?.name ?? '未知控制'}」${controlBrokenReason(brokenControls[0], evidenceById)}`
          : '关联控制与任务状态变化'
      changes.push({
        kind: 'threat',
        entityId: threat.id,
        label: `${threat.code} ${threat.title}`,
        from: threat.status,
        to: next,
        reason,
      })
      threat.status = next
    }
  }

  // 3. 风险联动：跟随关联威胁结论（接受/关闭为人工决策，不自动改）
  for (const risk of state.risks) {
    if (risk.status === 'accepted' || risk.status === 'closed') continue
    const linked = state.threats.filter(
      (threat) => threat.riskIds.includes(risk.id) && threat.status !== 'accepted',
    )
    if (linked.length === 0) continue
    let next: 'open' | 'mitigating'
    if (linked.some((threat) => threat.status === 'open')) next = 'open'
    else if (linked.some((threat) => threat.status === 'mitigating')) next = 'mitigating'
    else continue // 关联威胁全部已缓解：保持现状，由人工关闭
    if (next !== risk.status) {
      changes.push({
        kind: 'risk',
        entityId: risk.id,
        label: `${risk.code} ${risk.title}`,
        from: risk.status,
        to: next,
        reason: '关联威胁结论联动',
      })
      risk.status = next
    }
  }

  return changes
}

/** 供视图展示：威胁关联的已损坏控制 */
export const threatBrokenControls = (state: ThreatModelState, threat: Threat): SecurityControl[] => {
  const evidenceById = buildEvidenceMap(state)
  return threat.controlIds
    .map((id) => state.controls.find((control) => control.id === id))
    .filter((control): control is SecurityControl => Boolean(control))
    .filter((control) => controlBroken(control, evidenceById))
}
