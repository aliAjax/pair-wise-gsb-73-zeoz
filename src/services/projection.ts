import type {
  ControlEvidence,
  MitigationTask,
  Risk,
  SecurityControl,
  TaskDisposition,
  Threat,
  ThreatModelState,
  ThreatStatus,
} from '@/models/domain'

/** 业务时钟：与演示数据保持一致 */
export const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

export const evidenceIsEffective = (evidence: ControlEvidence): boolean =>
  evidence.valid && !evidenceIsExpired(evidence)

export const controlHasValidEvidence = (
  control: SecurityControl,
  evidence: ControlEvidence[],
): boolean =>
  control.evidenceIds.some((id) => {
    const item = evidence.find((entry) => entry.id === id)
    return item ? evidenceIsEffective(item) : false
  })

/** 控制有效 = 状态为 effective 且至少有一条未过期的有效证据 */
export const isControlEffective = (
  control: SecurityControl,
  evidence: ControlEvidence[],
): boolean => control.status === 'effective' && controlHasValidEvidence(control, evidence)

/** 任务依赖的控制：显式指定优先，否则继承关联威胁的控制 */
export const taskSupportControlIds = (task: MitigationTask, threat: Threat): string[] =>
  task.controlIds && task.controlIds.length > 0 ? task.controlIds : threat.controlIds

const progressRank = (task: MitigationTask): number => {
  switch (task.status) {
    case 'verifying':
      return 3
    case 'in_progress':
      return 2
    case 'done':
      return 1
    default:
      return 0
  }
}

export interface TaskView {
  task: MitigationTask
  /** 参与威胁/风险结论计算的实际状态（排队、待重排为对账推导） */
  displayStatus: MitigationTask['status']
  disposition: TaskDisposition | 'draft' | 'done'
  /** 占用备份控制通道保留执行 */
  viaBackup: boolean
  queuePosition?: number
  supportedControlIds: string[]
  ineffectiveControlIds: string[]
}

export interface ThreatCapacity {
  threatId: string
  /** 备份通道名额总数 */
  offered: number
  /** 已占用名额 */
  used: number
  /** 排队任务数，即缺少的名额数 */
  shortage: number
  queuedTaskIds: string[]
  replanningTaskIds: string[]
}

export interface ReconciliationResult {
  taskViews: TaskView[]
  taskViewById: Map<string, TaskView>
  threatStatusById: Map<string, ThreatStatus>
  riskStatusById: Map<string, Risk['status']>
  capacityByThreat: Map<string, ThreatCapacity>
  /** 控制（直接关联或经任务/证据关联）影响到的威胁 */
  affectedThreatsByControl: Map<string, string[]>
  controlEffectiveById: Map<string, boolean>
}

const DRAFT: TaskView['disposition'] = 'draft'
const DONE: TaskView['disposition'] = 'done'

export const buildReconciliation = (state: ThreatModelState): ReconciliationResult => {
  const taskViews: TaskView[] = []
  const taskViewById = new Map<string, TaskView>()
  const threatStatusById = new Map<string, ThreatStatus>()
  const riskStatusById = new Map<string, Risk['status']>()
  const capacityByThreat = new Map<string, ThreatCapacity>()
  const affectedThreatsByControl = new Map<string, string[]>()
  const controlEffectiveById = new Map<string, boolean>()

  const evidenceById = new Map(state.evidence.map((item) => [item.id, item]))
  const controlById = new Map(state.controls.map((item) => [item.id, item]))

  state.controls.forEach((control) => {
    controlEffectiveById.set(
      control.id,
      isControlEffective(
        control,
        control.evidenceIds
          .map((id) => evidenceById.get(id))
          .filter((item): item is ControlEvidence => Boolean(item)),
      ),
    )
  })

  const tasksByThreat = new Map<string, MitigationTask[]>()
  state.mitigations.forEach((task) => {
    const group = tasksByThreat.get(task.threatId) ?? []
    group.push(task)
    tasksByThreat.set(task.threatId, group)
  })

  state.threats.forEach((threat) => {
    const tasks = tasksByThreat.get(threat.id) ?? []

    // 失效任务与备份容量均按威胁维度归集
    const lost: { task: MitigationTask; ineffectiveControlIds: string[] }[] = []
    let offeredCapacity = 0

    tasks.forEach((task) => {
      const supportedControlIds = taskSupportControlIds(task, threat)
      const ineffectiveControlIds = supportedControlIds.filter(
        (id) => controlEffectiveById.get(id) === false,
      )
      const supportedByEffectiveControl = supportedControlIds.some(
        (id) => controlEffectiveById.get(id) === true,
      )

      let view: TaskView
      if (task.status === 'draft') {
        view = {
          task,
          displayStatus: 'draft',
          disposition: DRAFT,
          viaBackup: false,
          supportedControlIds,
          ineffectiveControlIds,
        }
      } else if (task.status === 'done') {
        view = {
          task,
          displayStatus: 'done',
          disposition: DONE,
          viaBackup: false,
          supportedControlIds,
          ineffectiveControlIds,
        }
      } else if (supportedByEffectiveControl) {
        view = {
          task,
          displayStatus: task.status,
          disposition: 'retained',
          viaBackup: false,
          supportedControlIds,
          ineffectiveControlIds,
        }
      } else {
        lost.push({ task, ineffectiveControlIds })
        view = {
          task,
          displayStatus: task.status,
          disposition: 'replanning',
          viaBackup: false,
          supportedControlIds,
          ineffectiveControlIds,
        }
      }
      taskViews.push(view)
      taskViewById.set(task.id, view)
    })

    // 备份控制容量按失效控制去重累计
    const countedControls = new Set<string>()
    lost.forEach(({ task, ineffectiveControlIds }) => {
      const supports = taskSupportControlIds(task, threat)
      supports
        .filter((id) => ineffectiveControlIds.includes(id))
        .forEach((id) => {
          if (countedControls.has(id)) return
          countedControls.add(id)
          offeredCapacity += controlById.get(id)?.backupCapacity ?? 0
        })
    })

    // 越接近验证完成、截止越早的任务优先占用备份通道
    const orderedLost = [...lost].sort((a, b) => {
      const rankDelta = progressRank(b.task) - progressRank(a.task)
      if (rankDelta !== 0) return rankDelta
      const dueDelta = a.task.dueAt.localeCompare(b.task.dueAt)
      if (dueDelta !== 0) return dueDelta
      return a.task.id.localeCompare(b.task.id)
    })

    const queuedTaskIds: string[] = []
    const replanningTaskIds: string[] = []
    let usedCapacity = 0
    orderedLost.forEach(({ task }, index) => {
      const view = taskViewById.get(task.id)
      if (!view) return
      if (index < offeredCapacity) {
        usedCapacity += 1
        view.disposition = 'retained'
        view.viaBackup = true
        view.displayStatus = task.status
      } else if (offeredCapacity > 0) {
        view.disposition = 'queued'
        view.displayStatus = 'queued'
        view.queuePosition = index - offeredCapacity + 1
        queuedTaskIds.push(task.id)
      } else {
        view.disposition = 'replanning'
        view.displayStatus = 'replanning'
        replanningTaskIds.push(task.id)
      }
    })

    capacityByThreat.set(threat.id, {
      threatId: threat.id,
      offered: offeredCapacity,
      used: usedCapacity,
      shortage: queuedTaskIds.length,
      queuedTaskIds,
      replanningTaskIds,
    })

    const activeViews = taskViews.filter(
      (item) =>
        item.task.threatId === threat.id &&
        item.disposition !== DRAFT &&
        item.displayStatus !== 'done' &&
        item.displayStatus !== 'queued' &&
        item.displayStatus !== 'replanning' &&
        item.displayStatus !== 'todo',
    )
    const doneViews = taskViews.filter(
      (item) => item.task.threatId === threat.id && item.disposition === DONE,
    )
    const stalledViews = taskViews.filter(
      (item) =>
        item.task.threatId === threat.id &&
        (item.displayStatus === 'queued' || item.displayStatus === 'replanning'),
    )

    const acceptedRisk = threat.riskIds
      .map((id) => state.risks.find((risk) => risk.id === id))
      .find((risk): risk is Risk =>
        Boolean(risk && risk.status === 'accepted' && !isExpired(risk.acceptanceExpiresAt)),
      )

    let status: ThreatStatus
    if (acceptedRisk) {
      status = 'accepted'
    } else if (doneViews.length > 0 && stalledViews.length === 0) {
      status = 'mitigated'
    } else if (activeViews.length > 0) {
      status = 'mitigating'
    } else {
      status = 'open'
    }
    threatStatusById.set(threat.id, status)
  })

  state.risks.forEach((risk) => {
    const linkedThreats = state.threats.filter((threat) => threat.riskIds.includes(risk.id))
    if (linkedThreats.length === 0) {
      riskStatusById.set(risk.id, risk.status)
      return
    }
    if (risk.status === 'accepted' && !isExpired(risk.acceptanceExpiresAt)) {
      riskStatusById.set(risk.id, 'accepted')
      return
    }
    const statuses = linkedThreats.map((threat) => threatStatusById.get(threat.id) ?? 'open')
    if (statuses.every((status) => status === 'mitigated' || status === 'accepted')) {
      riskStatusById.set(risk.id, 'closed')
    } else if (statuses.some((status) => status === 'open')) {
      riskStatusById.set(risk.id, 'open')
    } else {
      riskStatusById.set(risk.id, 'mitigating')
    }
  })

  // 控制 -> 关联威胁：威胁直接关联、任务显式依赖、任务证据挂在该控制上
  state.controls.forEach((control) => {
    const linked = new Set<string>()
    state.threats
      .filter((threat) => threat.controlIds.includes(control.id))
      .forEach((threat) => linked.add(threat.id))
    state.mitigations.forEach((task) => {
      const threat = state.threats.find((item) => item.id === task.threatId)
      if (!threat) return
      if (task.controlIds?.includes(control.id)) linked.add(threat.id)
      const evidenceControlIds = task.evidenceIds
        .map((id) => evidenceById.get(id)?.controlId)
        .filter((id): id is string => Boolean(id))
      if (evidenceControlIds.includes(control.id)) linked.add(threat.id)
    })
    affectedThreatsByControl.set(control.id, [...linked])
  })

  return {
    taskViews,
    taskViewById,
    threatStatusById,
    riskStatusById,
    capacityByThreat,
    affectedThreatsByControl,
    controlEffectiveById,
  }
}
