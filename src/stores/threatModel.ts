import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  MitigationTask,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import type { ReconcileChange } from '@/services/derivation'
import { nextMitigationStatus, reconcileState } from '@/services/derivation'
import { createId, loadState, resetState, saveState, toPlain } from '@/services/repository'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
  riskLevel,
  riskScore,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

const statusLabels: Record<string, string> = {
  open: '开放',
  mitigating: '处置中',
  mitigated: '已缓解',
  accepted: '已接受',
  closed: '已关闭',
  todo: '待处理',
  in_progress: '进行中',
  verifying: '验证中',
  done: '已完成',
  pending_reschedule: '待重排',
  queued: '排队中',
}

const labelOf = (value: string): string => statusLabels[value] ?? value

const reconcileEntityType: Record<ReconcileChange['kind'], string> = {
  threat: 'threat',
  task: 'mitigation',
  risk: 'risk',
}

const buildAudit = (
  entityType: string,
  entityId: string,
  action: string,
  detail: string,
): AuditEvent => ({
  id: createId('aud'),
  entityType,
  entityId,
  action,
  actor: '当前用户',
  createdAt: new Date().toISOString(),
  detail,
})

const pushAudit = (
  state: ThreatModelState,
  entityType: string,
  entityId: string,
  action: string,
  detail: string,
): void => {
  state.audit.unshift(buildAudit(entityType, entityId, action, detail))
}

const pushReconcileAudits = (state: ThreatModelState, changes: ReconcileChange[]): void => {
  changes.forEach((change) => {
    pushAudit(
      state,
      reconcileEntityType[change.kind],
      change.entityId,
      '自动重算',
      `${change.label}：${labelOf(change.from)} → ${labelOf(change.to)}${change.reason ? `（${change.reason}）` : ''}`,
    )
  })
}

const summarize = (changes: ReconcileChange[]): string => {
  const parts: string[] = []
  const threats = changes.filter((change) => change.kind === 'threat').length
  const tasks = changes.filter((change) => change.kind === 'task').length
  const risks = changes.filter((change) => change.kind === 'risk').length
  if (threats > 0) parts.push(`${threats} 条威胁结论`)
  if (tasks > 0) parts.push(`${tasks} 条缓解任务`)
  if (risks > 0) parts.push(`${risks} 条风险状态`)
  return `控制或证据状态变化，已重算：${parts.join('、') || '无变化'}`
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const bootstrap = (): ThreatModelState => {
    const state = loadState()
    const changes = reconcileState(state)
    if (changes.length > 0) {
      state.audit.unshift(buildAudit('system', 'reconcile', '自动重算', summarize(changes)))
      try {
        saveState(state)
      } catch {
        // 持久化不可用时仍返回完整的内存状态
      }
    }
    return state
  }

  const data = ref<ThreatModelState>(bootstrap())
  const lastSavedAt = ref(new Date().toISOString())
  const saveError = ref('')

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  /**
   * 统一提交：在最新完整状态上应用变更 → 重算关联结论 → 持久化。
   * 持久化失败时内存保持上一份完整状态，界面不出现半截数据。
   */
  const commit = (mutate: (state: ThreatModelState) => void): boolean => {
    const working = loadState()
    mutate(working)
    pushReconcileAudits(working, reconcileState(working))
    try {
      saveState(working)
    } catch {
      saveError.value = '保存失败，已从上一完整状态恢复'
      return false
    }
    data.value = working
    lastSavedAt.value = new Date().toISOString()
    saveError.value = ''
    return true
  }

  const saveEntity = <T extends IdentifiedEntity>(collection: CollectionKey, item: T): void => {
    const plain = toPlain(item)
    commit((state) => {
      const target = state[collection] as unknown as IdentifiedEntity[]
      const index = target.findIndex((entry) => entry.id === plain.id)
      if (index >= 0) {
        target[index] = plain
      } else {
        target.unshift(plain)
      }
      const label = 'name' in plain && typeof plain.name === 'string' ? plain.name : plain.id
      pushAudit(state, collection, plain.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    })
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    commit((state) => {
      const target = state[collection] as unknown as IdentifiedEntity[]
      const index = target.findIndex((entry) => entry.id === id)
      if (index < 0) return
      target.splice(index, 1)
      pushAudit(state, collection, id, '删除', '记录已从当前版本移除')
    })
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    commit((state) => {
      state.boundary = boundary
      pushAudit(state, 'boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    })
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    let snapshot: VersionSnapshot = {
      id: '',
      revision: data.value.currentRevision,
      label,
      createdAt: '',
      author: '当前用户',
      notes,
      threatIds: [],
      componentIds: [],
      flowIds: [],
      controlIds: [],
      riskIds: [],
      affectedThreatIds,
    }
    commit((state) => {
      const revision = state.currentRevision + 1
      snapshot = {
        id: createId('ver'),
        revision,
        label,
        createdAt: new Date().toISOString(),
        author: '当前用户',
        notes,
        threatIds: state.threats.map((threat) => threat.id),
        componentIds: state.components.map((component) => component.id),
        flowIds: state.flows.map((flow) => flow.id),
        controlIds: state.controls.map((control) => control.id),
        riskIds: state.risks.map((risk) => risk.id),
        affectedThreatIds,
      }
      state.currentRevision = revision
      state.versions.unshift(snapshot)
      state.threats = state.threats.map((threat) => {
        if (!affectedThreatIds.includes(threat.id)) {
          return { ...threat, revision }
        }
        return { ...threat, revision, reviewStatus: 'in_review' }
      })
      pushAudit(
        state,
        'version',
        snapshot.id,
        '创建版本',
        `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
      )
    })
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    commit((state) => {
      const threat = state.threats.find((item) => item.id === threatId)
      if (!threat) return
      state.decisions = state.decisions.filter(
        (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
      )
      state.decisions.unshift({
        id: createId('dec'),
        threatId,
        role,
        actor,
        decision,
        comment,
        createdAt: new Date().toISOString(),
        revision: threat.revision,
      })

      const currentDecisions = decisionsForThreat(state.decisions, threatId, threat.revision)
      const requiredRoles: ActorRole[] = ['development', 'security', 'business']
      const allSubmitted = requiredRoles.every((requiredRole) =>
        currentDecisions.some((item) => item.role === requiredRole),
      )
      if (currentDecisions.some((item) => item.decision === 'rejected')) {
        threat.reviewStatus = 'rejected'
      } else if (
        allSubmitted &&
        currentDecisions.every((item) => item.decision === 'approved')
      ) {
        threat.reviewStatus = 'approved'
      } else {
        threat.reviewStatus = 'in_review'
      }

      const decisionLabel: Record<DecisionType, string> = {
        accept: '接受',
        degrade: '降级',
        evidence_required: '要求补证',
        approved: '会签通过',
        rejected: '驳回',
      }
      pushAudit(state, 'threat', threatId, decisionLabel[decision], `${actor}（${role}）提交会签意见`)
    })
  }

  /**
   * 推进任务：两人同时推进同一任务时，先到的保留，
   * 后到的（基于旧版本）自动转为冲突草稿，不覆盖先到结果。
   */
  const advanceMitigation = (taskId: string): 'ok' | 'conflict' | 'ignored' => {
    const memoryTask = data.value.mitigations.find((task) => task.id === taskId)
    if (!memoryTask) return 'ignored'
    if (!['todo', 'in_progress', 'verifying'].includes(memoryTask.status)) return 'ignored'
    const attempted: MitigationTask = toPlain({
      ...memoryTask,
      status: nextMitigationStatus(memoryTask.status),
    })
    let outcome: 'ok' | 'conflict' = 'ok'
    const persisted = commit((state) => {
      const index = state.mitigations.findIndex((task) => task.id === taskId)
      if (index < 0) return
      const latest = state.mitigations[index]
      if (latest.version !== memoryTask.version) {
        outcome = 'conflict'
        state.drafts.unshift({
          id: createId('draft'),
          taskId,
          payload: attempted,
          attemptedBy: '当前用户',
          baseVersion: memoryTask.version,
          currentVersion: latest.version,
          createdAt: new Date().toISOString(),
          note: `任务已被先推进至 v${latest.version}（${labelOf(latest.status)}），本次修改转为草稿待确认`,
        })
        pushAudit(
          state,
          'mitigation',
          taskId,
          '并发冲突转草稿',
          `${memoryTask.title} 的推进基于 v${memoryTask.version}，与已保存的 v${latest.version} 冲突`,
        )
        return
      }
      state.mitigations[index] = { ...attempted, version: latest.version + 1 }
      pushAudit(state, 'mitigation', taskId, '推进任务', `${attempted.title} 推进为${labelOf(attempted.status)}`)
    })
    return persisted ? outcome : 'ignored'
  }

  /** 编辑保存任务：同样做版本检查，冲突时整份修改转草稿 */
  const saveMitigation = (task: MitigationTask): 'ok' | 'conflict' | 'ignored' => {
    const payload = toPlain(task)
    const memoryTask = data.value.mitigations.find((item) => item.id === payload.id)
    let outcome: 'ok' | 'conflict' = 'ok'
    const persisted = commit((state) => {
      const index = state.mitigations.findIndex((item) => item.id === payload.id)
      if (index < 0) {
        state.mitigations.unshift({ ...payload, version: 1 })
        pushAudit(state, 'mitigation', payload.id, '新增', `${payload.title} 已保存`)
        return
      }
      const latest = state.mitigations[index]
      if (memoryTask && latest.version !== memoryTask.version) {
        outcome = 'conflict'
        state.drafts.unshift({
          id: createId('draft'),
          taskId: payload.id,
          payload,
          attemptedBy: '当前用户',
          baseVersion: memoryTask.version,
          currentVersion: latest.version,
          createdAt: new Date().toISOString(),
          note: `编辑基于 v${memoryTask.version}，任务已更新至 v${latest.version}，修改转为草稿待确认`,
        })
        pushAudit(state, 'mitigation', payload.id, '并发冲突转草稿', `${payload.title} 的编辑与已保存版本冲突`)
        return
      }
      state.mitigations[index] = { ...payload, version: latest.version + 1 }
      pushAudit(state, 'mitigation', payload.id, '更新', `${payload.title} 已保存`)
    })
    return persisted ? outcome : 'ignored'
  }

  const applyDraft = (draftId: string): void => {
    commit((state) => {
      const draftIndex = state.drafts.findIndex((draft) => draft.id === draftId)
      if (draftIndex < 0) return
      const draft = state.drafts[draftIndex]
      const taskIndex = state.mitigations.findIndex((task) => task.id === draft.taskId)
      if (taskIndex >= 0) {
        state.mitigations[taskIndex] = {
          ...draft.payload,
          version: state.mitigations[taskIndex].version + 1,
        }
      } else {
        state.mitigations.unshift({ ...draft.payload, version: 1 })
      }
      state.drafts.splice(draftIndex, 1)
      pushAudit(state, 'mitigation', draft.taskId, '草稿重新提交', `${draft.payload.title} 已按草稿内容保存`)
    })
  }

  const discardDraft = (draftId: string): void => {
    commit((state) => {
      const draftIndex = state.drafts.findIndex((draft) => draft.id === draftId)
      if (draftIndex < 0) return
      const [draft] = state.drafts.splice(draftIndex, 1)
      pushAudit(state, 'mitigation', draft.taskId, '草稿已丢弃', draft.payload.title)
    })
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    commit((state) => {
      const risk = state.risks.find((item) => item.id === riskId)
      if (!risk) return
      risk.status = 'accepted'
      risk.acceptanceExpiresAt = expiresAt
      risk.acceptanceCondition = condition
      pushAudit(state, 'risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    })
  }

  const closeRisk = (riskId: string): void => {
    commit((state) => {
      const risk = state.risks.find((item) => item.id === riskId)
      if (!risk) return
      risk.status = 'closed'
      pushAudit(state, 'risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    })
  }

  const resetDemo = (): void => {
    const fresh = resetState()
    pushReconcileAudits(fresh, reconcileState(fresh))
    try {
      saveState(fresh)
    } catch {
      saveError.value = '保存失败，已从上一完整状态恢复'
      return
    }
    data.value = fresh
    lastSavedAt.value = new Date().toISOString()
    saveError.value = ''
  }

  const exportReport = (): string => {
    const heldTasks = data.value.mitigations.filter(
      (task) => task.status === 'pending_reschedule' || task.status === 'queued',
    )
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      `- 缓解任务待重排：${metrics.value.pendingReschedule}，排队中：${metrics.value.queuedTasks}`,
      '',
      '## 风险汇总',
      ...data.value.risks
        .filter((risk) => risk.status !== 'closed')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}：评分 ${riskScore(risk)}（${riskLevel(riskScore(risk))}），状态 ${labelOf(risk.status)}`,
        ),
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${labelOf(threat.status)}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 缓解任务重排与排队',
      ...(heldTasks.length > 0
        ? heldTasks.map((task) => {
            const threat = data.value.threats.find((item) => item.id === task.threatId)
            return `- [${labelOf(task.status)}] ${task.title}（${threat?.code ?? task.threatId}）：${task.pendingReason ?? '等待处理'}`
          })
        : ['- 当前没有待重排或排队的缓解任务']),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    saveError,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    advanceMitigation,
    saveMitigation,
    applyDraft,
    discardDraft,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
