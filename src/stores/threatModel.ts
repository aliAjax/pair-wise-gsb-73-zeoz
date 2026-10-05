import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  ControlStatus,
  DecisionType,
  MitigationTask,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import {
  SaveFailedError,
  createId,
  loadState,
  resetState,
  saveState,
} from '@/services/repository'
import { buildReconciliation } from '@/services/projection'
import {
  dashboardMetrics,
  decisionsForThreat,
  getValidationIssues,
  reviewProgress,
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

export type SaveEntityResult = 'saved' | 'conflict' | 'save_failed'

const nowIso = (): string => new Date().toISOString()

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(nowIso())
  const lastError = ref('')

  // 威胁清单、风险汇总、任务处置与报告统一读取这份对账结果
  const reconciliation = computed(() => buildReconciliation(data.value))
  const metrics = computed(() => dashboardMetrics(data.value, reconciliation.value))
  const issues = computed(() => getValidationIssues(data.value, reconciliation.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )
  const taskViews = computed(() => reconciliation.value.taskViews)
  const threatViews = computed(() =>
    data.value.threats.map((threat) => ({
      threat,
      effectiveStatus: reconciliation.value.threatStatusById.get(threat.id) ?? threat.status,
      capacity: reconciliation.value.capacityByThreat.get(threat.id),
    })),
  )
  const riskViews = computed(() =>
    data.value.risks.map((risk) => ({
      risk,
      effectiveStatus: reconciliation.value.riskStatusById.get(risk.id) ?? risk.status,
    })),
  )

  const restoreFromLastGoodSave = (): void => {
    data.value = loadState()
  }

  /**
   * 应用一次状态变更并持久化。保存失败时从最近一次完整保存恢复内存状态，
   * 避免界面与存储出现不一致。
   */
  const commit = (mutate: () => void): boolean => {
    const snapshot: ThreatModelState = JSON.parse(JSON.stringify(data.value)) as ThreatModelState
    mutate()
    try {
      saveState(data.value)
      lastSavedAt.value = nowIso()
      lastError.value = ''
      return true
    } catch (error) {
      if (error instanceof SaveFailedError) {
        data.value = snapshot
        restoreFromLastGoodSave()
        lastError.value = error.message
      } else {
        data.value = snapshot
        lastError.value = error instanceof Error ? error.message : '保存失败'
      }
      return false
    }
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): AuditEvent => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: nowIso(),
      detail,
    }
    data.value.audit.unshift(event)
    return event
  }

  /**
   * 控制状态或证据变化后，只重算关联威胁：升修订号并回到审核中。
   * 返回受影响的威胁列表。
   */
  const markAffectedThreatsForControl = (
    controlId: string,
    reason: string,
  ): Threat[] => {
    const affectedIds = reconciliation.value.affectedThreatsByControl.get(controlId) ?? []
    const affected: Threat[] = []
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedIds.includes(threat.id)) return threat
      affected.push(threat)
      return { ...threat, revision: threat.revision + 1, reviewStatus: 'in_review' }
    })
    if (affected.length > 0) {
      appendAudit(
        'control',
        controlId,
        '重算关联威胁',
        `${reason}，${affected.length} 条关联威胁进入重新审核。`,
      )
    }
    return affected
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): SaveEntityResult => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    const ok = commit(() => {
      if (index >= 0) {
        target[index] = item
      } else {
        target.unshift(item)
      }
      appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    })
    return ok ? 'saved' : 'save_failed'
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    commit(() => {
      target.splice(index, 1)
      appendAudit(collection, id, '删除', '记录已从当前版本移除')
    })
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): boolean =>
    commit(() => {
      data.value.boundary = boundary
      appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    })

  const saveThreat = (threat: Threat): SaveEntityResult => saveEntity('threats', threat)

  /** 控制状态变更：只重算该控制关联的威胁，其余威胁结论不动 */
  const updateControlStatus = (controlId: string, status: ControlStatus): SaveEntityResult => {
    const control = data.value.controls.find((item) => item.id === controlId)
    if (!control) return 'save_failed'
    if (control.status === status) return 'saved'

    const statusLabel: Record<ControlStatus, string> = {
      effective: '有效',
      degraded: '降级',
      failed: '失效',
      planned: '计划中',
    }
    const previousStatus: ControlStatus = control.status
    const ok = commit(() => {
      control.status = status
      markAffectedThreatsForControl(
        controlId,
        `${control.name} 由「${statusLabel[previousStatus]}」变为「${statusLabel[status]}」`,
      )
    })
    return ok ? 'saved' : 'save_failed'
  }

  /**
   * 保存证据：证据有效期一变，只重算证据所属控制关联的威胁。
   */
  const saveEvidenceEntity = (
    evidence: ThreatModelState['evidence'][number],
  ): SaveEntityResult => {
    const index = data.value.evidence.findIndex((item) => item.id === evidence.id)
    const previous = index >= 0 ? { ...data.value.evidence[index] } : undefined
    const ok = commit(() => {
      if (index >= 0) {
        data.value.evidence[index] = evidence
      } else {
        data.value.evidence.unshift(evidence)
      }
      const validityChanged =
        !previous ||
        previous.valid !== evidence.valid ||
        previous.expiresAt !== evidence.expiresAt ||
        previous.controlId !== evidence.controlId
      if (validityChanged) {
        markAffectedThreatsForControl(
          evidence.controlId,
          `${evidence.title} 的有效性、有效期或所属控制发生变化`,
        )
        // 证据从旧控制移走时，旧控制失去该证据，同样需要重算
        if (previous && previous.controlId !== evidence.controlId) {
          markAffectedThreatsForControl(
            previous.controlId,
            `${evidence.title} 从该控制移至其他控制`,
          )
        }
      }
      appendAudit('evidence', evidence.id, index >= 0 ? '更新' : '新增', `${evidence.title} 已保存`)
    })
    return ok ? 'saved' : 'save_failed'
  }

  /**
   * 保存缓解任务（编辑表单使用），带乐观并发控制。
   * expectedVersion 存在且落后时：先到者保留，后到者转草稿。
   */
  const saveMitigationTask = (
    task: MitigationTask,
    expectedVersion?: number,
  ): SaveEntityResult => {
    const existing = data.value.mitigations.find((item) => item.id === task.id)

    if (existing && expectedVersion !== undefined && existing.version !== expectedVersion) {
      // 后到的一方：编辑内容转草稿保留，不覆盖先到者
      const draft: MitigationTask = {
        ...task,
        id: createId('mit'),
        title: `${task.title}（冲突草稿）`,
        status: 'draft',
        version: 1,
        updatedAt: nowIso(),
      }
      const ok = commit(() => {
        data.value.mitigations.unshift(draft)
        appendAudit(
          'mitigation',
          draft.id,
          '并发冲突转草稿',
          `任务 ${existing.title} 已被他人先保存（v${existing.version}），本次修改已存为草稿。`,
        )
      })
      return ok ? 'conflict' : 'save_failed'
    }

    const nextVersion = existing ? existing.version + 1 : 1
    const next: MitigationTask = {
      ...task,
      version: nextVersion,
      updatedAt: nowIso(),
    }
    return saveEntity('mitigations', next)
  }

  /**
   * 推进任务状态（看板按钮）。两人同时推进时先到的保留，
   * 后到的转草稿。返回结果供界面提示。
   */
  const advanceMitigationTask = (
    taskId: string,
    expectedVersion: number,
  ): SaveEntityResult => {
    const existing = data.value.mitigations.find((item) => item.id === taskId)
    if (!existing) return 'save_failed'
    if (existing.version !== expectedVersion) {
      const draft: MitigationTask = {
        ...existing,
        id: createId('mit'),
        title: `${existing.title}（并发推进草稿）`,
        status: 'draft',
        version: 1,
        updatedAt: nowIso(),
      }
      const ok = commit(() => {
        data.value.mitigations.unshift(draft)
        appendAudit(
          'mitigation',
          draft.id,
          '并发冲突转草稿',
          `${existing.title} 已被他人推进至新版本（v${existing.version}），后到的推进已存为草稿。`,
        )
      })
      return ok ? 'conflict' : 'save_failed'
    }

    const sequence: MitigationTask['status'][] = ['todo', 'in_progress', 'verifying', 'done']
    const nextStatus = sequence[Math.min(sequence.indexOf(existing.status) + 1, sequence.length - 1)]
    const ok = commit(() => {
      existing.status = nextStatus
      existing.version += 1
      existing.updatedAt = nowIso()
      appendAudit('mitigation', existing.id, '更新状态', `${existing.title} 推进为 ${nextStatus}`)
    })
    return ok ? 'saved' : 'save_failed'
  }

  /**
   * 模拟“另一位同事先推进了任务”：直接在存储侧推进版本，
   * 用于演示并发冲突时后到者转草稿。
   */
  const simulateRemoteAdvance = (taskId: string): SaveEntityResult => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return 'save_failed'
    const ok = commit(() => {
      task.version += 1
      task.updatedAt = nowIso()
      appendAudit(
        'mitigation',
        task.id,
        '他人先更新',
        `${task.title} 已被另一会话更新到 v${task.version}。`,
      )
    })
    return ok ? 'saved' : 'save_failed'
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: nowIso(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    commit(() => {
      data.value.currentRevision = revision
      data.value.versions.unshift(snapshot)
      data.value.threats = data.value.threats.map((threat) => {
        if (!affectedThreatIds.includes(threat.id)) {
          return { ...threat, revision }
        }
        return { ...threat, revision, reviewStatus: 'in_review' }
      })
      appendAudit(
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
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    commit(() => {
      data.value.decisions = data.value.decisions.filter(
        (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
      )
      data.value.decisions.unshift({
        id: createId('dec'),
        threatId,
        role,
        actor,
        decision,
        comment,
        createdAt: nowIso(),
        revision: threat.revision,
      })

      const currentDecisions = decisionsForThreat(data.value.decisions, threatId, threat.revision)
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
      appendAudit(
        'threat',
        threatId,
        decisionLabel[decision],
        `${actor}（${role}）提交会签意见`,
      )
    })
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    commit(() => {
      risk.status = 'accepted'
      risk.acceptanceExpiresAt = expiresAt
      risk.acceptanceCondition = condition
      appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    })
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    commit(() => {
      risk.status = 'closed'
      appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    })
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastError.value = ''
    lastSavedAt.value = nowIso()
  }

  const exportReport = (): string => {
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${nowIso()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放严重威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单（对账后结论）',
      ...threatViews.value.map(
        ({ threat, effectiveStatus }) =>
          `- ${threat.code} [${threat.severity}/${effectiveStatus}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险汇总（对账后状态）',
      ...riskViews.value.map(
        ({ risk, effectiveStatus }) =>
          `- ${risk.code} ${risk.title}，评分 ${risk.likelihood * risk.impact}，状态：${effectiveStatus}` +
          (risk.acceptanceExpiresAt ? `，接受有效至 ${risk.acceptanceExpiresAt}` : ''),
      ),
      '',
      '## 缓解任务处置',
      ...taskViews.value.map((view) => {
        const suffix: string[] = []
        if (view.viaBackup) suffix.push('主控制失效，占用备份控制通道继续执行')
        if (view.displayStatus === 'queued') suffix.push(`备份容量不足，排队第 ${view.queuePosition ?? 1} 位（缺 ${view.queuePosition ?? 1} 个名额）`)
        if (view.displayStatus === 'replanning') suffix.push('支持控制失效或证据过期，进入待重排')
        if (view.disposition === 'draft') suffix.push('并发冲突草稿，等待人工处理')
        return `- ${view.task.title}（${view.displayStatus}）${suffix.length ? `：${suffix.join('；')}` : ''}`
      }),
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
    lastError,
    reconciliation,
    metrics,
    issues,
    pendingReviews,
    taskViews,
    threatViews,
    riskViews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    updateControlStatus,
    saveEvidenceEntity,
    saveMitigationTask,
    advanceMitigationTask,
    simulateRemoteAdvance,
    createVersion,
    submitDecision,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
