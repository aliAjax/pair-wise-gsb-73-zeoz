import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'
const STORAGE_VERSION_KEY = 'scapex-threat-model-schema'
const SCHEMA_VERSION = 2
const FAILURE_SWITCH_KEY = 'scapex-save-fails-next'

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

/** 补齐历史存档中缺失的字段，保证旧版本数据也能通过对账 */
const migrate = (state: ThreatModelState): ThreatModelState => {
  state.controls.forEach((control) => {
    if (typeof control.backupCapacity !== 'number') control.backupCapacity = 0
  })
  state.mitigations.forEach((task) => {
    if (typeof task.version !== 'number') task.version = 1
    if (typeof task.updatedAt !== 'string') task.updatedAt = new Date().toISOString()
    if (!Array.isArray(task.controlIds)) task.controlIds = []
  })
  return state
}

export class SaveConflictError extends Error {
  constructor(public entityId: string, public currentVersion: number) {
    super(`记录 ${entityId} 已被他人更新（当前版本 ${currentVersion}）`)
    this.name = 'SaveConflictError'
  }
}

export class SaveFailedError extends Error {
  constructor() {
    super('保存失败：本地持久化通道不可用，已从上次完整保存的状态恢复')
    this.name = 'SaveFailedError'
  }
}

/** 下一次保存注入失败，用于演示“保存失败后从完整状态恢复” */
export const armNextSaveFailure = (): void => {
  localStorage.setItem(FAILURE_SWITCH_KEY, '1')
}

export const saveFailureArmed = (): boolean => {
  const armed = localStorage.getItem(FAILURE_SWITCH_KEY) === '1'
  if (armed) localStorage.removeItem(FAILURE_SWITCH_KEY)
  return armed
}

export const clearSaveFailure = (): void => {
  localStorage.removeItem(FAILURE_SWITCH_KEY)
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  const schemaVersion = Number(localStorage.getItem(STORAGE_VERSION_KEY) ?? '1')
  if (!raw || schemaVersion < SCHEMA_VERSION) {
    const seed = migrate(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    localStorage.setItem(STORAGE_VERSION_KEY, String(SCHEMA_VERSION))
    return seed
  }

  try {
    return migrate(JSON.parse(raw) as ThreatModelState)
  } catch {
    const seed = migrate(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    localStorage.setItem(STORAGE_VERSION_KEY, String(SCHEMA_VERSION))
    return seed
  }
}

/**
 * 持久化完整状态。写入失败时抛出 SaveFailedError，调用方必须从最近一次
 * 完整保存的状态恢复内存，避免出现“界面改了、存储没改”的半截状态。
 */
export const saveState = (state: ThreatModelState): void => {
  if (saveFailureArmed()) {
    throw new SaveFailedError()
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
  localStorage.setItem(STORAGE_VERSION_KEY, String(SCHEMA_VERSION))
}

export const resetState = (): ThreatModelState => {
  const seed = migrate(createSeedState())
  clearSaveFailure()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
