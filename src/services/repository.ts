import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'

const STORAGE_KEY = 'scapex-threat-model-v1'

/** JSON 深拷贝：对 Vue 响应式 Proxy 安全（structuredClone 无法克隆 Proxy） */
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

export const toPlain = <T>(value: T): T => clone(value)

/** 旧版本持久化状态补齐新增字段，保证重算引擎输入完整 */
const migrate = (state: ThreatModelState): ThreatModelState => {
  state.drafts = state.drafts ?? []
  state.controls.forEach((control) => {
    control.backupCapacity ??= 0
  })
  state.mitigations.forEach((task) => {
    task.version ??= 1
  })
  return state
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  try {
    return migrate(JSON.parse(raw) as ThreatModelState)
  } catch {
    const seed = createSeedState()
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
