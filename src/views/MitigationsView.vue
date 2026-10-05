<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { MitigationTask } from '@/models/domain'
import { armNextSaveFailure, createId } from '@/services/repository'
import type { TaskView } from '@/services/projection'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const statusFilter = ref<string | null>(null)
const editorVisible = ref(false)
const editingVersion = ref<number | undefined>(undefined)
const failNextSave = ref(false)

const actionOptions = [
  { label: '限制访问', value: 'restrict' },
  { label: '持续监测', value: 'monitor' },
  { label: '加密保护', value: 'encrypt' },
  { label: '隔离处置', value: 'isolate' },
  { label: '有条件放行', value: 'allow_with_condition' },
]
const statusOptions = [
  { label: '待处理', value: 'todo' },
  { label: '进行中', value: 'in_progress' },
  { label: '验证中', value: 'verifying' },
  { label: '已完成', value: 'done' },
  { label: '待重排', value: 'replanning' },
  { label: '排队中', value: 'queued' },
  { label: '草稿', value: 'draft' },
]

const form = reactive<MitigationTask>({
  id: '',
  threatId: '',
  title: '',
  owner: '',
  dueAt: '',
  status: 'todo',
  action: 'restrict',
  detail: '',
  evidenceIds: [],
  conflictGroup: '',
  controlIds: [],
  version: 1,
  updatedAt: '',
})

const rows = computed<TaskView[]>(() =>
  statusFilter.value
    ? store.taskViews.filter((view) => view.displayStatus === statusFilter.value)
    : store.taskViews,
)

const capacityWarnings = computed(() =>
  [...store.reconciliation.capacityByThreat.values()].filter((capacity) => capacity.shortage > 0),
)

const conflictTaskIds = computed(() => {
  const conflicts = store.issues.filter((issue) => issue.kind === 'mitigation_conflict')
  const threatIds = new Set(conflicts.map((issue) => issue.entityId))
  return new Set(
    store.data.mitigations
      .filter((task) => threatIds.has(task.threatId) && task.conflictGroup)
      .map((task) => task.id),
  )
})

const threatLabel = (id: string): string => {
  const threat = store.data.threats.find((item) => item.id === id)
  return threat ? `${threat.code} ${threat.title}` : id
}

const openEditor = (view?: TaskView): void => {
  editingVersion.value = view ? view.task.version : undefined
  Object.assign(
    form,
    view
      ? structuredClone(view.task)
      : {
          id: '',
          threatId: store.data.threats[0]?.id ?? '',
          title: '',
          owner: '',
          dueAt: '',
          status: 'todo',
          action: 'restrict',
          detail: '',
          evidenceIds: [],
          conflictGroup: '',
          controlIds: [],
          version: 1,
          updatedAt: '',
        },
  )
  editorVisible.value = true
}

const saveTask = (): void => {
  if (!form.title.trim() || !form.threatId || !form.owner.trim() || !form.dueAt) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '威胁、任务、负责人和截止日期不能为空', life: 3000 })
    return
  }
  if (failNextSave.value) {
    armNextSaveFailure()
    failNextSave.value = false
  }
  const result = store.saveMitigationTask(
    { ...form, id: form.id || createId('mit') },
    editingVersion.value,
  )
  editorVisible.value = false
  if (result === 'conflict') {
    toast.add({
      severity: 'warn',
      summary: '任务已被他人先更新',
      detail: '先到的修改已保留，你的修改已转存为草稿。',
      life: 4000,
    })
  } else if (result === 'save_failed') {
    toast.add({
      severity: 'error',
      summary: '保存失败，已恢复完整状态',
      detail: store.lastError || '已回滚到上次完整保存的状态。',
      life: 5000,
    })
  } else {
    toast.add({ severity: 'success', summary: '缓解任务已保存', detail: form.title, life: 2500 })
  }
}

const advance = (view: TaskView): void => {
  const result = store.advanceMitigationTask(view.task.id, view.task.version)
  if (result === 'conflict') {
    toast.add({
      severity: 'warn',
      summary: '并发冲突',
      detail: '另一位同事已先推进该任务：先到者保留，你的推进已转草稿。',
      life: 4000,
    })
  } else if (result === 'save_failed') {
    toast.add({
      severity: 'error',
      summary: '保存失败，已恢复完整状态',
      detail: store.lastError || '任务状态未被修改。',
      life: 5000,
    })
  } else {
    toast.add({ severity: 'success', summary: '任务已推进', detail: view.task.title, life: 2000 })
  }
}

const simulateRemote = (view: TaskView): void => {
  store.simulateRemoteAdvance(view.task.id)
  toast.add({
    severity: 'info',
    summary: '已模拟他人先更新',
    detail: '再点击“推进”即可看到后到者转草稿。',
    life: 3000,
  })
}

const canAdvance = (view: TaskView): boolean =>
  ['todo', 'in_progress', 'verifying'].includes(view.displayStatus) && view.disposition === 'retained'
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="缓解执行"
      title="缓解任务与冲突检查"
      description="控制状态或证据有效期变化时自动对账：有效任务保留、失效任务待重排，备份容量不足时排队并标明缺口。"
    />

    <section v-if="capacityWarnings.length > 0" class="queue-banner">
      <i class="pi pi-database"></i>
      <div>
        <strong>备份控制容量不足</strong>
        <span v-for="capacity in capacityWarnings" :key="capacity.threatId">
          {{ threatLabel(capacity.threatId) }}：备份名额 {{ capacity.offered }} 个，已占用 {{ capacity.used }} 个，
          <b>缺 {{ capacity.shortage }} 个名额</b>，{{ capacity.shortage }} 个任务排队等待。
        </span>
      </div>
    </section>

    <section v-if="store.issues.some((issue) => issue.kind === 'mitigation_conflict')" class="conflict-banner">
      <i class="pi pi-exclamation-triangle"></i>
      <div>
        <strong>检测到互斥缓解措施</strong>
        <span>同一威胁同时存在限制访问与有条件放行，请统一处置方向后再进入会签。</span>
      </div>
    </section>

    <section class="panel filter-panel">
      <div class="toolbar-row">
        <div class="toolbar-field">
          <span>任务状态</span>
          <Select
            v-model="statusFilter"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            placeholder="全部状态"
            show-clear
          />
        </div>
        <label class="failure-toggle">
          <input type="checkbox" v-model="failNextSave" />
          模拟下一次保存失败（验证完整状态恢复）
        </label>
        <div class="filter-actions">
          <Button label="新增任务" icon="pi pi-plus" @click="openEditor()" />
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">缓解任务 {{ rows.length }} 条</h2>
      </div>
      <DataTable :value="rows" dataKey="task.id" size="small" stripedRows>
        <Column header="关联威胁" style="min-width: 210px">
          <template #body="{ data }">
            <strong>{{ threatLabel(data.task.threatId) }}</strong>
          </template>
        </Column>
        <Column field="task.title" header="缓解措施" style="min-width: 220px" />
        <Column header="动作" style="width: 110px">
          <template #body="{ data }">
            {{ actionOptions.find((item) => item.value === data.task.action)?.label }}
          </template>
        </Column>
        <Column field="task.owner" header="负责人" style="width: 100px" />
        <Column field="task.dueAt" header="截止日" style="width: 105px" />
        <Column header="对账状态" style="min-width: 190px">
          <template #body="{ data }">
            <div class="status-cell">
              <StatusTag :value="data.displayStatus" kind="status" />
              <span v-if="conflictTaskIds.has(data.task.id)" class="conflict-label">冲突</span>
              <span v-if="data.viaBackup" class="backup-label">备份通道</span>
              <span v-if="data.displayStatus === 'queued'" class="queue-label">
                缺 {{ data.queuePosition }} 个名额
              </span>
              <span v-if="data.displayStatus === 'replanning'" class="replan-label">待重排</span>
              <span class="muted">v{{ data.task.version }}</span>
            </div>
          </template>
        </Column>
        <Column header="操作" style="min-width: 260px">
          <template #body="{ data }">
            <Button label="编辑" size="small" text @click="openEditor(data)" />
            <Button
              v-if="canAdvance(data)"
              label="推进"
              icon="pi pi-arrow-right"
              size="small"
              text
              @click="advance(data)"
            />
            <Button
              label="模拟他人先更新"
              size="small"
              severity="secondary"
              text
              @click="simulateRemote(data)"
            />
          </template>
        </Column>
      </DataTable>
    </section>

    <Dialog
      v-model:visible="editorVisible"
      :header="form.id ? '编辑缓解任务' : '新增缓解任务'"
      modal
      :style="{ width: '760px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>关联威胁</label>
          <Select
            v-model="form.threatId"
            :options="store.data.threats"
            option-label="title"
            option-value="id"
            filter
          />
        </div>
        <div class="field field-wide">
          <label>任务名称</label>
          <InputText v-model="form.title" />
        </div>
        <div class="field">
          <label>处置动作</label>
          <Select
            v-model="form.action"
            :options="actionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>任务状态</label>
          <Select
            v-model="form.status"
            :options="statusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="form.owner" />
        </div>
        <div class="field">
          <label>截止日期</label>
          <InputText v-model="form.dueAt" type="date" />
        </div>
        <div class="field">
          <label>冲突检查组</label>
          <InputText
            v-model="form.conflictGroup"
            placeholder="同一威胁同一组的互斥动作会触发提醒"
          />
        </div>
        <div class="field">
          <label>依赖控制（留空继承威胁的控制）</label>
          <MultiSelect
            v-model="form.controlIds"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field">
          <label>关联证据</label>
          <MultiSelect
            v-model="form.evidenceIds"
            :options="store.data.evidence"
            option-label="title"
            option-value="id"
            display="chip"
          />
        </div>
        <div class="field field-wide">
          <label>执行说明</label>
          <Textarea v-model="form.detail" rows="4" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="editorVisible = false" />
        <Button label="保存任务" icon="pi pi-check" @click="saveTask" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.filter-panel {
  padding: 14px 16px;
}

.toolbar-row {
  display: flex;
  align-items: center;
  gap: 18px;
  flex-wrap: wrap;
}

.failure-toggle {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: #8a4b1f;
  font-size: 12px;
  cursor: pointer;
}

.queue-banner,
.conflict-banner {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  padding: 14px 16px;
  border-radius: 6px;
}

.queue-banner {
  margin-bottom: 14px;
  border: 1px solid #bcd3ee;
  border-left: 4px solid #2563a8;
  background: #f3f8fd;
}

.queue-banner > i {
  margin-top: 2px;
  color: #2563a8;
}

.queue-banner > div {
  display: grid;
  gap: 4px;
}

.queue-banner span {
  color: #415670;
  font-size: 12px;
}

.conflict-banner {
  margin-bottom: 14px;
  border: 1px solid #f2c78f;
  border-left: 4px solid #d97706;
  background: #fffaf0;
}

.conflict-banner > i {
  margin-top: 2px;
  color: #b45309;
}

.conflict-banner > div {
  display: grid;
  gap: 4px;
}

.conflict-banner span {
  color: #7b5d2c;
  font-size: 12px;
}

.status-cell {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}

.conflict-label,
.queue-label,
.replan-label,
.backup-label {
  font-size: 11px;
  font-weight: 700;
}

.conflict-label,
.replan-label {
  color: #b45309;
}

.queue-label {
  color: #b42318;
}

.backup-label {
  color: #1d4ed8;
}
</style>
