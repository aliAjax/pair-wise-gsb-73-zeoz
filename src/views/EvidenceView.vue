<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import Tab from 'primevue/tab'
import TabList from 'primevue/tablist'
import TabPanel from 'primevue/tabpanel'
import TabPanels from 'primevue/tabpanels'
import Tabs from 'primevue/tabs'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { ControlEvidence, ControlStatus, SecurityControl } from '@/models/domain'
import { armNextSaveFailure, createId } from '@/services/repository'
import {
  controlHasValidEvidence,
  evidenceIsExpired,
  isControlEffective,
} from '@/services/projection'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const activeTab = ref('controls')
const editorVisible = ref(false)
const controlEditorVisible = ref(false)
const validityFilter = ref<string | null>(null)
const controlFilter = ref<string | null>(null)
const failNextSave = ref(false)

const kindOptions = [
  { label: '测试记录', value: 'test' },
  { label: '配置快照', value: 'config' },
  { label: '工单记录', value: 'ticket' },
  { label: '扫描报告', value: 'scan' },
  { label: '签署证明', value: 'attestation' },
]
const validityOptions = [
  { label: '有效', value: 'valid' },
  { label: '已过期', value: 'expired' },
  { label: '已失效', value: 'invalid' },
]
const controlStatusOptions = [
  { label: '有效', value: 'effective' },
  { label: '降级', value: 'degraded' },
  { label: '失效', value: 'failed' },
  { label: '计划中', value: 'planned' },
]

const form = reactive<ControlEvidence>({
  id: '',
  controlId: '',
  title: '',
  kind: 'test',
  reference: '',
  collectedAt: '',
  expiresAt: '',
  owner: '',
  valid: true,
})

const controlForm = reactive<SecurityControl>({
  id: '',
  name: '',
  type: 'preventive',
  status: 'effective',
  owner: '',
  componentId: '',
  description: '',
  evidenceIds: [],
  backupCapacity: 0,
})

const filteredEvidence = computed(() =>
  store.data.evidence.filter((evidence) => {
    const validity = evidenceIsExpired(evidence) ? 'expired' : evidence.valid ? 'valid' : 'invalid'
    return (
      (!controlFilter.value || evidence.controlId === controlFilter.value) &&
      (!validityFilter.value || validity === validityFilter.value)
    )
  }),
)

const effectiveControls = computed(
  () =>
    store.data.controls.filter((control) =>
      isControlEffective(control, store.data.evidence),
    ).length,
)

const controlName = (id: string): string =>
  store.data.controls.find((control) => control.id === id)?.name ?? id

const validity = (evidence: ControlEvidence): string =>
  evidenceIsExpired(evidence) ? 'expired' : evidence.valid ? 'valid' : 'invalid'

const openEditor = (evidence?: ControlEvidence): void => {
  Object.assign(
    form,
    evidence
      ? structuredClone(evidence)
      : {
          id: '',
          controlId: store.data.controls[0]?.id ?? '',
          title: '',
          kind: 'test',
          reference: '',
          collectedAt: new Date().toISOString().slice(0, 10),
          expiresAt: '',
          owner: '',
          valid: true,
        },
  )
  editorVisible.value = true
}

const saveEvidence = (): void => {
  if (!form.title.trim() || !form.controlId || !form.reference.trim() || !form.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '控制、标题、引用编号和责任人不能为空', life: 3000 })
    return
  }
  if (!form.collectedAt || !form.expiresAt) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '采集日与到期日不能为空', life: 3000 })
    return
  }
  if (new Date(form.expiresAt) <= new Date(form.collectedAt)) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '到期日必须晚于采集日', life: 3000 })
    return
  }
  if (failNextSave.value) {
    armNextSaveFailure()
    failNextSave.value = false
  }
  const result = store.saveEvidenceEntity({ ...form, id: form.id || createId('ev') })
  editorVisible.value = false
  if (result === 'save_failed') {
    toast.add({
      severity: 'error',
      summary: '保存失败，已恢复完整状态',
      detail: store.lastError || '证据与关联威胁结论均未被修改。',
      life: 5000,
    })
    return
  }
  toast.add({
    severity: 'success',
    summary: '证据已保存',
    detail: '证据有效期变化，已只重算所属控制的关联威胁。',
    life: 3000,
  })
}

const openControlEditor = (control?: SecurityControl): void => {
  Object.assign(
    controlForm,
    control
      ? structuredClone(control)
      : {
          id: '',
          name: '',
          type: 'preventive',
          status: 'planned',
          owner: '',
          componentId: store.data.components[0]?.id ?? '',
          description: '',
          evidenceIds: [],
          backupCapacity: 0,
        },
  )
  controlEditorVisible.value = true
}

const saveControl = (): void => {
  if (!controlForm.name.trim() || !controlForm.owner.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '控制名称与负责人不能为空', life: 3000 })
    return
  }
  if (failNextSave.value) {
    armNextSaveFailure()
    failNextSave.value = false
  }
  const result = store.saveEntity('controls', {
    ...controlForm,
    id: controlForm.id || createId('ctl'),
  })
  controlEditorVisible.value = false
  if (result === 'save_failed') {
    toast.add({
      severity: 'error',
      summary: '保存失败，已恢复完整状态',
      detail: store.lastError || '控制状态未被修改。',
      life: 5000,
    })
    return
  }
  toast.add({ severity: 'success', summary: '控制已保存', detail: controlForm.name, life: 2500 })
}

const changeControlStatus = (control: SecurityControl, status: ControlStatus): void => {
  const result = store.updateControlStatus(control.id, status)
  if (result === 'save_failed') {
    toast.add({
      severity: 'error',
      summary: '保存失败，已恢复完整状态',
      detail: store.lastError || '控制状态与关联威胁结论均未被修改。',
      life: 5000,
    })
    return
  }
  const affected = store.reconciliation.affectedThreatsByControl.get(control.id)?.length ?? 0
  toast.add({
    severity: 'success',
    summary: `控制已${status === 'failed' ? '停用' : status === 'degraded' ? '降级' : '更新'}`,
    detail: `已重算 ${affected} 条关联威胁；有效缓解任务保留，失效任务待重排。`,
    life: 3500,
  })
}

const componentName = (id: string): string =>
  store.data.components.find((component) => component.id === id)?.name ?? id
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="控制保障"
      title="控制与证据"
      description="维护控制状态、备份容量与证据有效期；状态或有效期一变，只重算关联威胁的结论与缓解任务。"
    />

    <div class="evidence-metrics">
      <div>
        <span>控制总数</span>
        <strong>{{ store.data.controls.length }}</strong>
      </div>
      <div>
        <span>控制有效（含有效证据）</span>
        <strong>{{ effectiveControls }}</strong>
      </div>
      <div>
        <span>过期证据</span>
        <strong class="danger-text">{{ store.data.evidence.filter(evidenceIsExpired).length }}</strong>
      </div>
      <div>
        <span>证据/容量缺口</span>
        <strong>{{
          store.issues.filter(
            (issue) => issue.kind === 'missing_evidence' || issue.kind === 'backup_capacity_exceeded',
          ).length
        }}</strong>
      </div>
    </div>

    <label class="failure-toggle panel">
      <input type="checkbox" v-model="failNextSave" />
      模拟下一次保存失败（验证从完整状态恢复）
    </label>

    <Tabs v-model:value="activeTab">
      <TabList>
        <Tab value="controls">控制状态与备份容量</Tab>
        <Tab value="evidence">证据清单</Tab>
      </TabList>
      <TabPanels>
        <TabPanel value="controls">
          <section class="panel">
            <div class="panel-header">
              <h2 class="panel-title">安全控制</h2>
              <Button label="登记控制" icon="pi pi-plus" size="small" @click="openControlEditor()" />
            </div>
            <DataTable :value="store.data.controls" dataKey="id" size="small" stripedRows>
              <Column field="name" header="控制" />
              <Column header="归属组件" style="width: 180px">
                <template #body="{ data }">{{ componentName(data.componentId) }}</template>
              </Column>
              <Column header="控制状态" style="width: 200px">
                <template #body="{ data }">
                  <div class="status-cell">
                    <Select
                      :model-value="data.status"
                      :options="controlStatusOptions"
                      option-label="label"
                      option-value="value"
                      style="width: 120px"
                      @update:model-value="(value: ControlStatus) => changeControlStatus(data, value)"
                    />
                    <StatusTag :value="data.status" kind="status" />
                  </div>
                </template>
              </Column>
              <Column header="控制有效性" style="width: 120px">
                <template #body="{ data }">
                  <StatusTag
                    :value="isControlEffective(data, store.data.evidence) ? 'effective' : 'failed'"
                    kind="status"
                  />
                </template>
              </Column>
              <Column header="备份容量" style="width: 170px">
                <template #body="{ data }">
                  <span class="capacity-pill">
                    名额 {{ data.backupCapacity }}
                    <small v-if="!controlHasValidEvidence(data, store.data.evidence)">· 证据待补</small>
                  </span>
                </template>
              </Column>
              <Column field="owner" header="负责人" style="width: 120px" />
              <Column header="操作" style="width: 90px">
                <template #body="{ data }">
                  <Button label="编辑" size="small" text @click="openControlEditor(data)" />
                </template>
              </Column>
            </DataTable>
          </section>
        </TabPanel>

        <TabPanel value="evidence">
          <section class="panel filter-panel">
            <div class="toolbar-row">
              <div class="toolbar-field">
                <span>关联控制</span>
                <Select
                  v-model="controlFilter"
                  :options="store.data.controls"
                  option-label="name"
                  option-value="id"
                  placeholder="全部控制"
                  show-clear
                />
              </div>
              <div class="toolbar-field">
                <span>有效性</span>
                <Select
                  v-model="validityFilter"
                  :options="validityOptions"
                  option-label="label"
                  option-value="value"
                  placeholder="全部状态"
                  show-clear
                />
              </div>
              <div class="filter-actions">
                <Button label="登记证据" icon="pi pi-plus" @click="openEditor()" />
              </div>
            </div>
          </section>

          <section class="panel">
            <div class="panel-header">
              <h2 class="panel-title">证据清单</h2>
              <span class="muted">{{ filteredEvidence.length }} 条</span>
            </div>
            <DataTable :value="filteredEvidence" dataKey="id" size="small" stripedRows>
              <Column field="title" header="证据" />
              <Column header="关联控制" style="width: 210px">
                <template #body="{ data }">{{ controlName(data.controlId) }}</template>
              </Column>
              <Column header="类型" style="width: 100px">
                <template #body="{ data }">
                  {{ kindOptions.find((item) => item.value === data.kind)?.label }}
                </template>
              </Column>
              <Column field="reference" header="引用编号" style="width: 145px" />
              <Column field="owner" header="责任人" style="width: 120px" />
              <Column field="collectedAt" header="采集日" style="width: 110px" />
              <Column field="expiresAt" header="到期日" style="width: 110px" />
              <Column header="状态" style="width: 110px">
                <template #body="{ data }">
                  <StatusTag
                    :value="validity(data) === 'valid' ? 'effective' : validity(data) === 'expired' ? 'high' : 'failed'"
                    kind="status"
                  />
                </template>
              </Column>
              <Column header="操作" style="width: 100px">
                <template #body="{ data }">
                  <Button label="编辑" size="small" text @click="openEditor(data)" />
                </template>
              </Column>
            </DataTable>
          </section>
        </TabPanel>
      </TabPanels>
    </Tabs>

    <Dialog v-model:visible="controlEditorVisible" :header="controlForm.id ? '编辑控制' : '登记控制'" modal :style="{ width: '680px' }">
      <div class="editor-form">
        <div class="field">
          <label>控制名称</label>
          <InputText v-model="controlForm.name" />
        </div>
        <div class="field">
          <label>控制状态</label>
          <Select
            v-model="controlForm.status"
            :options="controlStatusOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>归属组件</label>
          <Select
            v-model="controlForm.componentId"
            :options="store.data.components"
            option-label="name"
            option-value="id"
            filter
          />
        </div>
        <div class="field">
          <label>备份控制容量（可承接的任务名额）</label>
          <InputNumber v-model="controlForm.backupCapacity" :min="0" :max="20" showButtons inputId="backup-capacity" />
        </div>
        <div class="field">
          <label>负责人</label>
          <InputText v-model="controlForm.owner" />
        </div>
        <div class="field field-wide">
          <label>说明</label>
          <InputText v-model="controlForm.description" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="controlEditorVisible = false" />
        <Button label="保存控制" icon="pi pi-check" @click="saveControl" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="editorVisible"
      :header="form.id ? '编辑控制证据' : '登记控制证据'"
      modal
      :style="{ width: '720px' }"
    >
      <div class="editor-form">
        <div class="field field-wide">
          <label>证据标题</label>
          <InputText v-model="form.title" />
        </div>
        <div class="field">
          <label>关联控制</label>
          <Select
            v-model="form.controlId"
            :options="store.data.controls"
            option-label="name"
            option-value="id"
          />
        </div>
        <div class="field">
          <label>证据类型</label>
          <Select
            v-model="form.kind"
            :options="kindOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field">
          <label>引用编号</label>
          <InputText v-model="form.reference" />
        </div>
        <div class="field">
          <label>责任人</label>
          <InputText v-model="form.owner" />
        </div>
        <div class="field">
          <label>采集日期</label>
          <InputText v-model="form.collectedAt" type="date" />
        </div>
        <div class="field">
          <label>到期日期</label>
          <InputText v-model="form.expiresAt" type="date" />
        </div>
        <div class="field">
          <label>证据是否有效</label>
          <Select
            v-model="form.valid"
            :options="[
              { label: '有效', value: true },
              { label: '已失效', value: false },
            ]"
            option-label="label"
            option-value="value"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="editorVisible = false" />
        <Button label="保存证据" icon="pi pi-check" @click="saveEvidence" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.evidence-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.evidence-metrics > div {
  display: grid;
  gap: 9px;
  padding: 15px 16px;
  background: #fff;
}

.evidence-metrics span {
  color: #6d788c;
  font-size: 12px;
}

.evidence-metrics strong {
  font-size: 24px;
}

.failure-toggle {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 14px 0;
  padding: 12px 16px;
  color: #8a4b1f;
  font-size: 12px;
  cursor: pointer;
}

.filter-panel {
  padding: 14px 16px;
}

.toolbar-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}

.status-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.capacity-pill {
  font-size: 12px;
  font-weight: 700;
  color: #1d4ed8;
}

.capacity-pill small {
  color: #b45309;
  font-weight: 400;
}
</style>
