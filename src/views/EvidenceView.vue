<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Select from 'primevue/select'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { ControlEvidence, ControlStatus, SecurityControl } from '@/models/domain'
import { controlHasValidEvidence, buildEvidenceMap, evidenceIsExpired } from '@/services/derivation'
import { createId } from '@/services/repository'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const editorVisible = ref(false)
const validityFilter = ref<string | null>(null)
const controlFilter = ref<string | null>(null)

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
const controlStatusOptions: { label: string; value: ControlStatus }[] = [
  { label: '有效', value: 'effective' },
  { label: '降级', value: 'degraded' },
  { label: '失效', value: 'failed' },
  { label: '计划中', value: 'planned' },
]
const controlTypeLabels: Record<SecurityControl['type'], string> = {
  preventive: '预防',
  detective: '检测',
  corrective: '纠正',
}
const capacityOptions = [0, 1, 2, 3].map((value) => ({ label: `${value} 个槽位`, value }))

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

const filteredEvidence = computed(() =>
  store.data.evidence.filter((evidence) => {
    const validity = evidenceIsExpired(evidence) ? 'expired' : evidence.valid ? 'valid' : 'invalid'
    return (
      (!controlFilter.value || evidence.controlId === controlFilter.value) &&
      (!validityFilter.value || validity === validityFilter.value)
    )
  }),
)

const evidenceById = computed(() => buildEvidenceMap(store.data))

const effectiveControls = computed(
  () =>
    store.data.controls.filter((control) =>
      control.evidenceIds.some((id) => {
        const evidence = store.data.evidence.find((item) => item.id === id)
        return evidence?.valid && !evidenceIsExpired(evidence)
      }),
    ).length,
)

const controlName = (id: string): string =>
  store.data.controls.find((control) => control.id === id)?.name ?? id

const linkedThreatCount = (controlId: string): number =>
  store.data.threats.filter((threat) => threat.controlIds.includes(controlId)).length

const hasValidEvidence = (control: SecurityControl): boolean =>
  controlHasValidEvidence(control, evidenceById.value)

const updateControlStatus = (control: SecurityControl, status: ControlStatus): void => {
  store.saveEntity('controls', { ...control, status })
  toast.add({
    severity: 'info',
    summary: '控制状态已更新',
    detail: `${control.name}：关联威胁结论与缓解任务已自动重算`,
    life: 3000,
  })
}

const updateControlCapacity = (control: SecurityControl, backupCapacity: number): void => {
  store.saveEntity('controls', { ...control, backupCapacity })
  toast.add({
    severity: 'info',
    summary: '备份容量已更新',
    detail: `${control.name} 可承接 ${backupCapacity} 个待重排任务`,
    life: 2500,
  })
}

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
  store.saveEntity('evidence', { ...form, id: form.id || createId('ev') })
  editorVisible.value = false
  toast.add({
    severity: 'success',
    summary: '证据已保存',
    detail: '证据有效期变化已触发关联威胁重算',
    life: 2500,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="控制保障"
      title="控制证据"
      description="登记控制测试、配置快照与审计签署，自动识别缺失、失效和过期证据。"
    />

    <div class="evidence-metrics">
      <div>
        <span>控制总数</span>
        <strong>{{ store.data.controls.length }}</strong>
      </div>
      <div>
        <span>具备有效证据</span>
        <strong>{{ effectiveControls }}</strong>
      </div>
      <div>
        <span>过期证据</span>
        <strong class="danger-text">{{ store.data.evidence.filter(evidenceIsExpired).length }}</strong>
      </div>
      <div>
        <span>证据缺口</span>
        <strong>{{ store.issues.filter((issue) => issue.kind === 'missing_evidence').length }}</strong>
      </div>
    </div>

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">安全控制状态</h2>
        <span class="muted">状态或证据有效期变化将自动重算关联威胁结论与缓解任务</span>
      </div>
      <DataTable :value="store.data.controls" dataKey="id" size="small" stripedRows>
        <Column field="name" header="控制" style="min-width: 200px" />
        <Column header="类型" style="width: 80px">
          <template #body="{ data }">{{ controlTypeLabels[data.type as SecurityControl['type']] }}</template>
        </Column>
        <Column header="状态" style="width: 150px">
          <template #body="{ data }">
            <Select
              :model-value="data.status"
              :options="controlStatusOptions"
              option-label="label"
              option-value="value"
              size="small"
              @update:model-value="updateControlStatus(data, $event)"
            />
          </template>
        </Column>
        <Column header="有效证据" style="width: 100px">
          <template #body="{ data }">
            <StatusTag :value="hasValidEvidence(data) ? 'effective' : 'failed'" kind="status" />
          </template>
        </Column>
        <Column header="关联威胁" style="width: 90px">
          <template #body="{ data }">{{ linkedThreatCount(data.id) }} 条</template>
        </Column>
        <Column header="备份容量" style="width: 150px">
          <template #body="{ data }">
            <Select
              :model-value="data.backupCapacity"
              :options="capacityOptions"
              option-label="label"
              option-value="value"
              size="small"
              @update:model-value="updateControlCapacity(data, $event)"
            />
          </template>
        </Column>
      </DataTable>
    </section>

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

.filter-panel {
  padding: 14px 16px;
}
</style>
