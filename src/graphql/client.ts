import { ApolloClient, ApolloLink, InMemoryCache, Observable } from '@apollo/client/core'
import { loadState } from '@/services/repository'
import { buildReconciliation } from '@/services/projection'
import { dashboardMetrics } from '@/services/selectors'

const resolveOperation = (operationName: string): Record<string, unknown> => {
  const state = loadState()
  const reconciliation = buildReconciliation(state)

  if (operationName === 'DashboardMetrics') {
    return { dashboardMetrics: dashboardMetrics(state, reconciliation) }
  }

  if (operationName === 'ThreatIndex') {
    return {
      threatIndex: state.threats.map((threat) => ({
        id: threat.id,
        code: threat.code,
        title: threat.title,
        severity: threat.severity,
        status: reconciliation.threatStatusById.get(threat.id) ?? threat.status,
        reviewStatus: threat.reviewStatus,
        componentCount: threat.componentIds.length,
        controlCount: threat.controlIds.length,
      })),
    }
  }

  if (operationName === 'ControlHealth') {
    return {
      controlHealth: {
        total: state.controls.length,
        effective: state.controls.filter(
          (control) => reconciliation.controlEffectiveById.get(control.id) === true,
        ).length,
        degraded: state.controls.filter((control) => control.status === 'degraded').length,
        failed: state.controls.filter((control) => control.status === 'failed').length,
        missingEvidence: state.controls.filter(
          (control) => reconciliation.controlEffectiveById.get(control.id) === false,
        ).length,
      },
    }
  }

  throw new Error(`未注册的 GraphQL 操作：${operationName}`)
}

const localLink = new ApolloLink(
  (operation) =>
    new Observable((observer) => {
      try {
        observer.next({ data: resolveOperation(operation.operationName) })
        observer.complete()
      } catch (error) {
        observer.error(error)
      }
    }),
)

export const apolloClient = new ApolloClient({
  link: localLink,
  cache: new InMemoryCache(),
  defaultOptions: {
    query: {
      fetchPolicy: 'no-cache',
    },
  },
})
