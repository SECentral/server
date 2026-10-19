import type { ResolutionWorkflow } from "../api/resolution";
import type { IssueDetailResponse } from "../api/issue";

type Candidate = ResolutionWorkflow["candidates"][number];
type Port = NonNullable<ResolutionWorkflow["port_investigations"]>[number];

export function portResourceKey(port: Pick<Port, "host_id" | "protocol" | "port" | "operation">): string {
  return `${port.host_id}:${port.protocol}:${port.port ?? "unknown"}:${port.operation}`;
}

export function resolutionResources(workflow: ResolutionWorkflow) {
  const resources: { key: string; label: string; port?: Port; candidates: Candidate[] }[] = (workflow.port_investigations ?? []).map((port) => ({
    key: portResourceKey(port),
    label: `${port.protocol.toUpperCase()}/${port.port ?? "port not recorded"} · ${port.operation === "name_bind" ? "Local bind" : "Outbound connect"} · ${port.hostname ?? `Host ${port.host_id}`}`,
    port, candidates: []
  }));
  for (const candidate of workflow.candidates) {
    const basis = candidate.evidence_basis;
    const port = resources.find((resource) => resource.port && resource.port.host_id === candidate.host_id &&
      (candidate.kind === "set_port_mapping"
        ? resource.port.protocol === basis.protocol && resource.port.port === basis.port && resource.port.operation === basis.operation
        : resource.port.occurrence_id === basis.occurrence_id));
    const key = port?.key ?? `${candidate.host_id}:${basis.path ?? `policy:${basis.occurrence_id ?? "unknown"}`}`;
    let resource = resources.find((item) => item.key === key);
    if (!resource) {
      resource = { key, label: `${basis.path ?? "Policy options"} · ${candidate.hostname ?? `Host ${candidate.host_id}`}`, candidates: [] };
      resources.push(resource);
    }
    resource.candidates.push(candidate);
  }
  return resources;
}

export function activeResolutionResource(workflow: ResolutionWorkflow, requested: string | null, source?: NonNullable<IssueDetailResponse["operator_guidance"]>["source"]) {
  const resources = resolutionResources(workflow);
  return resources.find((resource) => resource.key === requested) ?? resources.find((resource) => source && (resource.port?.occurrence_id === source.occurrence_id || resource.candidates.some((candidate) => candidate.host_id === source.host_id && (source.path ? candidate.evidence_basis.path === source.path : candidate.evidence_basis.occurrence_id === source.occurrence_id))))
    ?? resources.find((resource) => resource.candidates.some((candidate) => candidate.id === workflow.intent?.candidate_id)) ?? resources[0];
}
