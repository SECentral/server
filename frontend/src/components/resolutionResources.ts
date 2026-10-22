import type { ResolutionWorkflow } from "../api/resolution";
import type { IssueDetailResponse } from "../api/issue";

type Candidate = ResolutionWorkflow["candidates"][number];
type Port = NonNullable<ResolutionWorkflow["port_investigations"]>[number];
type Source = NonNullable<IssueDetailResponse["operator_guidance"]>["source"];

export function portResourceKey(port: Pick<Port, "host_id" | "protocol" | "port" | "operation">): string {
  return `${port.host_id}:${port.protocol}:${port.port ?? "unknown"}:${port.operation}`;
}

export function candidateFilePath(candidate: Candidate): string | null {
  const path = candidate.evidence_basis.path ?? candidate.home_content_path ?? candidate.evidence_basis.home_content_path;
  return typeof path === "string" && path.startsWith("/") ? path : null;
}

function unidentifiedResource(candidate: Candidate): string {
  const basis = candidate.evidence_basis;
  const names = Array.isArray(basis.home_content_names) ? basis.home_content_names.filter((name): name is string => typeof name === "string") : [];
  if (candidate.requires_home_content_review || basis.object_class === "file") return `Unidentified file${names.length === 1 ? `: ${names[0]}` : ""} · occurrence #${basis.occurrence_id ?? "unknown"}`;
  return `Policy review${typeof basis.boolean === "string" ? `: ${basis.boolean}` : ""}`;
}

export function resolutionResources(workflow: ResolutionWorkflow, source?: Source) {
  const resources: { key: string; label: string; path?: string; port?: Port; source?: Source; candidates: Candidate[] }[] = (workflow.port_investigations ?? []).map((port) => ({
    key: portResourceKey(port),
    label: `${port.protocol.toUpperCase()}/${port.port ?? "port not recorded"} · ${port.operation === "name_bind" ? "Local bind" : "Outbound connect"} · ${port.hostname ?? `Host ${port.host_id}`}`,
    port, candidates: []
  }));
  for (const item of workflow.file_investigations ?? []) {
    resources.push({ key: `${item.host_id}:${item.path}`, label: `${item.path} · ${item.hostname ?? `Host ${item.host_id}`}`,
      path: item.path, source: item, candidates: [] });
  }
  for (const candidate of workflow.candidates) {
    const basis = candidate.evidence_basis;
    const path = candidateFilePath(candidate);
    const port = resources.find((resource) => resource.port && resource.port.host_id === candidate.host_id &&
      (candidate.kind === "set_port_mapping"
        ? resource.port.protocol === basis.protocol && resource.port.port === basis.port && resource.port.operation === basis.operation
        : resource.port.occurrence_id === basis.occurrence_id));
    const key = port?.key ?? `${candidate.host_id}:${path ?? `policy:${basis.occurrence_id ?? "unknown"}`}`;
    let resource = resources.find((item) => item.key === key);
    if (!resource) {
      resource = { key, label: `${path ?? unidentifiedResource(candidate)} · ${candidate.hostname ?? `Host ${candidate.host_id}`}`, path: path ?? undefined, candidates: [] };
      resources.push(resource);
    }
    resource.candidates.push(candidate);
  }
  if (source && (source.path || ["file", "dir", "lnk_file", "fifo_file", "chr_file", "blk_file", "sock_file"].includes(source.object_class ?? ""))) {
    const key = `${source.host_id}:${source.path ?? `policy:${source.occurrence_id}`}`;
    const existing = resources.find((resource) => resource.key === key);
    if (existing) existing.source = source;
    else {
      const noun = source.object_class === "dir" ? "directory" : source.object_class === "sock_file" ? "Unix socket" : "file";
      resources.unshift({ key, label: `${source.path ?? `Unidentified ${noun}`} · ${source.hostname ?? `Host ${source.host_id}`}`, path: source.path ?? undefined, source, candidates: [] });
    }
  }
  return resources;
}

export function activeResolutionResource(workflow: ResolutionWorkflow, requested: string | null, source?: NonNullable<IssueDetailResponse["operator_guidance"]>["source"]) {
  const resources = resolutionResources(workflow, source);
  return resources.find((resource) => resource.key === requested)
    ?? resources.find((resource) => resource.candidates.some((candidate) => `${candidate.host_id}:policy:${candidate.evidence_basis.occurrence_id}` === requested))
    ?? resources.find((resource) => source && (resource.source?.occurrence_id === source.occurrence_id || resource.port?.occurrence_id === source.occurrence_id || resource.candidates.some((candidate) => candidate.host_id === source.host_id && (source.path ? candidateFilePath(candidate) === source.path : candidate.evidence_basis.occurrence_id === source.occurrence_id))))
    ?? resources.find((resource) => resource.candidates.some((candidate) => candidate.id === workflow.intent?.candidate_id)) ?? resources[0];
}

export function activeResourceFinding(detail: IssueDetailResponse, workflow: ResolutionWorkflow, requested: string | null) {
  const source = detail.operator_guidance?.source;
  const active = activeResolutionResource(workflow, requested, source);
  const candidate = active?.candidates[0];
  const occurrenceId = active?.port?.occurrence_id ?? active?.source?.occurrence_id ?? candidate?.evidence_basis.occurrence_id ?? source?.occurrence_id ?? workflow.observed_access?.occurrence_id;
  const hostId = active?.port?.host_id ?? active?.source?.host_id ?? candidate?.host_id ?? source?.host_id ?? workflow.observed_access?.host_id;
  // Use only an exact diagnosis source; group membership alone does not transfer its evidence.
  const groups = detail.host_explanations.flatMap((host) => host.diagnosis_groups);
  const group = groups.find((group) => group.diagnosis?.host_id === hostId && group.diagnosis?.occurrence_id === occurrenceId && occurrenceId != null);
  const diagnosis = group?.diagnosis ?? (detail.diagnosis?.occurrence_id === occurrenceId && detail.diagnosis?.host_id === hostId ? detail.diagnosis : null);
  const displayed = diagnosis ?? detail.diagnosis;
  const scopedFindings = (group?.findings ?? detail.findings?.map((finding) => finding.diagnosis) ?? []).filter((finding) => finding.occurrence_id === displayed?.occurrence_id && finding.host_id === displayed?.host_id);
  return {
    diagnosis: displayed,
    findings: scopedFindings.length ? scopedFindings : displayed ? [displayed] : [],
    count: group?.count ?? detail.findings?.find((finding) => finding.diagnosis.occurrence_id === displayed?.occurrence_id && finding.diagnosis.host_id === displayed?.host_id)?.occurrence_count,
    different: !!detail.diagnosis && !diagnosis && occurrenceId != null && (detail.diagnosis.occurrence_id !== occurrenceId || detail.diagnosis.host_id !== hostId)
  };
}

export function fileResourceLabel(resource: ReturnType<typeof resolutionResources>[number], resources: ReturnType<typeof resolutionResources>): string {
  const path = resource.path;
  if (typeof path !== "string") return resource.label;
  const parts = path.split("/").filter(Boolean);
  const otherPaths = resources.filter((other) => other.key !== resource.key).map((other) => other.path).filter((other): other is string => typeof other === "string");
  let suffix = parts.at(-1) ?? "/";
  for (let length = 1; length <= parts.length; length++) {
    suffix = parts.slice(-length).join("/");
    if (!otherPaths.some((other) => other !== path && other.split("/").filter(Boolean).slice(-length).join("/") === suffix)) break;
    if (length === parts.length) suffix = path;
  }
  if (otherPaths.includes(path)) return `${suffix} · ${resource.source?.hostname ?? resource.candidates[0]?.hostname ?? "Host"} (#${resource.source?.host_id ?? resource.candidates[0]?.host_id})`;
  return suffix;
}
