import type { SelinuxAdministrativeFacts } from "../api/generated/types.gen";

type Facts = Pick<SelinuxAdministrativeFacts, "transition_type" | "boundary_established" | "boolean_changes"> & Partial<SelinuxAdministrativeFacts>;
const state = (value: boolean | null) => value === true ? "On" : value === false ? "Off" : "Unknown";
const mode = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

export function administrativeDescription(activity: Facts) {
  const enforcement = activity.transition_type === "enforcement_change";
  const ports = activity.transition_type === "port_change";
  const mappings = activity.transition_type === "file_context_change";
  const mappingSummary = (activity.file_context_changes ?? []).map((change) => `${change.expression} · ${change.file_selector} · ${change.operation}${change.selinux_type ? ` → ${change.selinux_type}` : ""}${change.boundary_established ? "" : " · boundary not established"}`).join("; ") || "Mapping configuration reported · boundary not established";
  const portSummary = (activity.port_changes ?? []).map((change) => `${change.protocol.toUpperCase()}/${change.start}${change.end === change.start ? "" : `-${change.end}`} · ${change.operation}${change.selinux_type ? ` → ${change.selinux_type}` : ""}${change.boundary_established ? "" : " · boundary not established"}`).join("; ") || "Port configuration reported · boundary not established";
  const title = mappings ? (activity.boundary_established ? "File-context mapping write reported" : "File-context configuration reported") : ports ? (activity.boundary_established ? "Port mapping write reported" : "Port configuration reported") : !activity.boundary_established ? (enforcement ? "Enforcement status reported" : activity.transition_type === "policy_load" ? "Policy load reported" : "Boolean change reported")
    : activity.transition_type === "policy_load" ? "SELinux policy loaded"
    : enforcement ? "Enforcement changed"
    : activity.boolean_changes.length > 1 ? "SELinux booleans changed" : "Boolean changed";
  const typeLabel = mappings ? "File-context mapping" : ports ? "Port mapping" : enforcement ? "Enforcement" : activity.transition_type === "policy_load" ? "Policy load" : "Boolean";
  return { mappingSummary, portSummary, title, typeLabel };
}

export function SelinuxActivitySummary({ activity }: { activity: Facts }) {
  const description = administrativeDescription(activity);
  if (activity.transition_type === "file_context_change") return description.mappingSummary;
  if (activity.transition_type === "port_change") return description.portSummary;
  if (activity.transition_type === "policy_load") return description.title;
  if (activity.transition_type === "enforcement_change") {
    return activity.enforcement_changes?.length ? activity.enforcement_changes.map((change, index) => <span key={index}>
      {index ? "; " : ""}{change.state_change_established ? "" : "Reported: "}{mode(change.old_mode)} → {mode(change.new_mode)}{change.state_change_established ? "" : " · state change not established"}
    </span>) : "Enforcement status reported · state change not established";
  }
  return activity.boolean_changes.length ? activity.boolean_changes.map((change, index) => <span key={`${change.name}-${index}`}>
    {index ? "; " : ""}<code>{change.name}</code>: {change.state_change_established ? "" : "Reported: "}{state(change.old_value)} → {state(change.new_value)}{change.state_change_established ? "" : " · state change not established"}
  </span>) : "Boolean change reported · state change not established";
}
