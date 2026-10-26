import type { ObservationSummary } from "../api/generated/types.gen";

export function ObservationCounts({ observations }: { observations?: ObservationSummary }) {
  if (!observations) return <p>Observation breakdown unavailable.</p>;
  const { occurrences, audit_events, modes, syscall_outcomes } = observations;
  return <div>
    <p>{occurrences} AVC observations · {audit_events} audit events</p>
    <p>AVCs: {modes.enforcing ?? 0} enforced · {modes.permissive ?? 0} non-enforced · {modes.unknown ?? 0} unknown</p>
    <p>Associated syscalls by event: {syscall_outcomes.failed} failed · {syscall_outcomes.succeeded} succeeded · {syscall_outcomes.unknown} unknown</p>
    {!!observations.decision_outcomes?.length && <p>AVC/outcome associations: {observations.decision_outcomes.map((item) => `${item.occurrences} ${item.enforcement_mode === "permissive" ? "non-enforced" : item.enforcement_mode === "enforcing" ? "enforced" : "unknown enforcement"} / syscall ${item.syscall_outcome}`).join(" · ")}</p>}
  </div>;
}
