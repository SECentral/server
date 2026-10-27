import { Alert, Breadcrumb, BreadcrumbItem, Spinner, Title } from "@patternfly/react-core";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { OccurrenceInvestigation } from "../components/OccurrenceInvestigation";
import { formatUtc } from "../components/OccurrenceEvidence";
import { fetchHost, fetchHostOccurrence, fetchHostSelinuxActivity } from "../api/hosts";

export function HostOccurrenceDetail() {
  const { id, occurrenceId: rawOccurrenceId } = useParams();
  const hostId = Number(id);
  const occurrenceId = Number(rawOccurrenceId);
  const validIds = Number.isInteger(hostId) && hostId > 0 && Number.isInteger(occurrenceId) && occurrenceId > 0;

  const hostQuery = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => fetchHost(hostId),
    enabled: validIds
  });
  const occurrenceQuery = useQuery({
    queryKey: ["host-occurrence", hostId, occurrenceId],
    queryFn: () => fetchHostOccurrence(hostId, occurrenceId),
    refetchInterval: (query) => query.state.data?.raw_event.permissive_policy_state?.status === "pending" ? 2000 : false,
    enabled: validIds
  });
  const activityQuery = useQuery({
    queryKey: ["host-selinux-activity-occurrence", hostId, occurrenceId],
    queryFn: () => fetchHostSelinuxActivity(hostId, { occurrenceId }),
    enabled: validIds
  });

  if (!validIds) {
    return <Alert variant="danger" isInline title="Invalid occurrence address"><Link to="/hosts">Back to monitored servers</Link></Alert>;
  }
  if (hostQuery.isError) {
    return <Alert variant="danger" isInline title="Could not load host"><Link to={`/hosts/${hostId}`}>Back to host</Link></Alert>;
  }
  if (hostQuery.isPending || occurrenceQuery.isPending) {
    return <div aria-label="Loading occurrence" style={{ padding: "var(--pf-v6-global--spacer--xl)" }}><Spinner size="xl" /></div>;
  }
  if (occurrenceQuery.isError) {
    return <Alert variant="danger" isInline title="Could not load occurrence">{occurrenceQuery.error instanceof Error ? occurrenceQuery.error.message : "Unknown error"}</Alert>;
  }

  const host = hostQuery.data.host;
  const occurrence = occurrenceQuery.data;
  if (!occurrence) {
    return <Alert variant="warning" isInline title="Occurrence not found"><Link to={`/hosts/${hostId}`}>Back to {host.hostname ?? `Host ${hostId}`}</Link></Alert>;
  }
  const denial = occurrence.normalized_denial;

  return (
    <>
      <Breadcrumb aria-label="Breadcrumb" className="pf-v6-u-mb-sm">
        <BreadcrumbItem><Link to="/hosts">Monitored servers</Link></BreadcrumbItem>
        <BreadcrumbItem><Link to={`/hosts/${hostId}`}>{host.hostname ?? `Host ${hostId}`}</Link></BreadcrumbItem>
        <BreadcrumbItem isActive>Occurrence</BreadcrumbItem>
      </Breadcrumb>
      <Title headingLevel="h1" size="2xl" className="pf-v6-u-mt-0">
        <code>{denial.source_type ?? "unknown"}</code> → <code>{denial.target_type ?? "unknown"}</code>
      </Title>
      <p className="pf-v6-u-color-200">
        {denial.target_class ?? "unknown class"} · {denial.permissions?.join(", ") || "unknown permission"} · {formatUtc(occurrence.occurred_at)}
      </p>
      <OccurrenceInvestigation occurrence={occurrence} />
      {activityQuery.data?.items[0] ? <Alert variant="info" isInline title="SELinux state changed before this occurrence" className="pf-v6-u-mt-lg">
        {activityQuery.data.items[0].transition_type === "file_context_change"
          ? "File-context mapping configuration is unavailable for this occurrence until a complete checkpoint refresh. The recorded target label and path remain available. "
          : activityQuery.data.items[0].transition_type === "port_change"
          ? "Historical port inventory and policy identity are unavailable for this occurrence until a checkpoint refresh. The recorded target label remains available. "
          : activityQuery.data.items[0].transition_type === "enforcement_change"
          ? "Checkpoint enforcement mode is unavailable for this occurrence until refresh. Use the enforcement evidence recorded in the AVC. "
          : "No refreshed checkpoint applied to this occurrence, so checkpoint-dependent policy analysis is unavailable. "}
        <Link to={`/hosts/${hostId}?selinux_activity=${activityQuery.data.items[0].id}#selinux-activity`}>View the preceding observed transition</Link>.
      </Alert> : null}
    </>
  );
}
