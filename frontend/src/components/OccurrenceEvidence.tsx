import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  clipboardCopyFunc,
  CodeBlock,
  CodeBlockAction,
  CodeBlockCode,
  DataListCell,
  DataListContent,
  DataListItem,
  DataListItemRow,
  DataListToggle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Label,
  Stack,
  StackItem,
  Title
} from "@patternfly/react-core";
import { ChevronRightIcon, CopyIcon, DownloadIcon } from "@patternfly/react-icons";
import { Link } from "react-router-dom";
import { Fragment, useState, type ReactNode } from "react";
import Prism from "prismjs/components/prism-core";
import "prismjs/components/prism-json";
import type { OccurrenceDetail } from "../api/issue";
import { Disclosure as ExpandableSection } from "./Disclosure";

export function formatUtc(iso: string): string {
  return `${new Intl.DateTimeFormat("en", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    timeZone: "UTC"
  }).format(new Date(iso))} UTC`;
}

function Facts({ fields, isHorizontal = false }: { fields: [string, React.ReactNode][]; isHorizontal?: boolean }) {
  const present = fields.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (present.length === 0) return <p className="pf-v6-u-color-200">No normalized details recorded.</p>;
  if (isHorizontal) return <DescriptionList orientation={{ sm: "horizontal" }} isCompact isFluid columnModifier={{ default: "1Col", lg: "2Col" }}>
    {present.map(([label, value]) => <DescriptionListGroup key={label}>
      <DescriptionListTerm>{label}</DescriptionListTerm>
      <DescriptionListDescription>{value}</DescriptionListDescription>
    </DescriptionListGroup>)}
  </DescriptionList>;
  return (
    <dl className="detail-facts occurrence-facts">
      {present.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export { Facts as EvidenceFacts };

function jsonTokens(token: Prism.TokenStream): ReactNode {
  if (typeof token === "string") return token;
  if (Array.isArray(token)) return token.map((item, index) => <Fragment key={index}>{jsonTokens(item)}</Fragment>);
  return <span className={`json-token-${token.type}`}>{jsonTokens(token.content)}</span>;
}

function highlightedJson(value: string): ReactNode {
  try {
    JSON.parse(value);
    return jsonTokens(Prism.tokenize(value, Prism.languages.json));
  } catch {
    return value;
  }
}

export function EvidenceBlock({ value, label, hasCopyButton = false, isJson = false, downloadFilename }: { value: string; label: string; hasCopyButton?: boolean; isJson?: boolean; downloadFilename?: string }) {
  const [copyState, setCopyState] = useState("Copy");
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopyState("Copied");
    } catch {
      setCopyState("Copy failed");
    }
  }
  return (
    <CodeBlock
      className="occurrence-code-block"
      actions={
        <>
          <CodeBlockAction>
            {hasCopyButton ? <Button variant="plain" icon={<CopyIcon aria-hidden="true" />} aria-label={`Copy ${label}`} onClick={() => void copy()}><span aria-live="polite">{copyState}</span></Button> : <ClipboardCopy
              variant="inline-compact"
              isReadOnly
              isCode
              copyAriaLabel={`Copy ${label}`}
              textAriaLabel={label}
              hoverTip={`Copy ${label}`}
              clickTip={`${label} copied`}
              onCopy={(event) => clipboardCopyFunc(event, value)}
            >{copyPreview(value)}</ClipboardCopy>}
          </CodeBlockAction>
          {downloadFilename && <CodeBlockAction><Button variant="plain" icon={<DownloadIcon aria-hidden="true" />} onClick={() => {
            const url = URL.createObjectURL(new Blob([value], { type: "application/json;charset=utf-8" }));
            const anchor = document.createElement("a");
            anchor.href = url;
            anchor.download = downloadFilename;
            anchor.click();
            URL.revokeObjectURL(url);
          }}>Download JSON</Button></CodeBlockAction>}
        </>
      }
    >
      <CodeBlockCode>{isJson ? highlightedJson(value) : value}</CodeBlockCode>
    </CodeBlock>
  );
}

function copyPreview(value: string): string {
  const oneLine = value.replace(/\s+/g, " ");
  return oneLine.length > 42 ? `${oneLine.slice(0, 22)}…${oneLine.slice(-16)}` : oneLine;
}

function CopyEvidence({ value, label }: { value: string; label: string }) {
  return (
    <ClipboardCopy
      variant="inline-compact"
      isReadOnly
      isCode
      copyAriaLabel={`Copy ${label}`}
      textAriaLabel={label}
      hoverTip={`Copy ${label}`}
      clickTip={`${label} copied`}
      onCopy={(event) => clipboardCopyFunc(event, value)}
    >{copyPreview(value)}</ClipboardCopy>
  );
}

function jsonText(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? String(value);
}

function EvidenceSection({
  title,
  collapsed,
  isCard = !collapsed,
  children
}: {
  title: string;
  collapsed: boolean;
  isCard?: boolean;
  children: React.ReactNode;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const contents = collapsed ? (
    <ExpandableSection
      toggleTextCollapsed={title}
      toggleTextExpanded={`Hide ${title.toLowerCase()}`}
      isExpanded={isExpanded}
      onToggle={(_event, expanded) => setIsExpanded(expanded)}
    >
      {isExpanded && children}
    </ExpandableSection>
  ) : <>
    <CardTitle><Title headingLevel="h2" size="md">{title}</Title></CardTitle>
    <CardBody>{children}</CardBody>
  </>;
  return <StackItem>{isCard
    ? <Card isCompact className="occurrence-evidence-section" aria-label={title}>{collapsed ? <CardBody>{contents}</CardBody> : contents}</Card>
    : <section className="occurrence-evidence-section">{contents}</section>}
  </StackItem>;
}

export function OccurrenceNormalizedDetails({ occurrence }: { occurrence: OccurrenceDetail }) {
  return <Card isCompact className="occurrence-normalized-details">
    <CardTitle><Title headingLevel="h2" size="md">Normalized details</Title></CardTitle>
    <CardBody>
      <p>Parsed occurrence facts generated by the SECentral normalizer.</p>
      <div className="occurrence-normalized-json occurrence-normalized-json-full" role="region" aria-label="Normalized JSON payload" tabIndex={0}>
        <EvidenceBlock hasCopyButton isJson value={jsonText(occurrence.normalized_denial.details)} label={`normalized details for occurrence ${occurrence.id}`} downloadFilename={`occurrence-${occurrence.id}-normalized-details.json`} />
      </div>
    </CardBody>
  </Card>;
}

export function OccurrenceRawEvidence({ occurrence, collapsed = false, includeNormalized = true, omitRawAvc = false }: { occurrence: OccurrenceDetail; collapsed?: boolean; includeNormalized?: boolean; omitRawAvc?: boolean }) {
  const denial = occurrence.normalized_denial;
  const records = [...occurrence.raw_event.audit_records].sort((a, b) => a.position - b.position);
  const avcRecords = records.filter((record) => ["avc", "user_avc"].includes(record.type_name.toLowerCase()));
  return (
    <Stack hasGutter className="occurrence-raw-evidence">
      {collapsed && !omitRawAvc && <EvidenceSection title="Raw AVC" collapsed>
        {avcRecords.length > 0 ? avcRecords.map((record) => (
          <div className="occurrence-audit-record" key={record.position}>
            <small>#{record.position} · {record.type_name}</small>
            <EvidenceBlock hasCopyButton value={record.payload} label={`raw AVC record ${record.position} for occurrence ${occurrence.id}`} />
          </div>
        )) : <p className="pf-v6-u-color-200">No AVC audit record is present.</p>}
      </EvidenceSection>}
      <EvidenceSection title={collapsed ? "Raw audit records" : "Audit Event Records"} collapsed={collapsed}>
        {records.length > 0 ? records.map((record) => (
          <div className="occurrence-audit-record" key={record.position}>
            <small>#{record.position} · {record.type_name}</small>
            <EvidenceBlock hasCopyButton value={record.payload} label={`audit record ${record.position} for occurrence ${occurrence.id}`} />
          </div>
        )) : <p className="pf-v6-u-color-200">No raw audit records are present.</p>}
      </EvidenceSection>
      <EvidenceSection title={collapsed ? "Other retained payload" : "Retained Event Metadata"} collapsed={collapsed}>
        <Facts isHorizontal={!collapsed} fields={[
          ["Audit time", <time dateTime={occurrence.raw_event.audit_timestamp}>{formatUtc(occurrence.raw_event.audit_timestamp)}</time>],
          ["Audit sequence", occurrence.raw_event.audit_sequence],
          ["Boot ID", <code>{occurrence.raw_event.boot_id}</code>],
          ["Completion", occurrence.raw_event.completion_reason],
          ["Evidence digest", <CopyEvidence value={occurrence.raw_event.evidence_digest} label={`evidence digest for occurrence ${occurrence.id}`} />],
          ["Checkpoint port inventory", occurrence.raw_event.checkpoint_port_inventory_status],
          ["Checkpoint expected-label mappings", occurrence.raw_event.checkpoint_file_context_mappings_status],
          ["Exact policy identity", occurrence.raw_event.permissive_policy_state?.policy_identity && <CopyEvidence value={occurrence.raw_event.permissive_policy_state.policy_identity} label={`exact policy identity for occurrence ${occurrence.id}`} />]
        ]} />
      </EvidenceSection>
      {includeNormalized && <EvidenceSection title="Normalized details (debug)" collapsed isCard={!collapsed}>
        <div className="occurrence-normalized-json" role="region" aria-label="Normalized JSON payload" tabIndex={0}>
          <EvidenceBlock hasCopyButton isJson value={jsonText(denial.details)} label={`normalized details for occurrence ${occurrence.id}`} />
        </div>
      </EvidenceSection>}
    </Stack>
  );
}

export function OccurrenceEvidence({
  occurrence,
  isExpanded,
  onToggle,
  hostContext = false
}: {
  occurrence: OccurrenceDetail;
  isExpanded: boolean;
  onToggle?: (event?: React.MouseEvent<HTMLElement>) => void;
  hostContext?: boolean;
}) {
  const rowId = `occurrence-${occurrence.id}`;
  const denial = occurrence.normalized_denial;
  const occurrenceHref = `/hosts/${occurrence.host.id}/occurrences/${occurrence.id}`;
  const missing = Array.isArray(denial.details.missing)
    ? denial.details.missing.filter((item): item is string => typeof item === "string")
    : [];
  return (
    <DataListItem id={rowId} isExpanded={!hostContext && isExpanded} className="occurrence-list-item">
      <DataListItemRow rowid={rowId}>
        {!hostContext && (
          <DataListToggle
            isExpanded={isExpanded}
            id={rowId}
            rowid={rowId}
            aria-label={isExpanded ? "Collapse occurrence details" : "Expand occurrence details"}
            buttonProps={{ onClick: (event) => { event.stopPropagation(); onToggle?.(event); } }}
          />
        )}
        <DataListCell className="occurrence-list-summary">
          {hostContext ? (
            <Link className="occurrence-host-row-link" to={occurrenceHref}>
              <div className="occurrence-summary-layout">
                <div className="occurrence-list-primary">
                  <span className="occurrence-denial-types">
                    <code>{denial.source_type ?? "unknown source"}</code> → <code>{denial.target_type ?? "unknown target"}</code>
                  </span>
                  <span className="occurrence-class-permission pf-v6-u-color-200">
                    {denial.target_class ?? "unknown class"} · {denial.permissions?.join(", ") || "unknown permission"}
                    {occurrence.issue && <> · Issue #{occurrence.issue.id}</>}
                  </span>
                  <span className="occurrence-row-context">
                    {!occurrence.issue && <span className="pf-v6-u-color-200">Ungrouped event</span>}
                    {denial.status !== "ok" && (
                      <span className="occurrence-normalization-state">
                        <Label color="orange" isCompact>Ungroupable</Label>
                        {missing.length > 0 && <span className="pf-v6-u-color-200">Missing {missing.join(", ")}</span>}
                      </span>
                    )}
                  </span>
                </div>
                <time className="occurrence-list-time" dateTime={occurrence.occurred_at} title={occurrence.occurred_at}>
                  {formatUtc(occurrence.occurred_at)}
                </time>
                <ChevronRightIcon className="occurrence-row-chevron" aria-hidden="true" />
              </div>
            </Link>
          ) : (
            <div className="occurrence-summary-layout">
              <div className="occurrence-list-primary">
                <Link className="occurrence-host-name" to={`/hosts/${occurrence.host.id}`}>
                  {occurrence.host.hostname ?? `Host ${occurrence.host.id}`}
                </Link>
                <span className="occurrence-class-permission pf-v6-u-color-200">
                  {denial.target_class ?? "unknown class"} · {denial.permissions?.join(", ") || "unknown permission"}
                </span>
              </div>
              <time className="occurrence-list-time" dateTime={occurrence.occurred_at} title={occurrence.occurred_at}>
                {formatUtc(occurrence.occurred_at)}
              </time>
            </div>
          )}
        </DataListCell>
      </DataListItemRow>
      {!hostContext && <DataListContent isHidden={!isExpanded} rowid={rowId} aria-label={`Occurrence ${occurrence.id} details`}>
        <div className="occurrence-expanded-content">
          <section className="occurrence-evidence-section">
            <h3>Normalized denial</h3>
            <Facts fields={[
              ["Source type", denial.source_type && <code>{denial.source_type}</code>],
              ["Target type", denial.target_type && <code>{denial.target_type}</code>],
              ["Class", denial.target_class && <code>{denial.target_class}</code>],
              ["Permissions", denial.permissions?.map((permission) => <code key={permission}>{permission}</code>)],
              ["Observed path", denial.target_paths.length > 0 ? denial.target_paths.map((path) => <code key={path}>{path}</code>) : "None recorded"],
              ["Process", denial.command && <code>{denial.command}</code>],
              ["Executable", denial.executable && <code>{denial.executable}</code>],
              ["Source context", denial.source_context && <code>{denial.source_context}</code>],
              ["Target context", denial.target_context && <code>{denial.target_context}</code>],
              ...(hostContext ? [["Issue", occurrence.issue
                ? <Link to={`/issues/${occurrence.issue.id}?tab=occurrences`}>Issue #{occurrence.issue.id}</Link>
                : <span className="pf-v6-u-color-200">Ungrouped event</span>] as [string, React.ReactNode]] : [])
            ]} />
            {missing.length > 0 && <Alert variant="warning" isInline title={`Ungroupable: missing ${missing.join(", ")}`} />}
          </section>

          {occurrence.guidance && (
            <section className="occurrence-evidence-section">
              <h3>Guidance</h3>
              <p>{occurrence.guidance.summary}</p>
              {occurrence.guidance.observations.length > 0 && <EvidenceBlock value={jsonText(occurrence.guidance.observations)} label={`guidance observations for occurrence ${occurrence.id}`} />}
              {occurrence.guidance.checks.length > 0 && <EvidenceBlock value={jsonText(occurrence.guidance.checks)} label={`guidance checks for occurrence ${occurrence.id}`} />}
              {occurrence.guidance.missing_evidence.length > 0 && <p className="pf-v6-u-color-200">Missing evidence: {occurrence.guidance.missing_evidence.join(", ")}</p>}
              {occurrence.guidance.historical_limitations.length > 0 && <p className="pf-v6-u-color-200">Limitations: {occurrence.guidance.historical_limitations.join(", ")}</p>}
            </section>
          )}

          <OccurrenceRawEvidence occurrence={occurrence} />
        </div>
      </DataListContent>}
    </DataListItem>
  );
}
