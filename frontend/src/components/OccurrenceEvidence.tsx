import {
  Alert,
  Button,
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
  ExpandableSection,
  Label
} from "@patternfly/react-core";
import { ChevronRightIcon, CopyIcon } from "@patternfly/react-icons";
import { Link } from "react-router-dom";
import { useState } from "react";
import type { OccurrenceDetail } from "../api/issue";

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

function Facts({ fields }: { fields: [string, React.ReactNode][] }) {
  const present = fields.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (present.length === 0) return <p className="pf-v6-u-color-200">No normalized details recorded.</p>;
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

export function EvidenceBlock({ value, label, hasCopyButton = false }: { value: string; label: string; hasCopyButton?: boolean }) {
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
      }
    >
      <CodeBlockCode>{value}</CodeBlockCode>
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
  children
}: {
  title: string;
  collapsed: boolean;
  children: React.ReactNode;
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  return (
    <section className="occurrence-evidence-section">
      {collapsed ? (
        <ExpandableSection
          toggleTextCollapsed={title}
          toggleTextExpanded={`Hide ${title.toLowerCase()}`}
          isExpanded={isExpanded}
          onToggle={(_event, expanded) => setIsExpanded(expanded)}
        >
          {isExpanded && children}
        </ExpandableSection>
      ) : (
        <>
          <h3>{title}</h3>
          {children}
        </>
      )}
    </section>
  );
}

export function OccurrenceRawEvidence({ occurrence, collapsed = false }: { occurrence: OccurrenceDetail; collapsed?: boolean }) {
  const denial = occurrence.normalized_denial;
  const avcRecords = occurrence.raw_event.audit_records.filter((record) => ["avc", "user_avc"].includes(record.type_name.toLowerCase()));
  return (
    <div className="occurrence-raw-evidence">
      <EvidenceSection title="Normalized details (debug)" collapsed={collapsed}>
        <EvidenceBlock value={jsonText(denial.details)} label={`normalized details for occurrence ${occurrence.id}`} />
      </EvidenceSection>
      <EvidenceSection title="Raw AVC" collapsed={collapsed}>
        {avcRecords.length > 0 ? avcRecords.map((record) => (
          <div key={record.position}>
            <small>#{record.position} · {record.type_name}</small>
            <EvidenceBlock value={record.payload} label={`raw AVC record ${record.position} for occurrence ${occurrence.id}`} />
          </div>
        )) : <p className="pf-v6-u-color-200">No AVC audit record is present.</p>}
      </EvidenceSection>
      <EvidenceSection title="Raw audit records" collapsed={collapsed}>
        {occurrence.raw_event.audit_records.length > 0 ? occurrence.raw_event.audit_records.map((record) => (
          <div key={record.position}>
            <small>#{record.position} · {record.type_name}</small>
            <EvidenceBlock value={record.payload} label={`audit record ${record.position} for occurrence ${occurrence.id}`} />
          </div>
        )) : <p className="pf-v6-u-color-200">No raw audit records are present.</p>}
      </EvidenceSection>
      <EvidenceSection title="Other retained payload" collapsed={collapsed}>
        <Facts fields={[
          ["Audit time", <time dateTime={occurrence.raw_event.audit_timestamp}>{formatUtc(occurrence.raw_event.audit_timestamp)}</time>],
          ["Audit sequence", occurrence.raw_event.audit_sequence],
          ["Boot ID", <code>{occurrence.raw_event.boot_id}</code>],
          ["Completion", occurrence.raw_event.completion_reason],
          ["Evidence digest", <CopyEvidence value={occurrence.raw_event.evidence_digest} label={`evidence digest for occurrence ${occurrence.id}`} />]
        ]} />
      </EvidenceSection>
    </div>
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
