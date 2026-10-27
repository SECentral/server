import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { IssueAnalysisResponse, IssueDetailResponse, IssueOccurrencesResponse } from "../api/issue";
import { IssueDetail } from "./IssueDetail";

// Finding regressions use their existing API fixtures; the intent contract has
// its own component suite and must not receive an IssueDetailResponse as a mock.
vi.mock("../api/resolution", async (importOriginal) => ({
  ...await importOriginal<typeof import("../api/resolution")>(),
  fetchResolutions: vi.fn(async () => ({ candidates: [], rejected_candidates: [], observed_access: null,
    intent: null, freshness: null, change_plan: null, history: [] }))
}));

const RAW_AVC = '<script>alert("avc")</script> type=AVC scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:user_home_t:s0';
type Scenario = "001" | "002" | "003" | "004" | "005" | "basename" | "missing-observation" | "repeated" | "fleet-live";

function conditionalDiagnosis(scenario: "002" | "003" | "005") {
  const execute = scenario === "005";
  const bind = scenario === "003";
  const operation = execute ? "execute" : bind ? "name_bind" : "name_connect";
  const targetType = execute ? "httpd_sys_content_t" : "unreserved_port_t";
  const condition = bind ? "nis_enabled" : execute ? "httpd_builtin_scripting && httpd_unified && httpd_enable_cgi" : "httpd_can_network_connect";
  const booleans = bind ? [{ name: "nis_enabled", current: false, status: "observed", description: "Allow system to run with NIS" }] : execute
    ? [{ name: "httpd_builtin_scripting", current: true, status: "observed" }, { name: "httpd_unified", current: false, status: "observed" }, { name: "httpd_enable_cgi", current: true, status: "observed" }]
    : [{ name: "httpd_can_network_connect", current: false, status: "observed", description: "Allow HTTPD scripts and modules to connect to the network using TCP" }];
  const allowRule = bind
    ? "allow nsswitch_domain unreserved_port_t:tcp_socket name_bind; [ nis_enabled ]:True"
    : execute
      ? "allow httpd_t httpdcontent:file { execute execute_no_trans }; [ ( httpd_builtin_scripting && httpd_unified && httpd_enable_cgi ) ]:True"
      : "allow httpd_t port_type:tcp_socket name_connect; [ httpd_can_network_connect ]:True";
  const path = execute ? "/var/www/cgi-bin/secentral-s005-helper.sh" : undefined;
  return {
    kind: "conditional_allow_inactive",
    title: execute ? "SELinux blocked an execution request" : bind ? "SELinux blocked a local port bind request" : "SELinux blocked a network connection request",
    operation,
    enforcement_mode: "enforcing",
    syscall_failed: true,
    source_domain: execute || !bind ? "httpd_t" : "httpd_t",
    process_command: "httpd",
    executable: "/usr/sbin/httpd",
    target_type: targetType,
    target_class: execute ? "file" : "tcp_socket",
    policy_identity: "sha256:fixture-policy-identity",
    checkpoint_observed_at: "2026-09-30T16:26:00Z",
    permissions: [operation],
    ...(bind ? { bind_port: "12345" } : !execute ? { destination_port: "12345" } : {}),
    ...(path ? { path } : {}),
    lead: execute
      ? "SELinux blocked execute on the recorded helper. A matching conditional allow path was inactive in the correlated host state."
      : `SELinux blocked ${bind ? "a local port bind" : "a network connection"} on TCP/12345. A matching allow path exists, but its condition was inactive in the correlated host state.`,
    interpretation: "An inactive conditional allow is consistent with and may explain this denial.",
    limitation: execute
      ? "The denial does not establish that a domain transition was attempted or intended."
      : "Whether this workload should have this network capability is a workload and security decision.",
    next_step: execute ? "Confirm whether this workload is expected to execute this file." : `Confirm whether this workload is expected to ${bind ? "bind" : "connect to"} TCP port 12345; review the rule scope before changing policy state.`,
    conditional_rules: [{ rule: allowRule, expression: condition, state: "inactive" }],
    condition_boolean_states: bind || execute
      ? [{ rule: allowRule, expression: condition, state: "inactive", booleans }]
      : [
          { rule: allowRule, expression: "httpd_can_network_connect", state: "inactive", booleans },
           { rule: "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True", expression: "nis_enabled", state: "inactive", booleans: [{ name: "nis_enabled", current: false, status: "observed", description: "Allow system to run with NIS" }] }
        ],
    ...(scenario === "002" ? { conditional_rules: [
      { rule: allowRule, expression: "httpd_can_network_connect", state: "inactive" },
       { rule: "allow nsswitch_domain unreserved_port_t:tcp_socket name_connect; [ nis_enabled ]:True", expression: "nis_enabled", state: "inactive" }
    ] } : {}),
    evidence: [
      { fact: execute ? `httpd_t attempted to execute ${path}, labeled ${targetType}.` : `httpd_t attempted ${operation} on ${targetType}:tcp_socket at TCP port 12345.`, basis: "avc_record", certainty: "observed" },
      { fact: "A matching conditional allow exists, but its condition evaluated inactive in the correlated host state.", basis: "policy_fact", certainty: "derived" }
    ],
    occurrence_id: 101,
    host_id: 10
  };
}

function diagnosisFor(scenario: Scenario) {
  if (scenario === "basename" || scenario === "missing-observation") return null;
  if (scenario === "002" || scenario === "003" || scenario === "005") return conditionalDiagnosis(scenario);
  if (scenario === "fleet-live") {
    return {
      kind: "no_matching_allow",
      title: "No matching SELinux allow was found for this access",
      lead: "A runcon attempt in the httpd_t domain was denied entrypoint access to /usr/bin/id. The evaluated policy has no matching allow for this permission.",
      interpretation: "The denial is about entrypoint access; it does not prove which destination domain was intended.",
      next_step: "Confirm whether this command is expected to start /usr/bin/id under the observed confined service context.",
      limitation: "The AVC does not establish the intended domain transition or authorize custom policy.",
      source_domain: "httpd_t", target_type: "bin_t", target_class: "file", permissions: ["entrypoint"],
      enforcement_mode: "enforcing", syscall_failed: true,
      process_command: "runcon", executable: "/usr/bin/runcon", path: "/usr/bin/id",
      occurrence_id: 26632, host_id: 1139,
      policy_identity: "sha256:646dfbc98b55dba4e8622f4fbb1b23cb5e0c2c133144361d05cbc2a0c6cd2cff",
      checkpoint_observed_at: "2026-09-30T09:43:22.366Z",
      evaluations: [{ result: "no_matching_allow", permissions: ["entrypoint"], policy_identity: "sha256:646dfbc98b55dba4e8622f4fbb1b23cb5e0c2c133144361d05cbc2a0c6cd2cff", matching_rules: [] }]
    };
  }
  if (scenario === "004") {
    return {
      kind: "no_matching_allow",
      title: "No matching SELinux allow was found for this access",
      lead: "The SELinux domain mysqld_t was denied getattr access to a file labeled var_t. SECentral found no matching allow for the denied getattr access in the evaluated policy.",
      finding: "No matching allow was found for the observed denied permission.",
      interpretation: "This establishes a policy fact; it does not establish why this workload should or should not receive access.",
      next_step: "Confirm the object path and workload configuration before investigating the access requirement.",
      limitation: "The evidence does not establish the intended data path or expected label, or that custom policy is required.",
      source_domain: "mysqld_t", target_type: "var_t", target_class: "file", permissions: ["getattr"], occurrence_id: 104, host_id: 10,
      enforcement_mode: "enforcing", syscall_failed: true,
      process_command: "mariadbd", executable: "/usr/libexec/mariadbd",
      policy_identity: "sha256:84f172fa356f", checkpoint_observed_at: "2026-09-17T11:14:30Z",
      evaluations: [{ result: "no_matching_allow", permissions: ["getattr"], policy_identity: "sha256:84f172fa356f", matching_rules: [] }]
    };
  }
  return {
    kind: "file_context_mismatch",
    title: "Potential file-context mismatch",
    lead: "At AVC time, SELinux recorded the denied object as user_home_t. At a later inspection, matchpathcon resolved this path as httpd_sys_content_t.",
    interpretation: "The difference may help explain the denial; the inspection does not prove the earlier configuration or workload intent.",
    next_step: "Confirm that this path and expected label are appropriate for the workload before considering a labeling change.",
    limitation: "Expected context was inspected after the AVC; this does not prove it was the same at AVC time or that this label is appropriate for the workload.",
    path: "/var/www/html/secentral-test.html", observed_type: "user_home_t", expected_type: "httpd_sys_content_t",
    observed_context: "unconfined_u:object_r:user_home_t:s0", expected_context: "system_u:object_r:httpd_sys_content_t:s0",
    process_command: "httpd", executable: "/usr/sbin/httpd",
    file_type: "file", expected_context_observed_at: "2026-09-30T16:26:25.861462Z", occurrence_id: 101, host_id: 10,
    evidence: [
      { fact: "At AVC time, SELinux recorded the denied object as user_home_t.", basis: "avc_record", certainty: "observed" },
      { fact: "At inspection time, matchpathcon resolved this absolute path as httpd_sys_content_t.", basis: "expected_context_observation", certainty: "observed" }
    ]
  };
}

function detailPayload(scenario: Scenario, status: "open" | "resolved" | "ignored" = "open"): IssueDetailResponse {
  const database = scenario === "004";
  const port = scenario === "002" || scenario === "003";
  const execution = scenario === "005";
  const basename = scenario === "basename";
  const fleetLive = scenario === "fleet-live";
  const issueDiagnosis = diagnosisFor(scenario);
  const issue = {
    id: fleetLive ? 1932 : 7, organization_id: 1, status, display_status: status, disposition: "unclassified",
    resolved_at: null, ignored_at: null, reopened_at: null, regressions_count: 0,
    fingerprint_version: 3, fingerprint_digest: "issue-digest",
    source_type: database ? "mysqld_t" : "httpd_t",
    target_type: fleetLive ? "bin_t" : database ? "var_t" : port ? "unreserved_port_t" : execution ? "httpd_sys_content_t" : "user_home_t",
    target_class: port ? "tcp_socket" : "file",
    permissions: [fleetLive ? "entrypoint" : scenario === "002" ? "name_connect" : scenario === "003" ? "name_bind" : scenario === "004" ? "getattr" : scenario === "005" ? "execute" : "read"],
    first_seen_at: fleetLive ? "2026-09-30T09:46:04.740Z" : "2026-09-25T09:00:00Z",
    last_seen_at: fleetLive ? "2026-09-30T11:52:17.234Z" : "2026-09-30T16:26:25Z",
    occurrences_count: fleetLive ? 16 : scenario === "repeated" ? 5 : 2, affected_hosts: fleetLive ? 3 : 1, disposition_history: [], signatures: []
  } as IssueDetailResponse["issue"];
  issue.signatures = [{ id: 11, fingerprint_version: 3, fingerprint_digest: "signature-digest", permissions: issue.permissions,
    status, disposition: "unclassified", legacy: false, occurrences_count: issue.occurrences_count, affected_hosts: issue.affected_hosts,
    first_seen_at: issue.first_seen_at, last_seen_at: issue.last_seen_at }];
  return {
    issue,
    intelligence: {
      affected_hosts: fleetLive ? 3 : 1,
      paths: fleetLive ? ["/usr/bin/id", "/usr/bin/stat"] : basename ? [] : database ? ["/srv/secentral-s004-mariadb/ibdata1"] : execution ? ["/var/www/cgi-bin/secentral-s005-helper.sh"] : port ? [] : scenario === "missing-observation" ? ["/var/www/html/secentral-test.html"] : ["/var/www/html/secentral-test.html"],
      names: basename ? ["secentral-s001-basename-20260930"] : scenario === "missing-observation" ? [] : [],
      occurrence_time: {}, fleet: fleetLive ? { activity_hosts: 4, current_configuration_hosts: 4, hosts_with_occurrence: 3, hosts_without_occurrence: 1 } : { activity_hosts: 1, current_configuration_hosts: 1, hosts_with_occurrence: 1, hosts_without_occurrence: 0 }
    },
    diagnosis: issueDiagnosis as IssueDetailResponse["diagnosis"],
    host_explanations: (fleetLive ? [
      { host_id: 1139, hostname: "secentral-alma-9-clean", status: "agreement", diagnosis: issueDiagnosis, occurrence_count: 11, unexplained_occurrence_count: 0, additional_diagnosis_group_count: 0, diagnosis_groups: [{ status: "diagnosed", count: 11, diagnosis: issueDiagnosis, sample_occurrence_ids: [26632, 26635, 26636], policy_identity_count: 1, policy_provenance: [{ policy_identity: "sha256:646dfbc98b55dba4e8622f4fbb1b23cb5e0c2c133144361d05cbc2a0c6cd2cff", checkpoint_observed_at: "2026-09-30T09:43:22.366Z", occurrence_id: 26632 }], additional_policy_identity_count: 0 }] },
      { host_id: 1140, hostname: "secentral-alma9-test", status: "agreement", diagnosis: { ...issueDiagnosis, host_id: 1140, occurrence_id: 26633, policy_identity: "sha256:2d37c82b29f7a3e10bad5f0eaf43db0a0e4011dcf6e0dd06e95bf3d4a83c64dd", checkpoint_observed_at: "2026-09-30T09:44:06.856Z" }, occurrence_count: 1, unexplained_occurrence_count: 0, additional_diagnosis_group_count: 0, diagnosis_groups: [{ status: "diagnosed", count: 1, diagnosis: { ...issueDiagnosis, host_id: 1140, occurrence_id: 26633, policy_identity: "sha256:2d37c82b29f7a3e10bad5f0eaf43db0a0e4011dcf6e0dd06e95bf3d4a83c64dd", checkpoint_observed_at: "2026-09-30T09:44:06.856Z" }, sample_occurrence_ids: [26633], policy_identity_count: 1, policy_provenance: [{ policy_identity: "sha256:2d37c82b29f7a3e10bad5f0eaf43db0a0e4011dcf6e0dd06e95bf3d4a83c64dd", checkpoint_observed_at: "2026-09-30T09:44:06.856Z", occurrence_id: 26633 }], additional_policy_identity_count: 0 }] },
      { host_id: 1138, hostname: "secentral-agent-test", status: "agreement", diagnosis: { ...issueDiagnosis, host_id: 1138, occurrence_id: 26634, policy_identity: "sha256:6029a986a50695a29f9929d6b7ef3cc44f7de4e474bc9383dd647a8102fe6837", checkpoint_observed_at: "2026-09-30T09:44:46.489Z" }, occurrence_count: 4, unexplained_occurrence_count: 0, additional_diagnosis_group_count: 0, diagnosis_groups: [{
        status: "diagnosed", count: 4, diagnosis: { ...issueDiagnosis, host_id: 1138, occurrence_id: 26634, policy_identity: "sha256:6029a986a50695a29f9929d6b7ef3cc44f7de4e474bc9383dd647a8102fe6837", checkpoint_observed_at: "2026-09-30T09:44:46.489Z" },
        sample_occurrence_ids: [26634, 26658, 26659], policy_identity_count: 2, policy_provenance: [
          { policy_identity: "sha256:6029a986a50695a29f9929d6b7ef3cc44f7de4e474bc9383dd647a8102fe6837", checkpoint_observed_at: "2026-09-30T09:44:46.489Z", occurrence_id: 26634 },
          { policy_identity: "sha256:96604a2266033413e03164e737f7114a78e284684752af997e9250769de314e7", checkpoint_observed_at: "2026-09-30T11:50:29.274Z", occurrence_id: 26658 }
        ], additional_policy_identity_count: 0
      }] }
    ] : [{
      host_id: 10,
      hostname: "secentral-agent-test",
      status: issueDiagnosis ? "agreement" : "insufficient_evidence",
      diagnosis: issueDiagnosis as IssueDetailResponse["diagnosis"],
      occurrence_count: 1,
      unexplained_occurrence_count: issueDiagnosis ? 0 : 1,
      additional_diagnosis_group_count: 0,
      diagnosis_groups: [{ status: issueDiagnosis ? "diagnosed" : "insufficient_evidence", count: 1, diagnosis: issueDiagnosis, sample_occurrence_ids: [101], policy_identity_count: 0, policy_provenance: [], additional_policy_identity_count: 0 }]
    }]) as unknown as IssueDetailResponse["host_explanations"],
    fleet_explanation: { state: issueDiagnosis ? "consistent" : "insufficient_evidence", affected_host_count: fleetLive ? 3 : 1, host_status_counts: fleetLive ? { agreement: 3 } : {} },
    policy_analysis: { status: scenario === "basename" ? "pending" : "evaluated", limitations: scenario === "basename" ? ["policy evaluation is pending"] : [] },
    triage: { signals: [], windows: {}, evaluated_at: "2026-09-30T16:30:00Z" }
  };
}

function occurrencePage(scenario: Scenario): IssueOccurrencesResponse {
  const db = scenario === "004";
  const tcp = scenario === "002" || scenario === "003";
  const exec = scenario === "005";
  const basename = scenario === "basename";
  const permission = scenario === "002" ? "name_connect" : scenario === "003" ? "name_bind" : scenario === "004" ? "getattr" : scenario === "005" ? "execute" : "read";
  const path = db ? "/srv/secentral-s004-mariadb/ibdata1" : exec ? "/var/www/cgi-bin/secentral-s005-helper.sh" : basename ? null : "/var/www/html/secentral-test.html";
  const count = (scenario as string) === "repeated" ? 5 : 1;
  return {
    occurrences: Array.from({ length: count }, (_, index) => {
      const id = 101 + index;
      const targetType = db ? "var_t" : tcp ? "unreserved_port_t" : exec ? "httpd_sys_content_t" : "user_home_t";
      const targetClass = tcp ? "tcp_socket" : "file";
      const context = `unconfined_u:object_r:${targetType}:s0`;
      return {
        id,
        host: { id: 10, hostname: "secentral-agent-test" },
        occurred_at: `2026-09-30T16:26:${String(25 + index).padStart(2, "0")}Z`,
        normalized_denial: {
          status: "ok", source_type: db ? "mysqld_t" : "httpd_t", target_type: targetType,
          target_class: targetClass, permissions: [permission], target_paths: path ? [path] : [],
          source_context: `system_u:system_r:${db ? "mysqld_t" : "httpd_t"}:s0`, target_context: context,
          command: db ? "mariadbd" : "httpd", executable: db ? "/usr/libexec/mariadbd" : "/usr/sbin/httpd",
          details: {
            enforcement_mode: "enforcing", permissive: false,
            target_evidence: { filesystem_paths: path ? [path] : [], object_names: basename ? ["secentral-s001-basename-20260930"] : [] },
            network_evidence: tcp ? { dport_fields: ["12345"], bind_port_fields: ["12345"], proto_fields: ["tcp"] } : {},
            syscall_evidence: [{ syscall: exec ? "execve" : "openat", success: "no", exit: "-13" }],
            policy_evaluations: scenario === "004" ? [{ result: "no_match", permissions: ["getattr"], matching_rules: [] }] : []
          }
        },
        raw_event: {
          id: 500 + id, audit_timestamp: `2026-09-30T16:26:${String(25 + index).padStart(2, "0")}Z`,
          audit_sequence: 48874 + index, boot_id: "boot-accepted-scenario", category: "avc", transition_type: null,
          completion_reason: "eoe", evidence_digest: `digest-${id}`,
          audit_records: [{ position: 0, record_type: 1400, type_name: "avc", audit_timestamp: "2026-09-30T16:26:25Z", sequence: 48874 + index, payload: RAW_AVC }]
        },
        guidance: {
          summary: "Investigation checks based on retained evidence; no diagnosis is implied.", observations: [],
          checks: basename ? [{ check: "identify_object", reason: "Identify the complete object before path-specific checks.", command: null }] : [],
          missing_evidence: basename ? ["complete absolute target path from retained audit evidence; expected-context lookup was not run"] : [],
          historical_limitations: ["Current host labels and policy may differ from the state at occurrence time."]
        }
      };
    }),
    meta: { next_cursor: null }
  } as IssueOccurrencesResponse;
}

function analysisPayload(scenario: Scenario, disagreement = false): IssueAnalysisResponse {
  const diagnosis = diagnosisFor(scenario);
  const hostDiagnosis = diagnosis ? {
    kind: diagnosis.kind, title: diagnosis.title, interpretation: diagnosis.interpretation,
    next_step: diagnosis.next_step, limitation: diagnosis.limitation, occurrence_id: 101
  } : null;
  const payload = {
    host_explanations: [{
      host_id: 10, hostname: "secentral-agent-test", status: disagreement ? "disagreement" : diagnosis ? "agreement" : "insufficient_evidence",
      diagnosis: disagreement ? null : hostDiagnosis,
      occurrence_diagnoses: disagreement
        ? [
            { occurrence_id: 101, host_id: 10, status: "diagnosed", diagnosis: { kind: "no_matching_allow", title: "No matching SELinux allow was found" } },
            { occurrence_id: 102, host_id: 10, status: "diagnosed", diagnosis: { kind: "conditional_allow_inactive", title: "Conditional allow was inactive" } },
            { occurrence_id: 103, host_id: 10, status: "insufficient_evidence", diagnosis: null }
          ]
        : [{ occurrence_id: 101, host_id: 10, status: diagnosis ? "diagnosed" : "insufficient_evidence", diagnosis: hostDiagnosis }]
    }],
    fleet_explanation: {
      state: disagreement ? "disagreement" : diagnosis ? "consistent" : "insufficient_evidence",
      affected_host_count: 1, host_status_counts: { agreement: diagnosis ? 1 : 0 },
      explanation_groups: [], disagreeing_hosts: [], insufficient_evidence_hosts: []
    },
    hypotheses: [],
    supporting_evidence: {
      explanation: { policy_analysis: { status: scenario === "basename" ? "pending" : scenario === "missing-observation" ? "evaluated" : "evaluated", limitations: scenario === "basename" ? ["policy_evaluation_pending"] : [] } },
      file_contexts: { expected_context_observations: [] }
    }
  };
  return payload as unknown as IssueAnalysisResponse;
}

function response(status: number, body: unknown): Response {
  return { ok: status >= 200 && status < 300, status, statusText: "", headers: new Headers(), json: async () => body } as unknown as Response;
}

function detailResponse(url: string, payload: IssueDetailResponse): Response {
  if (/\/occurrences\?view=/.test(url)) return response(200, { occurrences: [], meta: { page: 1, page_size: 10, total: 0, total_pages: 1 } });
  return response(200, payload);
}

function mockApi(fetchMock: ReturnType<typeof vi.fn>, scenario: Scenario, options: { status?: "open" | "resolved" | "ignored" } = {}) {
  let currentStatus = options.status ?? "open";
  const issueId = scenario === "fleet-live" ? 1932 : 7;
  fetchMock.mockImplementation((url: string, request?: { method?: string; body?: string }) => {
    const method = request?.method ?? "GET";
    if (url === `/api/v1/issues/${issueId}` && method === "GET") return Promise.resolve(response(200, detailPayload(scenario, currentStatus)));
    if (url === `/api/v1/issues/${issueId}/status` && method === "PATCH") {
      currentStatus = JSON.parse(request?.body ?? "{}").status;
      return Promise.resolve(response(200, detailPayload(scenario, currentStatus).issue));
    }
    if (url === `/api/v1/issues/${issueId}/disposition` && method === "PATCH") return Promise.resolve(response(200, detailPayload(scenario, currentStatus).issue));
    if (/view=(summary|activity)/.test(url)) {
      const occurrences = occurrencePage(scenario).occurrences;
      return Promise.resolve(response(200, { occurrences: occurrences.map((item) => {
        const syscalls: { success?: unknown }[] = Array.isArray(item.normalized_denial.details.syscall_evidence) ? item.normalized_denial.details.syscall_evidence as { success?: unknown }[] : [];
        const syscall_outcome = syscalls.some((syscall) => ["no", "false", "0"].includes(String(syscall.success))) ? "failed"
          : syscalls.length > 0 && syscalls.every((syscall) => ["yes", "true", "1"].includes(String(syscall.success))) ? "succeeded" : "unknown";
        return { id: item.id, occurred_at: item.occurred_at, host: item.host, resource: item.normalized_denial.target_paths[0] ?? "secentral-test.html", absolute_path: item.normalized_denial.target_paths.length > 0, target_type: item.normalized_denial.target_type, permissions: item.normalized_denial.permissions, enforcement_mode: item.normalized_denial.details.enforcement_mode, syscall_outcome };
      }), meta: { page: 1, page_size: 10, total: occurrences.length, total_pages: 1 } }));
    }
    if (url.startsWith(`/api/v1/issues/${issueId}/occurrences/`)) {
      const occurrence = occurrencePage(scenario).occurrences.find((item) => url.endsWith(`/${item.id}`));
      return Promise.resolve(occurrence ? response(200, occurrence) : response(404, { error: { message: "Occurrence not retained in this fixture" } }));
    }
    if (url.startsWith(`/api/v1/issues/${issueId}/occurrences`)) return Promise.resolve(response(200, occurrencePage(scenario)));
    if (url === `/api/v1/issues/${issueId}/analysis`) return Promise.resolve(response(200, analysisPayload(scenario)));
    if (url === "/api/v1/issues/999") return Promise.resolve(response(404, { error: { code: "not_found", message: "Resource not found" } }));
    return Promise.reject(new Error(`unexpected url ${url}`));
  });
}

function renderDetail(initialEntry = "/issues/7") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[initialEntry]}><Routes><Route path="/issues/:id" element={<IssueDetail />} /></Routes></MemoryRouter></QueryClientProvider>);
}

describe("issue investigation", () => {
  it.each([
    ["read", "file", "single", "SELinux recorded httpd requesting read access to /srv/data."],
    ["write", "file", "single", "SELinux recorded httpd requesting write access to /srv/data."],
    ["open", "file", "single", "SELinux recorded httpd requesting open access to /srv/data."],
    ["read", "file", "names", "SELinux recorded httpd requesting read access to files labeled user_home_t."],
    ["write", "file", "paths", "SELinux recorded httpd requesting file write access to file objects labeled user_home_t."],
    ["name_connect", "tcp_socket", "ports", "SELinux recorded httpd requesting outbound TCP connection access."],
    ["name_bind", "tcp_socket", "ports", "SELinux recorded httpd requesting local TCP bind access on ports 8080, 8081."],
    ["read", "file", "signatures", "SELinux recorded httpd_t access requests to file objects labeled user_home_t"]
  ])("describes non-enforced %s AVCs with successful syscalls as observations (%s, %s)", async (permission, targetClass, grouping, headline) => {
    const payload = detailPayload("001");
    payload.diagnosis = null;
    payload.issue.permissions = [permission];
    payload.issue.target_class = targetClass;
    const count = grouping === "single" ? 1 : 2;
    payload.issue.occurrences_count = count;
    if (grouping === "signatures") payload.issue.signatures.push({ ...payload.issue.signatures[0], id: 12, permissions: ["open"] });
    payload.intelligence.paths = ["/srv/data"];
    payload.intelligence.resource_summary = { process_command: "httpd", path_count: grouping === "paths" ? 2 : 1,
      name_count: grouping === "names" ? 2 : 0, absolute_path_occurrences: 1, without_absolute_path_occurrences: 0,
      ...(grouping === "ports" ? permission === "name_bind" ? { bind_port_count: 2, bind_ports: [{ port: "8080", occurrence_count: 1 }, { port: "8081", occurrence_count: 1 }] } : { destination_port_count: 2 } : {}) };
    payload.issue.observations = { occurrences: count, audit_events: count, modes: { permissive: count },
      syscall_outcomes: { failed: 0, succeeded: count, unknown: 0 } };
    payload.intelligence.observation_summary = [{ host_id: 10, hostname: "web-1", ...payload.issue.observations }];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading).toHaveTextContent(headline);
    expect(heading).not.toHaveTextContent(/denied|blocked|failed|could not/i);
    expect(screen.getByRole("region", { name: "Recorded outcomes" })).toHaveTextContent(`Associated syscalls by event: 0 failed · ${count} succeeded · 0 unknown`);
  });

  function capabilityPayload() {
    const payload = detailPayload("basename");
    payload.issue.target_class = "capability";
    payload.issue.target_type = "httpd_t";
    payload.issue.permissions = ["net_admin"];
    payload.intelligence.names = [];
    payload.intelligence.resource_summary = { process_command: "httpd", path_count: 0, name_count: 0, absolute_path_occurrences: 0, without_absolute_path_occurrences: 0 };
    payload.policy_analysis = { status: "unavailable", limitations: ["exact policy identity is unavailable"] };
    payload.findings = [];
    payload.host_explanations[0].occurrence_count = 2;
    payload.host_explanations[0].unexplained_occurrence_count = 2;
    payload.host_explanations[0].diagnosis_groups[0].count = 2;
    payload.triage.signals = [{ code: "new_issue", label: "New issue", explanation: "This issue was first observed within the last 7 days.", evidence: {}, temporal_scope: "retained_occurrence_history" }];
    payload.operator_guidance = {
      source: { occurrence_id: 101, host_id: 10, hostname: "web-1", occurred_at: "2026-10-22T17:40:36Z", path: null, observed_type: "httpd_t", object_class: "capability" },
      capability: { explanation: "Linux capabilities are individual administrator privileges. net_admin includes privileged socket settings.", outcome: "SELinux recorded the request in permissive mode; the associated system call succeeded.", evidence: "The recorded x86-64 setsockopt call selected SO_SNDBUFFORCE.", hypothesis: "The service or a loaded module may be tuning socket buffers." },
      checks: [
        { title: "Review executable logs around the occurrence", command: "journalctl --utc --since '2026-10-22 17:39:36 UTC' --until '2026-10-22 17:41:36 UTC' _EXE=/usr/sbin/httpd", interpretation: "Look for startup or module messages." },
        { title: "Inspect current process contexts", command: "ps -eZ -o label,pid,comm", interpretation: "Compare current processes with the recorded domain." },
        { title: "Inspect current capability policy", command: "sesearch -A -s httpd_t -t httpd_t -c capability -p net_admin", interpretation: "Queries the host's currently loaded policy." }
      ], manual_check: "Review forced send-buffer settings in the service configuration.", possible_fix: "", verification: "Retry the intended request and check the application response under the intended enforcement mode.", verification_limit: "Check the workload result.", restriction: "Keep unwanted access denied."
    };
    payload.resolutions = { candidates: [], rejected_candidates: [], intent: null, freshness: null, history: [], change_plan: null,
      observed_access: { occurrence_id: 101, host_id: 10, hostname: "web-1", actor: "httpd", source_type: "httpd_t", resource: "Resource identity not established", target_type: "httpd_t", object_class: "capability", permissions: ["net_admin"], operation_label: "net_admin", outcome: "DENIED", observed_at: "2026-10-22T17:40:36Z" } };
    return payload;
  }

  it("explains capability requests with scoped investigation without empty disclosures or repeated novelty", async () => {
    const payload = capabilityPayload();
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("SELinux recorded httpd requesting the net_admin capability.");
    const diagnosis = screen.getByRole("region", { name: "Findings" });
    expect(diagnosis).toHaveTextContent("Historical policy analysis unavailable");
    expect(diagnosis).toHaveTextContent("exact SELinux policy identity is unavailable");
    expect(diagnosis).toHaveTextContent("administrator privileges");
    expect(diagnosis).toHaveTextContent("SO_SNDBUFFORCE");
    expect(diagnosis).toHaveTextContent("Investigation hypothesis:");
    expect(diagnosis).toHaveTextContent("permissive mode; the associated system call succeeded");
    expect(diagnosis).not.toHaveTextContent("blocked");
    expect(diagnosis).not.toHaveTextContent("Cause not confirmed; start with the checks below");
    expect(within(diagnosis).getByRole("link", { name: /Inspect capability request/ })).toHaveAttribute("href", expect.stringContaining("evidence_occurrence=101"));
    expect(screen.queryByRole("button", { name: "Retained evidence & analysis availability" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Additional findings & evidence gaps" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Occurrence pattern" })).not.toBeInTheDocument();
    expect(screen.queryByText("2 retained occurrences")).not.toBeInTheDocument();
    expect(screen.queryByText("Resource identity not established")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent("Capability");
    expect(screen.getByRole("complementary", { name: "Investigation context" })).toHaveTextContent("Capabilitynet_admin");
    expect(screen.getByRole("region", { name: "Finding coverage" })).toHaveTextContent("Supported findings: 0 of 2 occurrences");
    const checks = screen.getByRole("region", { name: "Check" });
    expect(within(checks).getByRole("button", { name: "Copy command: ps -eZ -o label,pid,comm" })).toBeVisible();
    expect(within(checks).getByRole("heading", { name: "Verify the workload" })).toBeVisible();
    expect(checks).toHaveTextContent("Review forced send-buffer settings");
    expect(screen.queryByText(/No reviewed change plan yet/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy command:.*(setsebool|restorecon|semanage)/ })).not.toBeInTheDocument();
    await userEvent.setup().click(within(checks).getByRole("button", { name: "Policy inspection" }));
    expect(within(checks).getByRole("button", { name: "Copy command: sesearch -A -s httpd_t -t httpd_t -c capability -p net_admin" })).toBeVisible();
  });

  it("renders capability names and SELinux contexts as code in Diagnosis", async () => {
    const payload = capabilityPayload();
    payload.issue.permissions = ["mac_admin"];
    payload.diagnosis = { ...diagnosisFor("004")!, permissions: ["mac_admin"] } as IssueDetailResponse["diagnosis"];
    payload.operator_guidance!.capability = {
      explanation: "mac_admin is checked for some security-label administration operations.",
      evidence: "The same audit event reports an invalid SELinux context: unconfined_u:object_r:secentral_nonexistent_t:s0."
    };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(within(diagnosis).getAllByText("mac_admin", { selector: "code" })).toHaveLength(2);
    expect(within(diagnosis).getByText("unconfined_u:object_r:secentral_nonexistent_t:s0", { selector: "code" })).toBeVisible();
  });

  it("keeps meaningful occurrence patterns and does not invent a syscall hypothesis when evidence is absent", async () => {
    const payload = capabilityPayload();
    payload.operator_guidance!.capability = { explanation: "Linux capabilities are individual administrator privileges." };
    payload.operator_guidance!.manual_check = "Review the recorded system call and command line.";
    payload.operator_guidance!.verification = "";
    payload.triage.signals.push({ ...payload.triage.signals[0], code: "frequency_increase", label: "Occurrence rate increased", explanation: "Recent rate is twice the baseline." });
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const pattern = await screen.findByRole("button", { name: "Occurrence pattern" });
    await userEvent.setup().click(pattern);
    expect(screen.getByText("Occurrence rate increased:")).toBeVisible();
    expect(screen.queryByText(/This issue was first observed within/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Investigation hypothesis:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/SO_SNDBUFFORCE/)).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Verify the workload" })).not.toBeInTheDocument();
  });

  it.each(["summary", "activity"] as const)("loads capability occurrences immediately in %s view with pagination as the only range display", async (view) => {
    const payload = capabilityPayload();
    const rows = [101, 102].map((id) => ({ id, occurred_at: "2026-10-22T17:40:36Z", host: { id: 10, hostname: "web-1" }, resource: null, absolute_path: false, target_type: "httpd_t", permissions: ["net_admin"] }));
    const fetchMock = vi.fn(async (url: string) => /\/occurrences\?view=/.test(url) ? response(200, {
      occurrences: rows, meta: { page: 1, page_size: 10, total: 2, total_pages: 1 },
      ...(view === "activity" ? { activity_groups: rows.map((row) => ({ occurrence_ids: [row.id], correlated: false, basis: null })), activity_scope: "current_page" } : {})
    }) : detailResponse(url, payload));
    vi.stubGlobal("fetch", fetchMock);
    renderDetail(`/issues/7?occurrence_view=${view}`);
    const table = await screen.findByRole("table", { name: view === "activity" ? "Audit activity" : "Occurrence summary" });
    expect(within(table).getAllByText("Capability: net_admin")).toHaveLength(2);
    expect(within(table).queryByText("Complete path not recorded")).not.toBeInTheDocument();
    expect(within(table).queryByRole("columnheader", { name: "Path evidence" })).not.toBeInTheDocument();
    const list = screen.getByRole("region", { name: "Retained occurrences" });
    expect(within(list).queryByRole("button", { name: "Show recent occurrences" })).not.toBeInTheDocument();
    expect(within(list).queryByRole("button", { name: "Hide occurrences" })).not.toBeInTheDocument();
    expect(list.querySelector("header")?.textContent).toBe("Retained occurrences");
    expect(within(list).getByRole("button", { name: "1 - 2 of 2" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledWith(`/api/v1/issues/7/occurrences?view=${view}&page=1&limit=10`, expect.anything());
  });

  it("keeps a missing-path fallback and path evidence for filesystem occurrences", async () => {
    const payload = detailPayload("missing-observation");
    vi.stubGlobal("fetch", vi.fn(async (url: string) => /\/occurrences\?view=/.test(url) ? response(200, {
      occurrences: [{ id: 101, occurred_at: "2026-10-22T17:40:36Z", host: { id: 10, hostname: "web-1" }, resource: null, absolute_path: false, target_type: "user_home_t", permissions: ["read"] }],
      meta: { page: 1, page_size: 10, total: 1, total_pages: 1 }
    }) : detailResponse(url, payload)));
    renderDetail("/issues/7?occurrence_view=summary");
    const table = await screen.findByRole("table", { name: "Occurrence summary" });
    expect(within(table).getByText("Complete path not recorded")).toBeVisible();
    expect(within(table).getByRole("columnheader", { name: "Path evidence" })).toBeVisible();
    expect(within(table).getByText("Not recorded")).toBeVisible();
  });

  it("shows automatic occurrence-load failures rather than an empty successful list", async () => {
    const payload = capabilityPayload();
    vi.stubGlobal("fetch", vi.fn(async (url: string) => /\/occurrences\?view=/.test(url) ? response(503, { error: { message: "Occurrence service unavailable" } }) : detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByText("Could not load occurrences")).toBeVisible();
    expect(screen.queryByText("No occurrences are retained for this issue.")).not.toBeInTheDocument();
  });
  it("shows related issues as evidence links and compares AVC modes separately from event outcomes", async () => {
    const payload = detailPayload("004");
    payload.fleet_explanation = { ...payload.fleet_explanation, state: "disagreement", affected_host_count: 2 };
    payload.related_activity = [{ issue_id: 31, host_id: 10, hostname: "db-enforcing", occurrence_id: 201,
      source_occurrence_id: 104, occurred_at: "2026-10-22T15:05:36Z", source_occurred_at: "2026-10-22T15:05:36Z",
      target_type: "var_t", target_class: "dir", basis: "same_audit_event" }];
    payload.intelligence.observation_summary = [
      { host_id: 10, hostname: "db-enforcing", occurrences: 4, audit_events: 4, modes: { enforcing: 4 }, syscall_outcomes: { failed: 4 } },
      { host_id: 11, hostname: "db-permissive", occurrences: 6, audit_events: 2, modes: { permissive: 6 }, syscall_outcomes: { succeeded: 2 } }
    ];
    const fetchMock = vi.fn();
    mockApi(fetchMock, "004");
    const original = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation((url: string, request?: { method?: string }) => url === "/api/v1/issues/7" ? Promise.resolve(response(200, payload)) : original(url, request));
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    const related = await screen.findByRole("region", { name: "Related issue activity" });
    expect(within(related).getByRole("link", { name: "Issue #31" })).toHaveAttribute("href", "/issues/31");
    expect(related).toHaveTextContent("Same audit event");
    expect(related).not.toHaveTextContent("not a shared diagnosis, remedy or lifecycle decision");
    const outcomes = screen.getByRole("table", { name: "Host outcome comparison" });
    expect(outcomes).toHaveTextContent("6 occurrences / 2 audit events");
    expect(outcomes).toHaveTextContent("Succeeded: 2");
    expect(outcomes).toHaveTextContent("Failed: 4");
    expect(within(screen.getByRole("region", { name: "Recorded outcomes" })).getByText(/One audit event can contain multiple AVC decisions/)).toBeVisible();
    expect(screen.getByRole("region", { name: "Recorded outcomes" })).toHaveTextContent("not necessarily that the entire host was permissive");
    expect(document.querySelector(".issue-operation-label")).toHaveTextContent(`${payload.issue.occurrences_count} occurrences`);
    expect(screen.getByText("Fleet scope").parentElement).toHaveTextContent("Findings differ between hosts");
    const coverage = await screen.findByRole("region", { name: "Finding coverage" });
    expect(coverage).not.toHaveTextContent("0 occurrences lack a supported finding");
    expect(coverage).not.toHaveTextContent("complete explanation");
    const peerCards = ["Recorded outcomes", "Fleet scope", "Retained occurrences"].map((name) => screen.getByRole("heading", { name, level: 2 }).closest(".pf-v6-c-card"));
    expect(peerCards.every(Boolean)).toBe(true);
    expect(new Set(peerCards).size).toBe(3);
    expect(within(related).getByRole("heading", { name: "Related issue activity", level: 3 })).toBeVisible();
    expect(related.closest(".pf-v6-c-card")).toBe(peerCards[1]);
  });

  it("updates the workbench and fleet table when refreshed issue evidence arrives", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={["/issues/7"]}>
      <Routes><Route path="/issues/:id" element={<IssueDetail />} /></Routes>
    </MemoryRouter></QueryClientProvider>);
    await screen.findByRole("heading", { name: "Findings" });

    const updated = detailPayload("001");
    updated.diagnosis = { ...updated.diagnosis!, title: "Refreshed label diagnosis" };
    updated.host_explanations = updated.host_explanations.map((host) => ({ ...host, hostname: "refreshed-host" }));
    act(() => queryClient.setQueryData(["issue", 7], updated));

    expect(await screen.findByRole("heading", { name: "Refreshed label diagnosis" })).toBeVisible();
    expect(within(screen.getByRole("table", { name: "Finding distribution" })).getByRole("link", { name: "refreshed-host" })).toBeVisible();
  });

  it("consolidates signatures while keeping individual actions and occurrence browsing explicitly scoped", async () => {
    const payload = detailPayload("001");
    const first = payload.issue.signatures[0];
    payload.issue.signatures = [first, { ...first, id: 12, permissions: ["open", "read"] }, { ...first, id: 13, permissions: ["execute"] }];
    payload.issue.permissions = ["execute", "open", "read"];
    const fetchMock = vi.fn(async (url: string, request?: { method?: string; body?: string }) => {
      if (request?.method === "PATCH") {
        const change = JSON.parse(request.body!);
        const signature = payload.issue.signatures.find((item) => item.id === change.signature_ids[0])!;
        if (change.status) signature.status = change.status;
        if (change.disposition) signature.disposition = change.disposition;
        return response(200, payload.issue);
      }
      return response(200, /view=(summary|activity)/.test(url) ? { occurrences: [], meta: { page: 1, page_size: 10, total: 0, total_pages: 1 } } : payload);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    const operations = await screen.findByRole("button", { name: "Denied operations" });
    expect(operations).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("table", { name: "Denied operations" })).not.toBeInTheDocument();
    expect(screen.queryByText(/This relationship groups related evidence/)).not.toBeInTheDocument();
    await user.click(operations);
    const table = screen.getByRole("table", { name: "Denied operations" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("SELinux recorded httpd_t access requests to file objects labeled user_home_t");
    expect(within(table).queryByRole("combobox")).not.toBeInTheDocument();
    await user.click(within(table).getByRole("button", { name: "Review read separately" }));
    const review = screen.getByRole("region", { name: "Review permission set" });
    expect(review).toHaveTextContent("Changes apply only to this permission set");
    expect(review).toHaveTextContent("They do not change SELinux policy or verify a fix");
    await user.selectOptions(within(review).getByLabelText("Operation status"), "ignored");
    expect(fetchMock.mock.calls.some(([, request]) => request?.method === "PATCH")).toBe(false);
    await user.click(within(review).getByRole("button", { name: "Save operation status" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/status", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "ignored", signature_ids: [11] }) })));
    expect(await within(review).findByRole("status")).toHaveTextContent("Status saved for this permission set only");
    expect(within(table).getAllByRole("row")[3]).toHaveTextContent("Open");
    await user.selectOptions(within(review).getByLabelText("Operation assessment"), "under_investigation");
    expect(fetchMock.mock.calls.filter(([, request]) => request?.method === "PATCH")).toHaveLength(1);
    await user.click(within(review).getByRole("button", { name: "Save operation assessment" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/disposition", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ disposition: "under_investigation", signature_ids: [11] }) })));
    expect(await within(review).findByRole("status")).toHaveTextContent("Assessment saved for this permission set only");
    await user.click(within(review).getByRole("button", { name: "Close review" }));
    expect(screen.queryByRole("region", { name: "Review permission set" })).not.toBeInTheDocument();
    await user.click(within(table).getByRole("button", { name: "View open, read signature 12 occurrences" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/occurrences?view=summary&page=1&limit=10&signature_id=12", expect.anything()));
    await user.click(screen.getByRole("button", { name: "Show all operations" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/occurrences?view=summary&page=1&limit=10", expect.anything()));
  });

  it("omits the operation breakdown for a single permission set and retains issue actions", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "003");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("button", { name: "Denied operations" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /policy draft/i })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("policy-drafts"))).toBe(false);
    expect(screen.getByText("Issue status")).toBeVisible();
    expect(screen.getByText("Open", { selector: ".pf-v6-c-label__text" })).toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: /Issue actions/ }));
    expect(screen.getByLabelText("Issue status")).toBeVisible();
    expect(screen.getByLabelText("Operator assessment")).toBeVisible();
  });

  it("keeps an unsuccessful separate review editable and reports the failure", async () => {
    const payload = detailPayload("001");
    payload.issue.signatures.push({ ...payload.issue.signatures[0], id: 12, permissions: ["execute"] });
    const fetchMock = vi.fn(async (url: string, request?: { method?: string }) => request?.method === "PATCH"
      ? response(500, { error: { message: "Could not save review" } }) : detailResponse(url, payload));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    await user.click(await screen.findByRole("button", { name: "Denied operations" }));
    await user.click(screen.getByRole("button", { name: "Review read separately" }));
    await user.selectOptions(screen.getByLabelText("Operation status"), "resolved");
    await user.click(screen.getByRole("button", { name: "Save operation status" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Operation review failed");
    expect(screen.getByLabelText("Operation status")).toHaveValue("resolved");
    expect(screen.getByRole("button", { name: "Save operation status" })).toBeEnabled();
    expect(screen.queryByText("Status saved for this permission set only.")).not.toBeInTheDocument();
  });

  it("does not infer a blocked syscall or an active-policy conclusion from an inactive conditional path", async () => {
    const payload = detailPayload("003");
    payload.diagnosis = { ...payload.diagnosis!, syscall_failed: false, enforcement_mode: "permissive", occurred_at: "2026-09-30T16:26:25Z" };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading).not.toHaveTextContent("blocked");
    const diagnosis = screen.getByRole("region", { name: "Findings" });
    expect(diagnosis).toHaveTextContent("Supporting occurrence recorded at Sep 30, 16:26:25 UTC");
    expect(within(diagnosis).getByRole("heading", { level: 3 })).toHaveTextContent("httpd_t was denied binding TCP/12345");
    expect(within(diagnosis).getByRole("button", { name: "Conditional policy paths" })).toHaveAttribute("aria-expanded", "false");
    expect(diagnosis).not.toHaveTextContent("no active allow rule");
    expect(document.querySelector(".issue-investigation details")).toBeNull();
  });
  it.each(["name_bind", "name_connect"])("explains the port-label conflict for %s instead of leading with a generic policy result", async (operation) => {
    const bind = operation === "name_bind";
    const payload = detailPayload(bind ? "003" : "002");
    const title = `httpd (httpd_t) was denied ${bind ? "binding" : "connecting"} to TCP port 9090`;
    const lead = `The port was labeled websm_port_t. The evaluated policy does not allow httpd_t to ${bind ? "bind to" : "connect to"} ports with that label.`;
    payload.issue.target_type = "websm_port_t";
    payload.diagnosis = {
      kind: "no_matching_allow", title, lead, operation, permissions: [operation], source_domain: "httpd_t",
      target_type: "websm_port_t", target_class: "tcp_socket", occurrence_id: 101, host_id: 10,
      interpretation: "No matching allow explains the observed policy denial, not workload intent.",
      limitation: "No matching allow does not establish a wrong target label or required custom policy.",
      ...(bind ? { bind_port: "9090" } : { destination_port: "9090" }),
      next_step: `Confirm whether httpd is intended to ${bind ? "listen on" : "connect to"} TCP port 9090. If so, check whether the service configuration and SELinux port mapping agree; this does not establish that the port label should change.`
    };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();

    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(within(diagnosis).getByRole("heading", { level: 3 })).toHaveTextContent(title);
    expect(within(diagnosis).getByText(lead)).toBeVisible();
    expect(diagnosis).toHaveTextContent(`intended to ${bind ? "listen on" : "connect to"} TCP port 9090`);
    expect(diagnosis).toHaveTextContent("does not establish that the port label should change");
    expect(diagnosis).not.toHaveTextContent("No matching SELinux allow was found");
    expect(diagnosis).toHaveTextContent("Limitation:");
  });

  it("keeps Diagnosis command-free and identifies unmatched evidence while the active workspace owns inspection", async () => {
    const payload = detailPayload("003");
    payload.operator_guidance = {
      source: { host_id: 10, hostname: "web-1", occurrence_id: 101, occurred_at: "2026-09-30T16:26:25Z", path: null, observed_type: "unreserved_port_t", protocol: "tcp", port: 12345, operation: "name_bind" },
      checks: [
        { title: "Listener", command: "ss -ltnp", interpretation: "Confirm listener ownership" },
        { title: "Effective mappings", command: "semanage port -l", interpretation: "Inspect ranges" },
        { title: "Local mappings", command: "semanage port -l -C", interpretation: "Inspect overrides" }
      ], manual_check: "Confirm intended service", possible_fix: "Compare configurations", verification: "Retry the actual workload", verification_limit: "Silence is not success", restriction: "Keep unwanted access denied"
    };
    payload.resolutions = { candidates: [], rejected_candidates: [], observed_access: null, intent: null, freshness: null, change_plan: null, history: [],
      port_investigations: [12345, 23451].map((port, index) => ({ host_id: 10, hostname: "web-1", occurrence_id: index ? 202 : 101, protocol: "tcp", port,
        operation: "name_bind", observed_type: "unreserved_port_t", occurrence_count: index ? 5 : 1, state: "blocked", reason: "Inspect intent before any change", types: [], type_count: 0 })) };
    const occurrence = occurrencePage("003").occurrences[0];
    occurrence.id = 202;
    occurrence.guidance!.checks = [
      { reason: "Effective classification", command: "semanage port -l", expected: "Check intersecting ranges" },
      { reason: "Local overrides", command: "semanage port -l -C", expected: "Check prior state" },
      { reason: "Listener ownership", command: "ss -ltnp 'sport = :23451'", expected: "Check intended owner" }
    ];
    const primaryOccurrence = { ...occurrence, id: 101, guidance: { ...occurrence.guidance!, checks: payload.operator_guidance.checks.map((check) => ({ reason: check.title, command: check.command, expected: check.interpretation })) } };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/occurrences/202") ? response(200, occurrence) : url.endsWith("/occurrences/101") ? response(200, primaryOccurrence) : detailResponse(url, payload)));
    const user = userEvent.setup();
    renderDetail();
    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(within(diagnosis).queryByRole("button", { name: /Copy/ })).not.toBeInTheDocument();
    expect(await screen.findAllByRole("button", { name: "Copy command: semanage port -l" })).toHaveLength(1);
    await user.click(screen.getByRole("tab", { name: /TCP\/23451/ }));
    expect(await screen.findByRole("button", { name: "Copy command: ss -ltnp 'sport = :23451'" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Copy command: ss -ltnp" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Copy command: semanage port -l" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Copy command: semanage port -l -C" })).toHaveLength(1);
    expect(await screen.findByRole("region", { name: "Observed access" })).toHaveTextContent("TCP/23451");
    const context = await screen.findByRole("complementary", { name: "Investigation context" });
    expect(context).toHaveTextContent("TCP/23451");
    expect(within(context).getByRole("link", { name: "#202" })).toHaveAttribute("href", "/hosts/10/occurrences/202");
    expect(screen.queryByRole("heading", { name: "Verify the investigation example" })).not.toBeInTheDocument();
    expect(diagnosis).toHaveTextContent("Inspection uses a different retained example");
    expect(within(diagnosis).getAllByRole("link", { name: /occurrence #101/ }).some((link) => link.getAttribute("href") === "/hosts/10/occurrences/101")).toBe(true);
    expect(within(diagnosis).queryByRole("button", { name: /Copy/ })).not.toBeInTheDocument();
  });

  it("uses complete bind summaries for identity and keeps finding coverage distinct from endpoint totals", async () => {
    const payload = detailPayload("003");
    payload.issue.occurrences_count = 6;
    payload.intelligence.resource_summary = { absolute_path_occurrences: 0, without_absolute_path_occurrences: 6,
      name_count: 0, path_count: 0, process_command: "httpd", bind_port_count: 2,
      bind_ports: [{ port: "23451", occurrence_count: 4 }, { port: "12345", occurrence_count: 2 }] };
    payload.findings = [{ diagnosis: payload.diagnosis!, occurrence_count: 1, observation_count: 0 }];
    payload.finding_coverage = { conditional_allow_inactive: 4, unexplained: 2 };
    payload.resolutions = { candidates: [], rejected_candidates: [], observed_access: null, intent: null, freshness: null, change_plan: null, history: [] };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByRole("heading", { level: 1 })).toHaveTextContent("recorded httpd requesting local TCP bind access on ports 23451, 12345");
    const scope = screen.getByRole("region", { name: "Finding coverage" });
    expect(scope).toHaveTextContent("Supported findings: 4 of 6 occurrences");
    expect(scope).toHaveTextContent("2 occurrences lack a supported finding");
    expect(scope).not.toHaveTextContent("Finding coverage does not establish resource identity, workload intent or a verified root cause.");
    expect(scope).toHaveTextContent("Displayed finding: 1");
    await userEvent.setup().hover(within(scope).getByText("Supported findings: 4 of 6 occurrences"));
    expect(await screen.findByRole("tooltip")).toHaveTextContent("not verified root causes or confirmed remediation");
  });
  function labelingPayload() {
    const payload = detailPayload("missing-observation");
    payload.triage_guidance = {
      type: "probable_label_mismatch", title: "Investigation lead: probable label mismatch", path: "/var/www/html/a file.txt",
      observed_type: "user_home_t", conventional_type: "httpd_sys_content_t",
      path_count: 2, recursive_path_count: 2, recursive_directory: "/var/www/html",
      summary: "Files under /var/www/ commonly use httpd_sys_content_t. Files moved from a home directory may retain user_home_t.",
      commands: [
        { action: "inspect", label: "Check the configured label", command: "matchpathcon -- '/var/www/html/a file.txt'" },
        { action: "restore_targeted", label: "Restore this file's configured context", command: "restorecon -v -- '/var/www/html/a file.txt'" },
        { action: "restore_recursive", label: "Alternatively, restore contexts recursively in the parent directory", command: "restorecon -Rv -- /var/www/html" }
      ]
    };
    payload.operator_guidance = {
      source: { occurrence_id: 101, host_id: 10, hostname: "web-1", occurred_at: "2026-09-30T16:26:25Z", path: "/var/www/html/a file.txt", observed_type: "user_home_t" },
      checks: [
        { title: "Current object label", command: "ls -ldZ -- '/var/www/html/a file.txt'", interpretation: "Read current context; local results are not collected." },
        { title: "Host-configured context", command: "matchpathcon -- '/var/www/html/a file.txt'", interpretation: "The third colon-separated field is the type." },
        { title: "Read-only restoration preview", command: "restorecon -n -v -- '/var/www/html/a file.txt'", interpretation: "If labels agree restoration may do nothing; if lookup fails investigate configuration." }
      ],
      manual_check: "Confirm the intended file on the affected host.", possible_fix: "Only restore suitable configured labels.",
      verification: "Retry the intended content request and check expected output.",
      verification_limit: "No new AVCs alone prove neither workload success nor safety; check permissiveness and delivery health.",
      restriction: "Keep unwanted access denied; verify legitimate work still succeeds."
    };
    return payload;
  }

  it("keeps a labeling inspection resource ahead of a Boolean finding from another host", async () => {
    const payload = labelingPayload();
    payload.operator_guidance!.source.object_class = "file";
    payload.triage_guidance = { ...payload.triage_guidance!, host_id: 10, occurrence_id: 101 };
    payload.diagnosis = { ...conditionalDiagnosis("002"), host_id: 20, occurrence_id: 202, operation: "read", permissions: ["read"], target_class: "file", target_type: "user_home_t" } as IssueDetailResponse["diagnosis"];
    payload.resolutions = { candidates: [{ id: "home-read", kind: "enable_boolean", finding_kind: "conditional_allow_inactive", host_id: 20, hostname: "basename-host",
      title: "Enable httpd_read_user_content", explanation: "A conditional path exists", evidence_basis: { occurrence_id: 202, boolean: "httpd_read_user_content" }, evidence_version: "v1",
      intent_prompt: "Confirm intentional home content", scope_kind: "host_boolean", scope_description: "Host-wide", scope_warning: "Broader effects", expected_effect: "May supply read permission",
      mechanically_supported: true, intent_confirmation_required: true, limitations: [], status: "proposed", presentation: "technical_alternative", requires_home_content_review: true }],
      observed_access: { occurrence_id: 202, host_id: 20, hostname: "basename-host", actor: "httpd", source_type: "httpd_t", resource: "Complete path not recorded", target_type: "user_home_t", object_class: "file", permissions: ["read"], operation_label: "read", outcome: "DENIED", observed_at: "2026-10-01T10:00:00Z" },
      rejected_candidates: [], intent: null, freshness: null, change_plan: null, history: [] };
    const occurrence = occurrencePage("001").occurrences[0];
    occurrence.id = 101;
    occurrence.normalized_denial.target_paths = ["/var/www/html/a file.txt"];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/occurrences/101") ? response(200, occurrence) : detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByRole("heading", { name: "Investigation lead: probable label mismatch" })).toBeVisible();
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("Inspect the current file label");
    await waitFor(() => expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent("/var/www/html/a file.txt"));
    expect(screen.getByRole("button", { name: "Copy command: restorecon -v -- '/var/www/html/a file.txt'" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Review this change" })).not.toBeInTheDocument();
  });

  it("identifies the latest occurrence when label checks use an older example", async () => {
    const payload = labelingPayload();
    payload.resolutions = {
      candidates: [], rejected_candidates: [],
      observed_access: { occurrence_id: 102, host_id: 10, hostname: "web-1", actor: "httpd", source_type: "httpd_t", resource: "/var/www/other.html", target_type: "user_home_t", object_class: "file", permissions: ["read"], operation_label: "read", outcome: "DENIED", observed_at: "2026-09-30T16:27:00Z" },
      intent: null, freshness: null, change_plan: null, history: []
    };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();

    const checks = await screen.findByRole("region", { name: "Check" });
    expect(within(checks).getByRole("link", { name: "web-1 · occurrence #101" })).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(within(checks).getByRole("link", { name: "web-1 · occurrence #102" })).toHaveAttribute("href", "/hosts/10/occurrences/102");
    expect(checks).toHaveTextContent("Latest access:");
    expect(checks).not.toHaveTextContent("These checks use a different example from the latest access");
  });

  it("presents a correlated pair as one activity while keeping both audit events accessible", async () => {
    const payload = detailPayload("repeated");
    payload.issue.occurrences_count = 3;
    const rows = [101, 102, 103].map((id) => ({ id, occurred_at: "2026-10-01T10:00:00Z", host: { id: id === 101 ? 10 : 20, hostname: id === 101 ? "enforcing-host" : "permissive-host" },
      resource: id === 101 ? "page.html" : "/var/www/html/page.html", absolute_path: id !== 101, target_type: "user_home_t", permissions: id === 101 ? ["read"] : id === 102 ? ["open", "read"] : ["map"], enforcement_mode: id === 101 ? "enforcing" : "permissive", syscall_outcome: id === 101 ? "failed" : "succeeded" }));
    const fetchMock = vi.fn(async (url: string) => response(200, /view=(activity|summary)/.test(url) ? { occurrences: rows, meta: { page: 1, page_size: 10, total: 3, total_pages: 1 },
      ...(url.includes("view=activity") ? { activity_scope: "current_page", activity_groups: [{ occurrence_ids: [101], correlated: false, basis: null }, { occurrence_ids: [102, 103], correlated: true, basis: "Same host and object; not proof of one request." }] } : {}) } : payload));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    const tabs = await screen.findByRole("tablist", { name: "Occurrence views" });
    expect(within(tabs).getByRole("tab", { name: /^Occurrences$/ })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("table", { name: "Occurrence summary" })).toBeVisible();
    await user.click(within(tabs).getByRole("tab", { name: "Grouped activity" }));
    const table = await screen.findByRole("table", { name: "Audit activity" });
    expect(screen.getByRole("tabpanel", { name: "Grouped activity" })).toContainElement(table);
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(screen.getByText(/may split at page or permission-filter boundaries/)).toBeVisible();
    await user.click(within(table).getByRole("button", { name: "2 audit events" }));
    expect(within(table).getByRole("button", { name: "Inspect occurrence #102" })).toBeVisible();
    expect(within(table).getByRole("button", { name: "Inspect occurrence #103" })).toBeVisible();
    await user.click(screen.getByRole("tab", { name: /^Occurrences$/ }));
    expect(await screen.findByRole("table", { name: "Occurrence summary" })).toBeVisible();
    expect(fetchMock.mock.calls.map(([url]) => url)).toContain("/api/v1/issues/7/occurrences?view=summary&page=1&limit=10");
  });

  it("distinguishes same-minute recurrences and labels AVC enforcement independently of unknown syscalls", async () => {
    const payload = detailPayload("repeated");
    const occurrences = [31, 35].map((second, index) => ({ id: 101 + index, occurred_at: `2026-10-26T16:38:${second}.123Z`,
      host: { id: 20, hostname: "fedora-host" }, resource: "example.txt", absolute_path: false,
      target_type: "user_home_t", permissions: ["read"], enforcement_mode: "enforcing", syscall_outcome: "unknown" }));
    vi.stubGlobal("fetch", vi.fn(async (url: string) => response(200, /view=summary/.test(url)
      ? { occurrences, meta: { page: 1, page_size: 10, total: 2, total_pages: 1 } } : payload)));
    renderDetail();
    const table = await screen.findByRole("table", { name: "Occurrence summary" });
    expect(within(table).getByRole("columnheader", { name: "AVC enforcement" })).toBeVisible();
    expect(within(table).getByText("Oct 26, 16:38:31 UTC")).toHaveAttribute("datetime", occurrences[0].occurred_at);
    expect(within(table).getByText("Oct 26, 16:38:35 UTC")).toHaveAttribute("title", occurrences[1].occurred_at);
    expect(within(table).getAllByRole("cell", { name: "Unknown" })).toHaveLength(2);
  });

  it("leads with server-provided label guidance and copyable commands without rejected solver options", async () => {
    const payload = labelingPayload();
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Investigation lead: probable label mismatch" })).toBeVisible();
    expect(screen.getAllByText("/var/www/html/a file.txt", { selector: "code" }).length).toBeGreaterThan(0);
    expect(screen.getByText("matchpathcon -- '/var/www/html/a file.txt'")).toBeVisible();
    expect(await screen.findByText("restorecon -v -- '/var/www/html/a file.txt'")).toBeVisible();
    expect(screen.getByRole("region", { name: "Check" })).toHaveTextContent("Label at denial: user_home_t");
    expect(screen.getByRole("region", { name: "Check" })).toHaveTextContent("Read-only restoration preview");
    expect(screen.getByRole("region", { name: "Optional restoration after verification" })).toHaveTextContent("including local customizations");
    expect(screen.getByText(/Targeted scope:/)).toBeVisible();
    expect(screen.getAllByText("Changes file labels")[0]).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Copy command: matchpathcon -- '/var/www/html/a file.txt'" }));
    expect(await navigator.clipboard.readText()).toBe("matchpathcon -- '/var/www/html/a file.txt'");
    expect(screen.getByText("restorecon -Rv -- /var/www/html")).not.toBeVisible();
    await user.click(screen.getByText("Broader alternative: recursive restoration"));
    expect(screen.getByText("restorecon -Rv -- /var/www/html")).toBeVisible();
    expect(screen.getByText(/2 of 2 distinct recorded paths/)).toBeVisible();
    expect(screen.queryByText("Options not offered")).not.toBeInTheDocument();
    expect(screen.queryByText(/Complete path unavailable for/)).not.toBeInTheDocument();
  });

  it("does not manufacture guidance when absent or replace an authoritative finding", async () => {
    const payload = labelingPayload();
    payload.diagnosis = diagnosisFor("001") as IssueDetailResponse["diagnosis"];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    const view = renderDetail();
    expect(await screen.findByRole("heading", { name: "Potential file-context mismatch" })).toBeVisible();
    expect(screen.queryByText("Investigation lead: probable label mismatch")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy command: restorecon -v/ })).not.toBeInTheDocument();
    view.unmount();

    payload.diagnosis = null;
    payload.triage_guidance = null;
    payload.operator_guidance = null;
    renderDetail();
    expect(await screen.findByText("Cause not confirmed.")).toBeVisible();
    expect(screen.queryByRole("button", { name: /Copy command: matchpathcon/ })).not.toBeInTheDocument();
  });

  it("shows targeted restoration without a recursive alternative for a broad system root", async () => {
    const payload = labelingPayload();
    payload.triage_guidance = { ...payload.triage_guidance!, path: "/etc/shadow", conventional_type: null,
      recursive_directory: null, recursive_path_count: 0, path_count: 1,
      commands: [
        { action: "inspect", label: "Check the configured label", command: "matchpathcon -- /etc/shadow" },
        { action: "restore_targeted", label: "Restore this file's configured context", command: "restorecon -v -- /etc/shadow" }
      ] };
    payload.operator_guidance!.source.path = "/etc/shadow";
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByRole("button", { name: "Copy command: restorecon -v -- /etc/shadow" })).toBeVisible();
    expect(screen.queryByText("Broader alternative: recursive restoration")).not.toBeInTheDocument();
    expect(screen.queryByText(/restorecon -Rv/)).not.toBeInTheDocument();
  });

  it("keeps access flow and compact context visible while the sidebar opens technical evidence on demand", async () => {
    const payload = detailPayload("002");
    payload.issue.fingerprint_digest = "sha256:issue-fingerprint";
    payload.resolutions = { candidates: [], rejected_candidates: [], intent: null, freshness: null, change_plan: null, history: [],
      observed_access: { occurrence_id: 101, host_id: 10, hostname: "web-1", actor: "httpd", source_type: "httpd_t",
        resource: "TCP/12345", target_type: "unreserved_port_t", object_class: "tcp_socket", permissions: ["name_connect"],
        operation_label: "connect", outcome: "DENIED", observed_at: "2026-09-30T16:26:25Z" } };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => /occurrences\/101$/.test(url) ? response(200, occurrencePage("002").occurrences[0]) : detailResponse(url, payload)));
    const user = userEvent.setup();
    renderDetail();
    const flow = await screen.findByRole("region", { name: "Observed access" });
    expect(flow).toHaveTextContent("httpd");
    expect(flow).toHaveTextContent("POLICY DENIAL");
    expect(flow).toHaveTextContent("TCP/12345");
    const context = screen.getByRole("complementary", { name: "Investigation context" });
    expect(within(context).getByText("Observed access & finding example")).toBeVisible();
    expect(context).toHaveTextContent("web-1");
    expect(context).toHaveTextContent("Process");
    expect(context).toHaveTextContent("Permission");
    expect(context).toHaveTextContent("unreserved_port_t");
    expect(screen.queryByText("sha256:issue-fingerprint")).not.toBeInTheDocument();
    expect(screen.queryByText(/allow httpd_t port_type/)).not.toBeInTheDocument();
    await user.click(within(context).getByRole("link", { name: "View technical evidence" }));
    expect(screen.getByRole("button", { name: "Technical details & audit provenance" })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tab", { name: "Policy evaluation" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("sha256:issue-fingerprint")).not.toBeInTheDocument();
    expect(screen.getByText(/allow httpd_t port_type/)).toBeVisible();
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(await screen.findByRole("link", { name: "Open occurrence" })).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(screen.queryByRole("heading", { name: "Evaluation checkpoint" })).not.toBeInTheDocument();
    expect(screen.queryByText("sha256:issue-fingerprint")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical details & audit provenance" }));
    expect(screen.queryByText("sha256:issue-fingerprint")).not.toBeInTheDocument();
  });

  it("aligns the selected metadata denial with its own finding instead of the latest read finding", async () => {
    const payload = labelingPayload();
    payload.triage_guidance = null;
    const metadata = { ...diagnosisFor("004")!, host_id: 10, occurrence_id: 101, source_domain: "httpd_t", target_type: "user_home_t", path: payload.operator_guidance!.source.path! } as NonNullable<IssueDetailResponse["diagnosis"]>;
    const read = { ...metadata, occurrence_id: 202, permissions: ["read"] };
    payload.diagnosis = read;
    payload.findings = [{ diagnosis: read, occurrence_count: 1, observation_count: 0 }];
    payload.issue.occurrences_count = 4;
    const host = payload.host_explanations[0];
    host.occurrence_count = 4;
    host.unexplained_occurrence_count = 0;
    host.diagnosis_groups = [
      { ...host.diagnosis_groups[0], diagnosis: read, count: 1, sample_occurrence_ids: [202] },
      { ...host.diagnosis_groups[0], diagnosis: metadata, count: 3, sample_occurrence_ids: [101, 102, 103] }
    ];
    payload.resolutions = { candidates: [], rejected_candidates: [], intent: null, freshness: null, change_plan: null, history: [],
      observed_access: { occurrence_id: 202, host_id: 10, hostname: "web-1", actor: "httpd", source_type: "httpd_t",
        resource: "shadow", target_type: "user_home_t", object_class: "file", permissions: ["read"],
        operation_label: "read", outcome: "DENIED", observed_at: "2026-10-01T10:00:00Z" } };
    const occurrence = occurrencePage("001").occurrences[0];
    occurrence.normalized_denial.permissions = ["getattr"];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/occurrences/101") ? response(200, occurrence) : detailResponse(url, payload)));
    renderDetail("/issues/7?evidence_occurrence=202");

    await waitFor(() => expect(screen.getByRole("region", { name: "Observed access" })).toHaveTextContent("getattr"));
    const diagnosis = screen.getByRole("region", { name: "Findings" });
    expect(diagnosis).toHaveTextContent("inspect file attributes such as ownership and permissions");
    expect(diagnosis).not.toHaveTextContent("denied file read");
    expect(diagnosis).not.toHaveTextContent("Inspection uses a different retained example");
    const context = screen.getByRole("complementary", { name: "Investigation context" });
    expect(context).toHaveTextContent("Displayed finding: 3");
    expect(within(context).getByText("Observed access & finding example")).toBeVisible();
    expect(within(context).getByRole("link", { name: "Policy evidence" })).toHaveAttribute("href", expect.stringContaining("evidence_occurrence=101"));
    const user = userEvent.setup();
    await user.click(within(context).getByRole("link", { name: "Policy evidence" }));
    const policy = screen.getByRole("tabpanel", { name: "Policy evaluation" });
    expect(within(policy).getByRole("heading", { name: "Policy evaluation · occurrence #101" })).toBeVisible();
    expect(policy).toHaveTextContent("getattr");
    expect(policy).not.toHaveTextContent("occurrence #202");
  });

  function readFinding() {
    const rule = "allow httpd_t user_home_type:file { getattr ioctl lock open read }; [ httpd_read_user_content ]:True";
    const booleans = [{ name: "httpd_read_user_content", current: false, status: "observed" }];
    return { ...conditionalDiagnosis("002"), title: "A matching SELinux read rule was inactive", operation: "read", permission: "read", permissions: ["read"], target_class: "file", target_type: "user_home_t", destination_port: undefined, next_step: "Confirm whether this workload is intended to read files labeled user_home_t before considering a change.", conditional_rules: [{ rule, expression: "httpd_read_user_content", state: "inactive" }], condition_boolean_states: [{ rule, expression: "httpd_read_user_content", state: "inactive", booleans }] };
  }

  it("limits a richer permissive event's conditional-read explanation to the assessed permission", async () => {
    const payload = detailPayload("basename");
    const finding = { ...readFinding(), permissions: ["open", "read", "map"], explained_permissions: ["read"], enforcement_mode: "permissive", syscall_failed: false };
    payload.diagnosis = finding;
    payload.findings = [{ diagnosis: finding, occurrence_count: 1, observation_count: 0 }];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(diagnosis).toHaveTextContent("This finding explains read only. Other permissions recorded in this event (open, map) need independent assessment.");
    expect(diagnosis).not.toHaveTextContent("blocked");
  });

  it("shows independent label and policy findings for the same scoped event without borrowing another host's finding", async () => {
    const payload = detailPayload("001");
    const label = { ...payload.diagnosis!, permissions: ["entrypoint"] };
    const policy = { ...diagnosisFor("004")!, host_id: 10, occurrence_id: 101, source_domain: "httpd_t", target_type: "user_home_t", permissions: ["entrypoint"] };
    const foreign = { ...policy, host_id: 20, occurrence_id: 202, operation: "name_bind", lead: "Foreign policy evidence must not appear here." };
    payload.diagnosis = label;
    payload.host_explanations[0].diagnosis_groups[0].diagnosis = label;
    payload.host_explanations[0].diagnosis_groups[0].findings = [label, foreign, policy];
    payload.resolutions = { candidates: [], rejected_candidates: [], intent: null, freshness: null, history: [], change_plan: null,
      observed_access: { occurrence_id: 101, host_id: 10, hostname: "web-1", actor: "runcon", source_type: "httpd_t", resource: label.path!,
        target_type: "user_home_t", object_class: "file", permissions: ["entrypoint"], operation_label: "entrypoint", outcome: "DENIED", observed_at: "2026-09-30T16:26:25Z" } };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(diagnosis).not.toHaveTextContent("Finding example");
    expect(diagnosis).not.toHaveTextContent("Other occurrences can have different findings");
    expect(within(diagnosis).getByRole("heading", { name: /Host-configured label/ })).toBeVisible();
    expect(diagnosis).toHaveTextContent("no allow rule for this launch");
    expect(diagnosis).toHaveTextContent("entrypoint permission controls whether a file can be used to start or transition into a process domain");
    expect(within(diagnosis).queryByRole("heading", { name: "Policy explanation" })).not.toBeInTheDocument();
    expect(diagnosis).not.toHaveTextContent("Foreign policy evidence");
    expect(diagnosis).toHaveTextContent("Limitation:");
    expect(within(diagnosis).queryByRole("button", { name: /Copy command/ })).not.toBeInTheDocument();
    expect(within(diagnosis).queryByRole("button", { name: "Label observation details" })).not.toBeInTheDocument();
    const context = screen.getByRole("complementary", { name: "Investigation context" });
    expect(within(context).getByRole("link", { name: "#101" })).toHaveAttribute("href", "/hosts/10/occurrences/101");
    await userEvent.setup().click(within(context).getByRole("link", { name: "Policy evidence" }));
    const evidence = screen.getByRole("tabpanel", { name: "Policy evaluation" });
    expect(within(evidence).getByText(label.expected_context_observed_at!)).toBeVisible();
    expect(within(evidence).getByRole("heading", { name: "Label comparison · occurrence #101" })).toBeVisible();
    expect(within(evidence).getByRole("heading", { name: "Policy evaluation · occurrence #101" })).toBeVisible();
    expect(evidence).not.toHaveTextContent("Foreign policy evidence");
  });

  it("keeps a shadow_t policy finding separate from an unavailable configured-label comparison", async () => {
    const payload = detailPayload("004");
    payload.issue.source_type = "httpd_t";
    payload.issue.target_type = "shadow_t";
    payload.diagnosis = { ...payload.diagnosis!, source_domain: "httpd_t", target_type: "shadow_t", path: "/var/www/html/example.txt" };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    const diagnosis = await screen.findByRole("region", { name: "Findings" });
    expect(diagnosis).toHaveTextContent("The policy SECentral checked has no rule allowing mariadbd to inspect file attributes such as ownership and permissions on files labeled shadow_t");
    expect(within(diagnosis).getByText("mariadbd", { selector: "code" })).toBeVisible();
    expect(within(diagnosis).getByText("shadow_t", { selector: "code" })).toBeVisible();
    expect(diagnosis).not.toHaveTextContent("Host-configured label: not established by this policy finding");
    expect(within(diagnosis).queryByLabelText("AVC and host-configured label comparison")).not.toBeInTheDocument();
    expect(within(diagnosis).queryByRole("button", { name: "Label observation details" })).not.toBeInTheDocument();
  });

  it("001-A shows conditional-read evidence and the independent missing-path limitation without exposing provenance", async () => {
    const payload = detailPayload("basename");
    const finding = readFinding();
    payload.issue.occurrences_count = 2057;
    payload.intelligence.names = ["0000.txt", "0001.txt", "secentral-test.html"];
    payload.intelligence.resource_summary = { absolute_path_occurrences: 0, without_absolute_path_occurrences: 2057, name_count: 2050, path_count: 0, process_command: "httpd" };
    payload.diagnosis = finding;
    payload.findings = [{ diagnosis: finding, occurrence_count: 2057, observation_count: 0 }];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    const user = userEvent.setup();
    renderDetail();
    expect(await screen.findByRole("heading", { level: 1, name: "SELinux recorded httpd requesting read access to files labeled user_home_t." })).toBeInTheDocument();
    expect(document.querySelector(".issue-operation-label")).toHaveTextContent(`${(2057).toLocaleString()} occurrences · 1 server · ${(2050).toLocaleString()} filenames`);
    const conditionValues = screen.getAllByText("httpd_read_user_content", { selector: ".issue-condition-summary code" });
    expect(conditionValues).toHaveLength(2);
    conditionValues.forEach((value) => expect(value).not.toBeVisible());
    await user.click(screen.getByRole("button", { name: "Conditional policy paths" }));
    screen.getAllByText("httpd_read_user_content", { selector: ".issue-condition-summary code" }).forEach((value) => expect(value).toBeVisible());
    expect(document.querySelector(".issue-condition-summary")).toHaveTextContent("Off");
    await user.click(screen.getByRole("button", { name: "Additional findings & evidence gaps" }));
    expect(screen.getByRole("heading", { name: "Path-based label check unavailable" })).toBeVisible();
    expect(screen.getByText(/cannot determine whether/)).toHaveTextContent("user_home_t");
    expect(screen.queryByText("No evidence-backed explanation is available yet.")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Potential file-context mismatch" })).not.toBeInTheDocument();
    expect(screen.queryByText(/allow httpd_t user_home_type:file/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical details & audit provenance" }));
    const explanation = document.querySelector("#issue-technical-evidence .issue-selinux-explanation") as HTMLElement;
    expect(within(explanation).getByText(/allow httpd_t user_home_type:file/)).toBeVisible();
    expect(within(explanation).getByText(/user_home_t:file/)).toBeVisible();
    expect(within(explanation).getByText("read", { selector: "code" })).toBeVisible();
    expect(within(explanation).queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(within(explanation).getByText("2026-09-30T16:26:00Z")).toBeVisible();
  });

  it("keeps an independent conditional-read finding alongside a primary file-context mismatch", async () => {
    const payload = detailPayload("001");
    payload.fleet_explanation.state = "disagreement";
    payload.findings = [{ diagnosis: payload.diagnosis!, occurrence_count: 2, observation_count: 1 }, { diagnosis: readFinding(), occurrence_count: 2, observation_count: 0 }];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    expect(await screen.findByRole("heading", { name: "Potential file-context mismatch" })).toBeVisible();
    await userEvent.setup().click(screen.getByRole("button", { name: "Additional findings & evidence gaps" }));
    expect(screen.getByText("A matching SELinux read rule was inactive · 2 occurrences")).toBeVisible();
    expect(screen.getByLabelText("Finding coverage")).toHaveTextContent("Displayed finding: 2");
    expect(screen.getByText(/Findings differ between occurrences/)).toBeInTheDocument();
  });
  it("compares AVC-time and later expected file types for accepted Scenario 001", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Potential file-context mismatch" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Label SELinux used/ })).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { name: /Host-configured label/ }).length).toBeGreaterThan(0);
    expect(screen.getByText("user_home_t", { selector: ".issue-context-type" })).toBeInTheDocument();
    expect(screen.getByText("httpd_sys_content_t", { selector: ".issue-context-type" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("/var/www/html/secentral-test.html");
    expect(screen.getByText("Looked up after the denial")).toBeInTheDocument();
    expect(screen.getByText("At the denial")).toBeInTheDocument();
    expect(screen.getByText("Different types")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Findings" })).toHaveTextContent("Policy explanation unavailable for this occurrence.");
    expect(screen.queryByText("unconfined_u:object_r:user_home_t:s0")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical details & audit provenance" }));
    const fullContext = document.querySelector("#issue-technical-evidence .issue-selinux-explanation") as HTMLElement;
    expect(within(fullContext).getByText("unconfined_u:object_r:user_home_t:s0")).toBeVisible();
  });

  it("makes basename-only Scenario 001 explicitly incomplete without claiming a lookup", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "basename");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByText(/No absolute path was retained/)).toBeInTheDocument();
    expect(screen.getByText(/Resource examples: secentral-s001-basename-20260930/)).toBeInTheDocument();
    expect(screen.getByText(/Policy evaluation is pending/)).toBeInTheDocument();
    expect(screen.getByText(/In Retained occurrences, open an affected occurrence's raw audit evidence and check its CWD and PATH records/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Potential file-context mismatch" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Compare host configurations" })).not.toBeInTheDocument();
  });

  it("shows Scenario 002 operation, destination port, each inactive boolean, and exact rule", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "002");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting connection access/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "httpd_t was denied connecting to TCP/12345." })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Findings" })).toHaveTextContent("TCP/12345");
    expect(screen.getAllByText("httpd_can_network_connect").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Conditional policy paths" })).toHaveAttribute("aria-expanded", "false");
    await user.click(screen.getByRole("button", { name: "Conditional policy paths" }));
    expect(document.querySelector(".issue-condition-summary li")).toHaveTextContent("httpd_can_network_connect");
    expect(document.querySelector(".issue-condition-summary li")).toHaveTextContent("Off");
    expect(screen.getAllByText("nis_enabled").length).toBeGreaterThan(0);
    expect(screen.queryByText(/allow httpd_t port_type/)).not.toBeInTheDocument();
    expect(screen.queryByText(/What remains unknown/)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Technical details & audit provenance" }));
    const selinuxExplanation = document.querySelector("#issue-technical-evidence .issue-selinux-explanation");
    expect(within(selinuxExplanation as HTMLElement).getByText(/allow httpd_t port_type/)).toBeVisible();
    expect(within(selinuxExplanation as HTMLElement).getByText(/allow nsswitch_domain unreserved_port_t/)).toBeVisible();
    expect(within(selinuxExplanation as HTMLElement).queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(within(selinuxExplanation as HTMLElement).getByText("2026-09-30T16:26:00Z")).toBeVisible();
    expect(screen.getByRole("button", { name: "Conditional policy paths" })).toHaveAttribute("aria-expanded", "true");
    expect(screen.queryByText(/setsebool/i)).not.toBeInTheDocument();
  });

  it("shows live Scenario 002 resource cohorts and partial checkpoint coverage without treating network evidence as filenames", async () => {
    const payload = detailPayload("002");
    payload.issue.occurrences_count = 3;
    payload.fleet_explanation.state = "insufficient_evidence";
    payload.intelligence.resource_summary = {absolute_path_occurrences: 0, without_absolute_path_occurrences: 3, path_count: 0, name_count: 0, process_command: "httpd", destination_port_count: 2, destination_ports: [{port: "12345", occurrence_count: 2}, {port: "12346", occurrence_count: 1}]};
    payload.findings = [{diagnosis: payload.diagnosis!, occurrence_count: 1, observation_count: 0}];
    payload.finding_coverage = {conditional_allow_inactive: 2, unexplained: 1};
    payload.policy_analysis.limitations = ["For 1 denial, a matching conditional rule was active at the associated checkpoint, so that sample does not support an inactive-condition explanation. Checkpoint state is not an AVC-time measurement."];
    const selected = occurrencePage("002").occurrences[0];
    selected.normalized_denial.details.network_evidence = {dport_fields: [], dest_fields: ["127.0.0.1", "12345"]};
    const fetchMock = vi.fn((url: string) => Promise.resolve(response(200, /occurrences\/101$/.test(url) ? selected : /view=(summary|activity)/.test(url) ? {occurrences: [{id: 101, occurred_at: "2026-10-01T10:42:20Z", host: {id: 10, hostname: "agent-test"}, resource: "TCP/12345", absolute_path: false, permissions: ["name_connect"], target_type: "unreserved_port_t"}], meta: {page: 1, page_size: 25, total: 3, total_pages: 1}} : payload)));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    expect(await screen.findByRole("heading", {level: 1, name: "SELinux recorded httpd requesting outbound TCP connection access."})).toBeInTheDocument();
    expect(screen.getByText(/TCP\/12345 \(2 occurrences\).*TCP\/12346 \(1 occurrence\)/)).toBeVisible();
    expect(await screen.findByRole("region", { name: "Finding coverage" })).toHaveTextContent("Displayed finding: 1");
    await user.click(screen.getByRole("button", { name: "Additional findings & evidence gaps" }));
    expect(screen.getByText(/a matching conditional rule was active at the associated checkpoint/)).toBeVisible();
    expect(screen.getByText(/Some occurrences still need investigation/)).toBeVisible();
    await screen.findByRole("table", { name: "Occurrence summary" });
    const table = await screen.findByRole("table", {name: "Occurrence summary"});
    expect(within(table).getByText("TCP/12345")).toBeVisible();
    expect(within(table).queryByText("Basename only")).not.toBeInTheDocument();
    expect(within(table).queryByText("Path evidence")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => /occurrences\/\d+$/.test(url))).toBe(false);
    await user.click(within(table).getByRole("button", {name: "Inspect occurrence 101"}));
    await screen.findByText(/Occurrence #101/);
    expect(screen.getByRole("region", { name: "Selected occurrence evidence" })).toHaveTextContent("TCP/12345");
    expect(screen.queryByText(/TCP\/127\.0\.0\.1/)).not.toBeInTheDocument();
  });

  it("keeps Scenario 003 bind semantics and does not prescribe a port mapping", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "003");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting local bind access/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "httpd_t was denied binding TCP/12345." })).toBeInTheDocument();
    expect(screen.getAllByText(/local port bind/).length).toBeGreaterThan(0);
    expect(screen.getByRole("region", { name: "Findings" })).toHaveTextContent("TCP/12345");
    expect(screen.getAllByText("nis_enabled").length).toBeGreaterThan(0);
    screen.getAllByText("nis_enabled").forEach((value) => expect(value).not.toBeVisible());
    expect(screen.queryByText(/whether this workload is expected to bind TCP port 12345/)).not.toBeInTheDocument();
    expect(screen.queryByText(/map.*http_port_t/i)).not.toBeInTheDocument();
  });

  it("shows Scenario 004 no-matching-allow without inferring workload intent", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "004");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting file metadata access/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "No matching SELinux allow was found for this access" })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Findings" })).toHaveTextContent(/no rule allowing mariadbd to inspect file attributes such as ownership and permissions on files labeled var_t/);
    expect(screen.getByText(/\/srv\/secentral-s004-mariadb\/ibdata1/)).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Findings" })).queryByText(/cannot infer the intended database path or label/)).not.toBeInTheDocument();
    expect(within(await screen.findByRole("complementary", { name: "Investigation context" })).getByRole("link", { name: "#104" })).toHaveAttribute("href", "/hosts/10/occurrences/104");
    expect(screen.queryByText(/generate custom policy/i)).not.toBeInTheDocument();
  });

  it.each([
    ["permissive", "succeeded"],
    ["permissive", "failed"],
    ["enforcing", "failed"]
  ] as const)("scopes a file no-allow diagnosis to its permission and observed outcome (%s, %s)", async (mode, outcome) => {
    const payload = detailPayload("004");
    const path = "/srv/secentral-scenario006-test/write-target";
    const diagnosis = {
      ...diagnosisFor("004")!,
      operation: "open",
      permissions: ["open"],
      source_domain: "httpd_sys_script_t",
      process_command: "scenario006.cgi",
      target_type: "var_t",
      target_class: "file",
      path,
      occurrence_id: 101,
      host_id: 10,
      enforcement_mode: mode,
      syscall_failed: outcome === "failed"
    } as NonNullable<IssueDetailResponse["diagnosis"]>;
    payload.issue.source_type = "httpd_sys_script_t";
    payload.issue.target_type = "var_t";
    payload.issue.permissions = ["open"];
    payload.issue.occurrences_count = 1;
    payload.issue.signatures[0].permissions = ["open"];
    payload.diagnosis = diagnosis;
    payload.findings = [{ diagnosis, occurrence_count: 1, observation_count: 0 }];
    payload.host_explanations[0].hostname = "web-test";
    payload.host_explanations[0].occurrence_count = 1;
    payload.host_explanations[0].diagnosis = diagnosis;
    payload.host_explanations[0].diagnosis_groups[0] = { ...payload.host_explanations[0].diagnosis_groups[0], count: 1, diagnosis, sample_occurrence_ids: [101] };
    payload.intelligence.paths = [path];
    payload.intelligence.names = [];
    payload.operator_guidance = {
      source: { occurrence_id: 101, host_id: 10, hostname: "web-test", occurred_at: "2026-10-24T17:45:45Z", path, observed_type: "var_t", object_class: "file" },
      checks: [
        { title: "Current object label", command: `ls -ldZ -- ${path}`, interpretation: "Read the current object's context." },
        { title: "Host-configured context", command: `matchpathcon -- ${path}`, interpretation: "Compare the configured label." },
        { title: "Read-only restoration preview", command: `restorecon -n -v -- ${path}`, interpretation: "Preview a label restoration." }
      ],
      manual_check: "Confirm the file's role.", possible_fix: "Investigate the configured label.", verification: "Retry the intended access.",
      verification_limit: "Check the workload result.", restriction: "Keep unwanted access denied."
    };
    payload.resolutions = {
      candidates: [], rejected_candidates: [], observed_access: null, intent: null,
      freshness: null, change_plan: null, history: []
    };

    const fetchMock = vi.fn(async (url: string) => {
      if (url === "/api/v1/issues/7") return response(200, payload);
      if (url.includes("view=summary")) return response(200, { occurrences: [{
        id: 101, occurred_at: "2026-10-24T17:45:45Z", host: { id: 10, hostname: "web-test" },
        resource: path, absolute_path: true, target_type: "var_t", permissions: ["open"],
        enforcement_mode: mode, syscall_outcome: outcome
      }], meta: { page: 1, page_size: 10, total: 1, total_pages: 1 } });
      return detailResponse(url, payload);
    });
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    const heading = await screen.findByRole("heading", { name: "No matching SELinux allow for open on var_t:file" });
    expect(heading).toBeVisible();
    expect(screen.getByRole("region", { name: "Findings" })).not.toHaveTextContent("SELinux caused");
    expect(await screen.findByRole("link", { name: `web-test · ${mode === "permissive" ? "Permissive" : "Enforcing"} · syscall ${outcome === "succeeded" ? "Succeeded" : "Failed"}` })).toHaveAttribute("href", expect.stringContaining("evidence_occurrence=101"));
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("Confirm with the service owner whether this open access is intended");
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("If you suspect var_t:file is the wrong label, inspect the collapsed label checks");
    expect(screen.getByRole("button", { name: "Check for a possible label mismatch" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Copy command: restorecon -n -v -- /srv/secentral-scenario006-test/write-target" })).not.toBeInTheDocument();
    expect(screen.queryByText(/No reviewed change plan yet/)).not.toBeInTheDocument();
    expect(screen.queryByText(/The evaluated policy has no allow rule for the denied open/)).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Check for a possible label mismatch" }));
    expect(screen.getByRole("region", { name: "Check" })).toHaveTextContent("Investigation example: web-test · occurrence #101");
    expect(screen.getByLabelText("Suggested next step")).toHaveTextContent("label inspection does not establish that access should be allowed");
    expect(screen.getByRole("button", { name: "Copy command: restorecon -n -v -- /srv/secentral-scenario006-test/write-target" })).toBeVisible();
  });

  it("omits network endpoint from file evidence and labels the syscall separately from its result", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail("/issues/7?evidence=audit-evidence&evidence_tab=audit&evidence_occurrence=101");

    const record = await screen.findByRole("region", { name: "Selected occurrence evidence" });
    expect(within(record).queryByText("Recorded endpoint")).not.toBeInTheDocument();
    expect(within(record).getByText("First recorded syscall")).toBeInTheDocument();
    expect(within(record).queryByText("First recorded syscall result")).not.toBeInTheDocument();
  });

  it("shows the exact checkpoint condition and Boolean values while leaving transition intent unknown", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "005");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting execute access to \/var\/www\/cgi-bin/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /httpd_t was denied executing/ })).toBeInTheDocument();
    expect(screen.getAllByText(/\/var\/www\/cgi-bin\/secentral-s005-helper\.sh/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("httpd_unified").length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Conditional policy paths" }));
    const checkpoint = screen.getByRole("region", { name: "Possible policy paths" });
    expect(within(checkpoint).getByRole("link", { name: "secentral-agent-test · occurrence #101" })).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(checkpoint).toHaveTextContent("Sep 30, 16:26:00 UTC");
    expect(checkpoint).toHaveTextContent("httpd_builtin_scripting && httpd_unified && httpd_enable_cgi · Inactive");
    expect(checkpoint).toHaveTextContent("httpd_builtin_scripting On");
    expect(checkpoint).toHaveTextContent("httpd_unified Off");
    expect(checkpoint).toHaveTextContent("httpd_enable_cgi On");
    expect(checkpoint).toHaveTextContent("not AVC-time or current runtime state");
    expect(within(screen.getByRole("region", { name: "Findings" })).getByText(/does not establish that a domain transition was attempted or intended/)).toBeVisible();
  });

  it("summarizes differing policy evidence without exposing digests", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "fleet-live");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/1932");

    expect(await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting entrypoint access to \/usr\/bin\/id/ })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "No matching SELinux allow was found for this access" })).toBeInTheDocument();
    expect(screen.getByText(/The evaluated policy has no allow rule for this launch/)).toBeInTheDocument();
    expect(document.querySelector(".issue-primary-finding .issue-selinux-explanation")).toBeNull();
    expect(screen.getByRole("heading", { name: "Retained occurrences" })).toBeInTheDocument();
    expect(screen.getByText(/3 affected hosts/)).toBeInTheDocument();
    expect(screen.getByText("Fleet scope").parentElement).toHaveTextContent("3 affected hosts");
    expect(screen.queryByText(/Same supported findings across affected hosts/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Technical details & audit provenance" }));
    const why = document.querySelector("#issue-technical-evidence .issue-selinux-explanation");
    expect(within(why as HTMLElement).getAllByText(/entrypoint/).length).toBeGreaterThan(0);
    expect(within(why as HTMLElement).queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(within(why as HTMLElement).queryByRole("button", { name: "Copy exact policy identity" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Provenance" }));
    expect(screen.getByRole("tab", { name: "Provenance" })).toHaveAttribute("aria-selected", "true");
    const provenance = screen.getByRole("tabpanel", { name: "Provenance" });
    expect(provenance).not.toHaveTextContent("sha256:");
    expect(within(provenance).queryByRole("heading", { name: "Evaluation checkpoint" })).not.toBeInTheDocument();

    const host = within(screen.getByRole("region", { name: "Fleet scope" })).getByRole("link", { name: "secentral-agent-test" });
    const listItem = host.closest("tr");
    expect(listItem).not.toBeNull();
    expect(within(listItem!).getByText("4 of 4 with supported findings")).toBeInTheDocument();
    expect(within(listItem!).queryByText(/sha256:/)).not.toBeInTheDocument();
    await user.click(within(listItem!).getByRole("link", { name: "View group evidence" }));
    const evidence = document.getElementById("host-evidence-1138")!;
    expect(within(evidence).getByText("Policy evaluation varied across these occurrences.")).toBeVisible();
    expect(within(evidence).queryByText(/sha256:/)).not.toBeInTheDocument();
    expect(within(evidence).queryByText("Checkpoint")).not.toBeInTheDocument();
    expect(within(evidence).queryByText("Example occurrence")).not.toBeInTheDocument();
    expect(within(evidence).getByRole("list", { name: "Example occurrences" }).querySelectorAll("li")).toHaveLength(3);
    expect(screen.getAllByRole("link", { name: "secentral-alma-9-clean" })).toHaveLength(2);
    expect(screen.getByRole("link", { name: "secentral-alma9-test" })).toBeInTheDocument();
  });

  it("loads secondary fleet analysis only when requested and reports when no correlation is supported", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "fleet-live");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/1932");

    await screen.findByRole("heading", { level: 1, name: /SELinux recorded .* requesting entrypoint access to \/usr\/bin\/id/ });
    expect(fetchMock.mock.calls.map(([url]) => String(url))).not.toContain("/api/v1/issues/1932/analysis");
    await user.click(screen.getByRole("button", { name: "Compare host configurations" }));
    expect(await screen.findByText(/No supported policy-version, local file-context or custom-module correlation/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/1932/analysis");
  });

  it("hides unavailable configuration comparison without requesting analysis for historical affected hosts", async () => {
    const payload = detailPayload("001");
    payload.issue.affected_hosts = 2;
    payload.fleet_explanation.affected_host_count = 2;
    payload.intelligence.fleet = { activity_hosts: 1, current_configuration_hosts: 1, hosts_with_occurrence: 1, hosts_without_occurrence: 0, comparison_requirement: "Fleet comparison needs at least two hosts with configuration confirmed within the last 15 minutes." };
    const fetchMock = vi.fn(async (url: string) => url.endsWith("/analysis") ? response(200, analysisPayload("001")) : detailResponse(url, payload));
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByRole("heading", { name: "Fleet scope" });
    expect(screen.queryByRole("button", { name: "Compare host configurations" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Fleet comparison needs/)).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => url).some((url) => String(url).endsWith("/analysis"))).toBe(false);
  });

  it("offers lazy comparison with an unaffected cohort even when only one host has historical denials, retaining loading and error states", async () => {
    const payload = detailPayload("001");
    payload.intelligence.fleet = { activity_hosts: 2, current_configuration_hosts: 2, hosts_with_occurrence: 1, hosts_without_occurrence: 1 };
    let finishAnalysis: (response: Response) => void = () => {};
    const pendingAnalysis = new Promise<Response>((resolve) => { finishAnalysis = resolve; });
    const fetchMock = vi.fn(async (url: string) => url.endsWith("/analysis") ? pendingAnalysis : detailResponse(url, payload));
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    const button = await screen.findByRole("button", { name: "Compare host configurations" });
    expect(fetchMock.mock.calls.map(([url]) => url)).not.toContain("/api/v1/issues/7/analysis");
    await userEvent.setup().click(button);
    expect(screen.getByText("Checking supporting fleet evidence…")).toBeVisible();
    finishAnalysis(response(503, { error: { message: "Comparison unavailable" } }));
    expect(await screen.findByText("Fleet correlations could not be loaded.")).toBeVisible();
    expect(screen.queryByText(/No supported policy-version/)).not.toBeInTheDocument();
  });

  it.each([
    [{}, /Fleet comparison needs host reporting and configuration data/],
    [{ current_configuration_hosts: 0, hosts_with_occurrence: 0, hosts_without_occurrence: 0 }, /Fleet comparison needs current configuration from hosts/],
    [{ activity_hosts: 0, current_configuration_hosts: 0, hosts_with_occurrence: 0, hosts_without_occurrence: 0, comparison_requirement: "Fleet comparison needs hosts reporting within the last 7 minutes." }, /Fleet comparison needs hosts reporting within the last 7 minutes/],
    [{ activity_hosts: 2, current_configuration_hosts: 0, hosts_with_occurrence: 0, hosts_without_occurrence: 0, comparison_requirement: "Fleet comparison needs host configuration confirmed within the last 1 hour." }, /Fleet comparison needs host configuration confirmed within the last 1 hour/],
    [{ activity_hosts: 2, current_configuration_hosts: 2, hosts_with_occurrence: 2, hosts_without_occurrence: 0, comparison_requirement: "All eligible hosts have recorded this issue. Comparison needs a host with no recorded occurrence." }, /All eligible hosts have recorded this issue/],
    [{ activity_hosts: 2, current_configuration_hosts: 2, hosts_with_occurrence: 0, hosts_without_occurrence: 2, comparison_requirement: "Hosts that recorded this issue need to report and confirm their configuration before fleet comparison." }, /Hosts that recorded this issue need to report/]
  ])("does not render missing or empty current fleet evidence as a successful negative correlation (%j)", async (fleet, explanation) => {
    const payload = detailPayload("001");
    payload.intelligence.fleet = fleet;
    vi.stubGlobal("fetch", vi.fn(async (url: string) => detailResponse(url, payload)));
    renderDetail();
    await screen.findByRole("heading", { name: "Fleet scope" });
    expect(screen.queryByRole("button", { name: "Compare host configurations" })).not.toBeInTheDocument();
    expect(screen.queryByText(explanation)).not.toBeInTheDocument();
  });

  it("shows a readable occurrence summary and links to its full record", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "repeated");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Retained occurrences" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show recent occurrences" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Hide occurrences" })).not.toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Occurrence summary" })).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url)).some((url) => /occurrences\/\d+$/.test(url))).toBe(false);
    await user.click(screen.getAllByRole("button", { name: /Inspect occurrence/ })[0]);
    await screen.findByText(/Occurrence #101/);
    expect(screen.getByRole("region", { name: "Selected occurrence evidence" }).closest("#issue-technical-evidence")).not.toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(document.getElementById("audit-evidence")));
    expect(screen.getByRole("tab", { name: "Audit record" })).toHaveAttribute("aria-selected", "true");
    const record = screen.getByRole("region", { name: "Selected occurrence evidence" });
    expect(record).toHaveTextContent("httpd_t");
    expect(record).toHaveTextContent("read");
    expect(record).toHaveTextContent("user_home_t:file");
    expect(screen.queryByText(RAW_AVC)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Raw audit records" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Other retained payload" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Normalized source data" })).not.toBeInTheDocument();
    const occurrenceLinks = screen.getAllByRole("link", { name: "Open occurrence" });
    expect(occurrenceLinks).toHaveLength(1);
    expect(occurrenceLinks[0]).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(document.querySelector("script")).toBeNull();
  });

  it("honors existing occurrence deep links by opening the occurrence section", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail("/issues/7?tab=occurrences");

    expect((await screen.findAllByText("secentral-agent-test")).length).toBeGreaterThan(0);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/7/occurrences?view=summary&page=1&limit=10");
  });

  it("replaces occurrence pages instead of appending rows and never requests raw evidence for the table", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "basename");
    const fallback = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation((url: string, request?: { method?: string; body?: string }) => {
      if (/view=(summary|activity)/.test(url)) {
        const page = Number(new URL(url, "http://localhost").searchParams.get("page"));
        return Promise.resolve(response(200, { occurrences: [{ id: page, occurred_at: "2026-10-01T08:47:03Z", host: { id: 10, hostname: "agent-test" }, resource: `page-${page}.txt`, absolute_path: false, target_type: "user_home_t", permissions: ["read"] }], meta: { page, page_size: 25, total: 2057, total_pages: 83 } }));
      }
      return fallback(url, request);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/7?tab=occurrences");
    expect(await screen.findByText("page-1.txt")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Go to previous page" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Go to next page" }));
    expect(await screen.findByText("page-2.txt")).toBeInTheDocument();
    expect(screen.queryByText("page-1.txt")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to previous page" }));
    expect(await screen.findByText("page-1.txt")).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url)).some((url) => /occurrences\/\d+$/.test(url))).toBe(false);
  });

  it("states when an expected-context observation is missing for a retained absolute path", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "missing-observation");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByText(/No event-linked expected-context observation is available/)).toBeInTheDocument();
    expect(await screen.findByRole("complementary", { name: "Investigation context" })).toHaveTextContent("user_home_t");
  });

  it("keeps workflow available in the compact issue-actions card and updates lifecycle status", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    await screen.findByRole("heading", { name: "Potential file-context mismatch" });
    expect(screen.getByRole("button", { name: /Issue actions/ })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Issue actions/ }));
    await user.selectOptions(screen.getByLabelText("Issue status"), "resolved");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/status", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "resolved", signature_ids: [11] }) })));
  });

  it("distinguishes the latest diagram from a different investigation host and links both sources", async () => {
    const payload = labelingPayload();
    payload.policy_analysis.status = "error";
    payload.resolutions = { candidates: [], rejected_candidates: [], intent: null, freshness: null, change_plan: null, history: [],
      observed_access: { occurrence_id: 202, host_id: 20, hostname: "web-latest", actor: "worker", source_type: "httpd_t",
        resource: "/var/www/html/z.txt", target_type: "user_home_t", object_class: "file", permissions: ["read"],
        operation_label: "read", outcome: "DENIED", observed_at: "2026-10-01T10:00:00Z" } };
    const occurrence = occurrencePage("001").occurrences[0];
    occurrence.host = { id: 10, hostname: "web-1" };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => url.endsWith("/occurrences/101") ? response(200, occurrence) : detailResponse(url, payload)));
    renderDetail();
    const context = await screen.findByRole("complementary", { name: "Investigation context" });
    expect(context).toHaveTextContent("/var/www/html/a file.txt");
    expect(context).not.toHaveTextContent("/var/www/html/z.txt");
    expect(within(context).getByRole("link", { name: "web-1" })).toHaveAttribute("href", "/hosts/10");
    expect(within(context).getByText("Latest access")).toBeVisible();
    expect(within(context).getByText("Active resource example")).toBeVisible();
    expect(within(context).getByRole("link", { name: "#101" })).toHaveAttribute("href", "/hosts/10/occurrences/101");
    expect(within(context).getByRole("link", { name: "#202" })).toHaveAttribute("href", "/hosts/20/occurrences/202");
    const observed = await screen.findByRole("region", { name: "Observed access" });
    expect(observed).toHaveTextContent("/var/www/html/a file.txt");
    expect(observed).not.toHaveTextContent("worker");
    expect(screen.getByText(/Policy analysis: Error/)).toBeVisible();
    expect(screen.getByRole("button", { name: "Post-restoration verification checklist" })).toHaveAttribute("aria-expanded", "false");
  });

  it("saves an assessment note without changing the existing assessment or issue status", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "Potential file-context mismatch" });
    await user.click(screen.getByRole("button", { name: /Issue actions/ }));
    expect(screen.queryByRole("button", { name: "Keep restriction" })).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Assessment note"), "Intentional boundary: no web access to private files");
    await user.click(screen.getByRole("button", { name: "Save assessment" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/disposition", expect.objectContaining({
      method: "PATCH", body: JSON.stringify({ disposition: "unclassified", signature_ids: [11], note: "Intentional boundary: no web access to private files" })
    }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/status"))).toBe(false);
  });

  it("loads occurrence evidence immediately and shows not-found issues accessibly", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByRole("heading", { name: "Potential file-context mismatch" });
    await waitFor(() => expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/7/occurrences?view=summary&page=1&limit=10"));
    expect(screen.queryByRole("button", { name: "Show recent occurrences" })).not.toBeInTheDocument();

    const notFoundFetch = vi.fn().mockResolvedValue(response(404, { error: { code: "not_found", message: "Resource not found" } }));
    vi.stubGlobal("fetch", notFoundFetch);
    renderDetail("/issues/999");
    expect(await screen.findByText("Issue not found")).toBeInTheDocument();
  });
});
