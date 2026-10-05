import { render, screen, waitFor, within } from "@testing-library/react";
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
    occurrences_count: fleetLive ? 16 : scenario === "repeated" ? 5 : 2, affected_hosts: fleetLive ? 3 : 1, disposition_history: []
  } as IssueDetailResponse["issue"];
  return {
    issue,
    intelligence: {
      affected_hosts: fleetLive ? 3 : 1,
      paths: fleetLive ? ["/usr/bin/id", "/usr/bin/stat"] : basename ? [] : database ? ["/srv/secentral-s004-mariadb/ibdata1"] : execution ? ["/var/www/cgi-bin/secentral-s005-helper.sh"] : port ? [] : scenario === "missing-observation" ? ["/var/www/html/secentral-test.html"] : ["/var/www/html/secentral-test.html"],
      names: basename ? ["secentral-s001-basename-20260930"] : scenario === "missing-observation" ? [] : [],
      occurrence_time: {}, fleet: {}
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
    if (url.includes("view=summary")) {
      const occurrences = occurrencePage(scenario).occurrences;
      return Promise.resolve(response(200, { occurrences: occurrences.map((item) => ({ id: item.id, occurred_at: item.occurred_at, host: item.host, resource: item.normalized_denial.target_paths[0] ?? "secentral-test.html", absolute_path: item.normalized_denial.target_paths.length > 0, target_type: item.normalized_denial.target_type, permissions: item.normalized_denial.permissions })), meta: { page: 1, page_size: 25, total: occurrences.length, total_pages: 1 } }));
    }
    if (url.startsWith(`/api/v1/issues/${issueId}/occurrences/`)) return Promise.resolve(response(200, occurrencePage(scenario).occurrences.find((item) => url.endsWith(`/${item.id}`))));
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
  function readFinding() {
    const rule = "allow httpd_t user_home_type:file { getattr ioctl lock open read }; [ httpd_read_user_content ]:True";
    const booleans = [{ name: "httpd_read_user_content", current: false, status: "observed" }];
    return { ...conditionalDiagnosis("002"), title: "A matching SELinux read rule was inactive", operation: "read", permission: "read", permissions: ["read"], target_class: "file", target_type: "user_home_t", destination_port: undefined, next_step: "Confirm whether this workload is intended to read files labeled user_home_t before considering a change.", conditional_rules: [{ rule, expression: "httpd_read_user_content", state: "inactive" }], condition_boolean_states: [{ rule, expression: "httpd_read_user_content", state: "inactive", booleans }] };
  }

  it("001-A shows conditional-read evidence and the independent missing-path limitation without exposing provenance", async () => {
    const payload = detailPayload("basename");
    const finding = readFinding();
    payload.issue.occurrences_count = 2057;
    payload.intelligence.names = ["0000.txt", "0001.txt", "secentral-test.html"];
    payload.intelligence.resource_summary = { absolute_path_occurrences: 0, without_absolute_path_occurrences: 2057, name_count: 2050, path_count: 0, process_command: "httpd" };
    payload.diagnosis = finding;
    payload.findings = [{ diagnosis: finding, occurrence_count: 2057, observation_count: 0 }];
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(200, payload)));
    const user = userEvent.setup();
    renderDetail();
    expect(await screen.findByRole("heading", { level: 1, name: "httpd was denied reading files labeled user_home_t." })).toBeInTheDocument();
    expect(screen.getByText(/2,057 denials · 1 server · 2,050 filenames/)).toBeInTheDocument();
    expect(screen.getByText(/httpd_read_user_content/, { selector: ".issue-condition-summary code" })).toBeVisible();
    expect(document.querySelector(".issue-condition-summary")).toHaveTextContent("Off");
    await user.click(screen.getByText("Additional investigation", { selector: "summary" }));
    expect(screen.getByRole("heading", { name: "Path-based label check unavailable" })).toBeVisible();
    expect(screen.getByText(/cannot determine whether/)).toHaveTextContent("user_home_t");
    expect(screen.queryByText("No evidence-backed explanation is available yet.")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Potential file-context mismatch" })).not.toBeInTheDocument();
    const explanation = document.querySelector(".issue-primary-finding .issue-selinux-explanation") as HTMLElement;
    expect(within(explanation).getByText(/allow httpd_t user_home_type:file/)).not.toBeVisible();
    await user.click(within(explanation).getByText("SELinux explanation"));
    expect(within(explanation).getByText(/allow httpd_t user_home_type:file/)).toBeVisible();
    expect(within(explanation).getByText(/user_home_t:file/)).toBeVisible();
    expect(within(explanation).getByText("read", { selector: "code" })).toBeVisible();
    expect(within(explanation).getByText("sha256:fixture-policy-identity")).not.toBeVisible();
    await user.click(within(explanation).getByText("Policy provenance"));
    expect(within(explanation).getByText("sha256:fixture-policy-identity")).toBeVisible();
    expect(within(explanation).getByText("2026-09-30T16:26:00Z")).toBeVisible();
  });

  it("keeps an independent conditional-read finding alongside a primary file-context mismatch", async () => {
    const payload = detailPayload("001");
    payload.fleet_explanation.state = "disagreement";
    payload.findings = [{ diagnosis: payload.diagnosis!, occurrence_count: 2, observation_count: 1 }, { diagnosis: readFinding(), occurrence_count: 2, observation_count: 0 }];
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(200, payload)));
    renderDetail();
    expect(await screen.findByRole("heading", { name: "Potential file-context mismatch" })).toBeVisible();
    await userEvent.setup().click(screen.getByText("Additional investigation", { selector: "summary" }));
    expect(screen.getByText("A matching SELinux read rule was inactive · 2 denials")).toBeVisible();
    expect(screen.getByLabelText("Finding coverage")).toHaveTextContent("2 of 2 denials");
    expect(screen.getByLabelText("Finding coverage")).toHaveTextContent("1 distinct inspection");
    expect(screen.getByText(/Finding evidence varies between occurrences/)).toBeInTheDocument();
  });
  it("compares AVC-time and later expected file types for accepted Scenario 001", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Potential file-context mismatch" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Label SELinux used/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Expected for this path/ })).toBeInTheDocument();
    expect(screen.getByText("user_home_t", { selector: ".issue-context-type" })).toBeInTheDocument();
    expect(screen.getByText("httpd_sys_content_t", { selector: ".issue-context-type" })).toBeInTheDocument();
    expect(screen.getAllByText("/var/www/html/secentral-test.html").length).toBeGreaterThan(0);
    expect(screen.getByText("Checked after the denial")).toBeInTheDocument();
    expect(screen.getByText("At the denial")).toBeInTheDocument();
    expect(screen.getByText("Different types")).toBeInTheDocument();
    const fullContext = document.querySelector(".issue-primary-finding .issue-selinux-explanation") as HTMLElement;
    expect(fullContext).not.toHaveAttribute("open");
    await user.click(within(fullContext).getByText("Why these labels matter"));
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
    expect(screen.getByText(/Identify the complete absolute path/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Potential file-context mismatch" })).not.toBeInTheDocument();
    expect(screen.queryByText("Check for additional fleet correlations")).not.toBeInTheDocument();
  });

  it("shows Scenario 002 operation, destination port, each inactive boolean, and exact rule", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "002");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: "httpd was blocked from connecting to TCP port 12345 (destination)." })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Matching conditional policy paths were inactive" })).toBeInTheDocument();
    expect(screen.getByText(/TCP port 12345 \(destination\)/)).toBeInTheDocument();
    expect(screen.getAllByText("httpd_can_network_connect").length).toBeGreaterThan(0);
    expect(document.querySelector(".issue-condition-summary li")).toHaveTextContent("httpd_can_network_connect");
    expect(document.querySelector(".issue-condition-summary li")).toHaveTextContent("Off");
    expect(screen.getAllByText("nis_enabled").length).toBeGreaterThan(0);
    const selinuxExplanation = document.querySelector("details.issue-selinux-explanation");
    expect(selinuxExplanation).not.toHaveAttribute("open");
    await user.click(within(selinuxExplanation as HTMLElement).getByText("SELinux explanation"));
    expect(within(selinuxExplanation as HTMLElement).getByText(/allow httpd_t port_type/)).toBeVisible();
    expect(within(selinuxExplanation as HTMLElement).getByText(/allow nsswitch_domain unreserved_port_t/)).toBeVisible();
    expect(within(selinuxExplanation as HTMLElement).getByText(/controls connecting a socket to a labeled network port/)).toBeVisible();
    expect(screen.getByText(/independent rules, not a requirement to enable every listed setting/)).toBeInTheDocument();
    const provenance = document.querySelector("details.issue-policy-provenance");
    expect(provenance).not.toHaveAttribute("open");
    await user.click(within(provenance as HTMLElement).getByText("Policy provenance"));
    expect(within(provenance as HTMLElement).getByText("sha256:fixture-policy-identity")).toBeInTheDocument();
    expect(within(provenance as HTMLElement).getByText("2026-09-30T16:26:00Z")).toBeInTheDocument();
    await user.click(screen.getByText("Check next · limitations & coverage"));
    expect(screen.getByText(/Checkpoint boolean state does not tell us whether this workload should have this capability/)).toBeInTheDocument();
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
    const fetchMock = vi.fn((url: string) => Promise.resolve(response(200, /occurrences\/101$/.test(url) ? selected : url.includes("view=summary") ? {occurrences: [{id: 101, occurred_at: "2026-10-01T10:42:20Z", host: {id: 10, hostname: "agent-test"}, resource: "TCP/12345", absolute_path: false, permissions: ["name_connect"], target_type: "unreserved_port_t"}], meta: {page: 1, page_size: 25, total: 3, total_pages: 1}} : payload)));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();
    expect(await screen.findByRole("heading", {level: 1, name: "httpd was denied outbound TCP connections."})).toBeInTheDocument();
    expect(screen.getByText(/TCP\/12345 \(2 denials\).*TCP\/12346 \(1 denial\)/)).toBeVisible();
    expect(screen.getByLabelText("Finding coverage")).toHaveTextContent("cover 2 of 3 denials");
    await user.click(screen.getByText("Additional investigation", { selector: "summary" }));
    expect(screen.getByText(/a matching conditional rule was active at the associated checkpoint/)).toBeVisible();
    expect(screen.getByText(/Not every denial has a supported finding/)).toBeVisible();
    await user.click(screen.getByRole("button", {name: "Show recent occurrences"}));
    const table = await screen.findByRole("table", {name: "Occurrence summary"});
    expect(within(table).getByText("TCP/12345")).toBeVisible();
    expect(within(table).queryByText("Basename only")).not.toBeInTheDocument();
    expect(within(table).queryByText("Path evidence")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => /occurrences\/\d+$/.test(url))).toBe(false);
    await user.click(within(table).getByRole("button", {name: "Inspect occurrence 101"}));
    expect(await screen.findByText(/Occurrence #101/)).toHaveTextContent("TCP/12345");
    expect(screen.queryByText(/TCP\/127\.0\.0\.1/)).not.toBeInTheDocument();
  });

  it("keeps Scenario 003 bind semantics and does not prescribe a port mapping", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "003");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: "httpd was blocked from binding locally on TCP port 12345 (local bind)." })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "A relevant SELinux allow rule was inactive" })).toBeInTheDocument();
    expect(screen.getAllByText(/local port bind/).length).toBeGreaterThan(0);
    expect(screen.getByText(/TCP port 12345 \(local bind\)/)).toBeInTheDocument();
    expect(screen.getAllByText("nis_enabled").length).toBeGreaterThan(0);
    expect(screen.getByText(/whether this workload is expected to bind TCP port 12345/)).toBeInTheDocument();
    expect(screen.queryByText(/map.*http_port_t/i)).not.toBeInTheDocument();
  });

  it("shows Scenario 004 no-matching-allow without inferring workload intent", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "004");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /mariadbd was blocked from checking file metadata/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "No matching SELinux allow was found for this access" })).toBeInTheDocument();
    expect(screen.getByText(/no allow rule for checking metadata on this file labeled var_t/)).toBeInTheDocument();
    expect(screen.getByText(/\/srv\/secentral-s004-mariadb\/ibdata1/)).toBeInTheDocument();
    expect(screen.getByText(/cannot infer the intended database path or label/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View source event" })).toHaveAttribute("href", "/hosts/10/occurrences/104");
    expect(screen.queryByText(/generate custom policy/i)).not.toBeInTheDocument();
  });

  it("shows Scenario 005 execute evidence while leaving transition intent unknown", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "005");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByRole("heading", { level: 1, name: /httpd could not execute \/var\/www\/cgi-bin/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "A relevant SELinux allow rule was inactive" })).toBeInTheDocument();
    expect(screen.getAllByText(/\/var\/www\/cgi-bin\/secentral-s005-helper\.sh/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("httpd_unified").length).toBeGreaterThan(0);
    expect(screen.getByText(/does not establish that a domain transition was attempted or intended/)).toBeInTheDocument();
  });

  it("keeps Issue 1932 in fleet agreement while disclosing its two policy identities", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "fleet-live");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/1932");

    expect(await screen.findByRole("heading", { level: 1, name: "runcon could not start /usr/bin/id." })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "No matching SELinux allow was found for this access" })).toBeInTheDocument();
    expect(screen.getByText(/The evaluated policy has no allow rule for this launch/)).toBeInTheDocument();
    within(document.querySelector(".issue-primary-finding .issue-selinux-explanation") as HTMLElement).queryAllByText(/entrypoint/).forEach((element) => expect(element).not.toBeVisible());
    expect(screen.getByText(/16 retained denials/)).toBeInTheDocument();
    expect(screen.getByText(/3 affected hosts/)).toBeInTheDocument();
    expect(screen.getByText(/Where this occurs/).parentElement).toHaveTextContent("Same explanation across affected hosts");

    const why = document.querySelector("details.issue-selinux-explanation");
    expect(why).not.toHaveAttribute("open");
    await user.click(within(why as HTMLElement).getByText("SELinux explanation"));
    expect(within(why as HTMLElement).getAllByText(/entrypoint/).length).toBeGreaterThan(0);
    const provenance = within(why as HTMLElement).getByText("Policy provenance").closest("details");
    expect(provenance).not.toBeNull();
    expect(provenance).not.toHaveAttribute("open");
    await user.click(within(provenance as HTMLElement).getByText("Policy provenance"));
    expect(within(provenance as HTMLElement).getByText("sha256:646dfbc98b55dba4e8622f4fbb1b23cb5e0c2c133144361d05cbc2a0c6cd2cff")).toBeVisible();

    const host = await screen.findByRole("link", { name: "secentral-agent-test" });
    const listItem = host.closest("li");
    expect(listItem).not.toBeNull();
    expect(within(listItem!).getByText("Same explanation across 4 occurrences")).toBeInTheDocument();
    within(listItem!).getAllByText(/sha256:/).forEach((value) => expect(value).not.toBeVisible());
    await user.click(within(listItem!).getByText("Technical provenance"));
    expect(within(listItem!).getByText(/sha256:6029a986/)).toBeInTheDocument();
    expect(within(listItem!).getByText(/sha256:96604a22/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "secentral-alma-9-clean" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "secentral-alma9-test" })).toBeInTheDocument();
  });

  it("loads secondary fleet analysis only when requested and reports when no correlation is supported", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "fleet-live");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/1932");

    await screen.findByRole("heading", { level: 1, name: "runcon could not start /usr/bin/id." });
    expect(fetchMock.mock.calls.map(([url]) => String(url))).not.toContain("/api/v1/issues/1932/analysis");
    await user.click(screen.getByText("Check for additional fleet correlations"));
    expect(await screen.findByText(/No additional fleet correlation is supported/)).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/1932/analysis");
  });

  it("shows repeated occurrences as scan-friendly rows, then readable detail before raw evidence", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "repeated");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    expect(await screen.findByText("5 retained denials")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show recent occurrences" }));
    expect(await screen.findByText("5 retained denials · 1–5 of 5")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Occurrence summary" })).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url)).some((url) => /occurrences\/\d+$/.test(url))).toBe(false);
    await user.click(screen.getAllByRole("button", { name: /Inspect occurrence/ })[0]);
    await screen.findByText(/Occurrence #101/);
    const summary = screen.getAllByText(/secentral-agent-test/).find((element) => element.closest("summary"))?.closest("summary");
    expect(summary).toBeDefined();
    await user.click(summary!);
    const occurrenceHeading = (await screen.findAllByRole("heading", { name: "What happened" })).find((heading) => heading.tagName === "H3");
    expect(occurrenceHeading?.nextElementSibling).toHaveTextContent("was denied file read");
    expect(screen.queryByText(RAW_AVC)).not.toBeInTheDocument();

    const openOccurrence = document.querySelector(".issue-occurrence[open]");
    expect(openOccurrence).not.toBeNull();
    await user.click(within(openOccurrence as HTMLElement).getByText("Technical details and raw audit records"));
    await user.click(within(openOccurrence as HTMLElement).getByRole("button", { name: "Raw AVC" }));
    expect(await screen.findByText(RAW_AVC)).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });

  it("honors existing occurrence deep links by opening the occurrence section", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail("/issues/7?tab=occurrences");

    expect((await screen.findAllByText("secentral-agent-test")).length).toBeGreaterThan(0);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/7/occurrences?view=summary&page=1");
  });

  it("replaces occurrence pages instead of appending rows and never requests raw evidence for the table", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "basename");
    const fallback = fetchMock.getMockImplementation()!;
    fetchMock.mockImplementation((url: string, request?: { method?: string; body?: string }) => {
      if (url.includes("view=summary")) {
        const page = Number(new URL(url, "http://localhost").searchParams.get("page"));
        return Promise.resolve(response(200, { occurrences: [{ id: page, occurred_at: "2026-10-01T08:47:03Z", host: { id: 10, hostname: "agent-test" }, resource: `page-${page}.txt`, absolute_path: false, target_type: "user_home_t", permissions: ["read"] }], meta: { page, page_size: 25, total: 2057, total_pages: 83 } }));
      }
      return fallback(url, request);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail("/issues/7?tab=occurrences");
    expect(await screen.findByText("page-1.txt")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("page-2.txt")).toBeInTheDocument();
    expect(screen.queryByText("page-1.txt")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("page-1.txt")).toBeInTheDocument();
    expect(fetchMock.mock.calls.map(([url]) => String(url)).some((url) => /occurrences\/\d+$/.test(url))).toBe(false);
  });

  it("states when an expected-context observation is missing for a retained absolute path", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "missing-observation");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();

    expect(await screen.findByText(/no event-linked expected-context observation is available/)).toBeInTheDocument();
    expect(screen.getByText(/unknown state, not evidence that the access is safe/)).toBeInTheDocument();
  });

  it("keeps workflow available in compact Actions and updates lifecycle status", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderDetail();

    await screen.findByRole("heading", { name: "Potential file-context mismatch" });
    expect(screen.getByText("Actions · Unclassified")).toBeInTheDocument();
    await user.click(screen.getByText("Actions · Unclassified"));
    await user.selectOptions(screen.getByLabelText("Issue status"), "resolved");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/v1/issues/7/status", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "resolved" }) })));
  });

  it("loads occurrence evidence immediately and shows not-found issues accessibly", async () => {
    const fetchMock = vi.fn();
    mockApi(fetchMock, "001");
    vi.stubGlobal("fetch", fetchMock);
    renderDetail();
    await screen.findByRole("heading", { name: "Potential file-context mismatch" });
    expect(fetchMock.mock.calls.map(([url]) => String(url))).not.toContain("/api/v1/issues/7/occurrences?view=summary&page=1");
    await userEvent.setup().click(screen.getByRole("button", { name: "Show recent occurrences" }));
    await waitFor(() => expect(fetchMock.mock.calls.map(([url]) => String(url))).toContain("/api/v1/issues/7/occurrences?view=summary&page=1"));

    const notFoundFetch = vi.fn().mockResolvedValue(response(404, { error: { code: "not_found", message: "Resource not found" } }));
    vi.stubGlobal("fetch", notFoundFetch);
    renderDetail("/issues/999");
    expect(await screen.findByText("Issue not found")).toBeInTheDocument();
  });
});
