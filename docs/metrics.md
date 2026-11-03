# Prometheus domain metrics

SECentral exposes database-backed product gauges at both `/metrics` and
`/metrics/`. These are installation-wide administrative aggregates across all
organizations, without organization or per-entity labels. They are not Rails,
request, or process instrumentation.

## Enable and scrape

Generate a dedicated secret with `openssl rand -hex 32` and set it as
`SECENTRAL_METRICS_TOKEN` in the deployment environment. With the supplied Compose
deployment, set it in `.env` and recreate the server container. Restart/recreate
the server after configuration changes. Keep this secret separate from the
ingestion key and browser credentials.

Unset, empty, or whitespace-only values disable the endpoint (`404`). A nonblank
value enables it and requires `Authorization: Bearer <token>`; missing or invalid
credentials return `401`. Nonblank secrets are compared exactly, without trimming.
Use a generated token without whitespace. Browser sessions and ingestion keys do
not independently grant access. Responses are not cacheable.

Use the existing HTTPS endpoint with certificate verification enabled. Restrict
network access as defense in depth. Do not put credentials in URLs or commit them
to configuration repositories. Store the token in a file readable by Prometheus
and restrict that file's permissions:

```yaml
scrape_configs:
  - job_name: secentral
    scheme: https
    metrics_path: /metrics
    scrape_interval: 60s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/secentral-metrics-token
    static_configs:
      - targets: [secentral.example.com]
```

The endpoint serves Prometheus text format 0.0.4. Query failures fail the scrape;
they do not produce successful partial results or fabricated zero counts.

## Metric contract

All families below are **gauges**, not monotonic counters. Counts can decrease
through corrections or future retention. In particular,
`rate(secentral_occurrences[5m])` is not an ingestion-rate measurement.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `secentral_issues` | `status`, `disposition` | Issues by status and issue-level disposition. |
| `secentral_regressed_issues` | none | Currently regressed issues; a subset of open issues. |
| `secentral_occurrences` | none | Current retained occurrences, including ungrouped ones, excluding superseded interpretations. |
| `secentral_ungrouped_occurrences` | none | Current occurrences without an associated issue. |
| `secentral_hosts` | none | All registered hosts, regardless of recent contact. |
| `secentral_hosts_by_selinux_enforcement` | `state` | Registered hosts classified by fresh, trusted host-wide enforcement evidence. |
| `secentral_hosts_with_open_issues` | none | Distinct hosts with current occurrences associated with open issues. |
| `secentral_agent_installations` | `state` | All installations, including unbound ones, classified by recent contact. |

Known label combinations are always emitted, including zero values. There are no
hostnames, IDs, paths, evidence payloads, or SELinux types in labels.

### Issues and regressions

Statuses are `open`, `resolved`, and `ignored`. Dispositions are `unclassified`,
`under_investigation`, `expected_harmless`, `application_configuration`,
`labeling_configuration`, `policy_required`, `possible_policy_package_defect`,
`suspicious_behavior`, and issue-level aggregate `mixed`. All 27 combinations are
emitted. Each issue is counted once, not once per signature or occurrence.

Examples:

```promql
sum(secentral_issues)
sum(secentral_issues{status="open"})
secentral_issues{status="open",disposition="suspicious_behavior"}
```

A currently regressed issue is an open issue that was reopened after its latest
recorded resolution, or has a recorded reopening but no recorded resolution. Historical
regressions alone do not qualify. These issues remain in their open/disposition
bucket: do not add `secentral_regressed_issues` to issue totals.

### Agent contact

The `reporting`, `stale`, and `offline` states describe **recent agent contact**
through either heartbeats or event submissions. The existing intervals are
15 minutes for stale contact and 60 minutes for offline; installations that have
never contacted the server are also offline.

Recent contact does not prove capture completeness, collection health, an empty
backlog, or delivery health. Installations are counted, not hosts or an expected
fleet.

### Host enforcement evidence

Each registered host contributes exactly once to one of four states:

- `enforcing`: SELinux is reported in enforcing mode.
- `permissive`: SELinux is reported in permissive mode.
- `disabled`: SELinux is reported as disabled.
- `unknown`: there is insufficient current, trustworthy enforcement evidence.

The counts sum to `secentral_hosts`. They use the existing **15-minute
configuration freshness interval**. Missing or stale configuration, an unknown or
unrecognized mode, or enforcement evidence invalidated by a change or reported
uncertainty results in `unknown`. Recent agent contact alone does not keep
configuration evidence fresh.
`unknown` does not necessarily mean offline, unhealthy, or disabled.

These are reported host-wide modes, **not live checks**. An `enforcing` host may
still have permissive domains; these counts do not guarantee enforcement for
every domain or operation. Registered hosts are not an expected-fleet inventory,
so these counts are not coverage ratios.

## Scrape consistency and cost

Start with a **60-second scrape interval**. Each scrape queries the database;
frequent scraping adds load, especially as retained data grows. Minor differences
between metric families can occur while agents are reporting concurrently.

This endpoint does not provide capture/spool diagnostics, ingestion throughput or
latency, expected-fleet coverage, dashboards, or alert rules.
