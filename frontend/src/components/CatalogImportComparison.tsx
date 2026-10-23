import { Card, CardBody, CardTitle } from "@patternfly/react-core";
import { Link } from "react-router-dom";
import type * as Types from "../api/generated/types.gen";

export function CatalogImportComparison({ report }: { report: Types.CatalogImportComparison | null | undefined }) {
  if (!report) return null;
  return (
    <Card isCompact>
      <CardTitle>Recorded import comparison</CardTitle>
      <CardBody>
        <p>Result: {report.status.replaceAll("_", " ")}. {report.reason?.replaceAll("_", " ")}</p>
        <p>Imported revision <Link to={`/catalogs/${report.to_revision.id}`}>{report.to_revision.id}</Link> · <code>{report.to_revision.content_digest}</code></p>
        {report.from_revision && <p>Compared from existing revision <Link to={`/catalogs/${report.from_revision.id}`}>{report.from_revision.id}</Link> · <code>{report.from_revision.content_digest}</code></p>}
        {report.changes && <>
          <h3>Structural changes</h3>
          <p>Loaded-policy identity changed: {report.changes.policy.loaded_policy_digest_changed ? "yes" : "no"}; packages changed: {report.changes.policy.packages_changed ? "yes" : "no"}.</p>
          <table className="pf-v6-c-table pf-m-compact" aria-label="Recorded catalog changes">
            <thead><tr><th scope="col">Family</th><th scope="col">Change</th><th scope="col">Count</th><th scope="col">Bounded samples</th></tr></thead>
            <tbody>{(["booleans", "ports"] as const).flatMap((family) => Object.entries(report.changes![family]).map(([kind, change]) => (
              <tr key={`${family}-${kind}`}><td>{family === "booleans" ? "Booleans" : "Ports"}</td><td>{kind.replaceAll("_", " ")}</td><td>{change.count}</td>
                <td>{change.samples.map((sample) => typeof sample === "string" ? sample : JSON.stringify(sample)).join(", ") || "—"}{change.truncated && " (additional changes omitted)"}</td></tr>
            )))}</tbody>
          </table>
        </>}
        {report.status === "ambiguous" && <p>{report.candidate_count} existing compatible revisions; no predecessor was chosen.</p>}
      </CardBody>
    </Card>
  );
}
