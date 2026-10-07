import { useState } from "react";
import type { EffectivePermissiveDomains as DomainState } from "../api/generated/types.gen";

export function EffectivePermissiveDomains({ state }: { state?: DomainState }) {
  const [page, setPage] = useState(0);
  const domains = state?.status === "observed" ? state.domains : null;
  const count = domains?.length ?? 0;
  return <section aria-label="Effective permissive domains">
    <h3>Effective permissive domains{domains ? ` (${count})` : ""}</h3>
    {domains ? count === 0 ? <p>No permissive domains in the observed loaded policy.</p> : <>
      <ul>{domains.slice(page * 20, (page + 1) * 20).map((domain) => <li key={domain}><code>{domain}</code></li>)}</ul>
      {count > 20 ? <div>
        <button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous domains</button>{" "}
        <span>Page {page + 1} of {Math.ceil(count / 20)}</span>{" "}
        <button type="button" disabled={(page + 1) * 20 >= count} onClick={() => setPage((value) => value + 1)}>Next domains</button>
      </div> : null}
    </> : <p>Unknown — {state?.reason ?? (state?.status === "pending" ? "exact-policy analysis is pending" : "exact loaded policy is currently unavailable")}.</p>}
    <p className="pf-v6-u-color-200">Effective loaded policy; not global host mode or stored semanage configuration.</p>
    {state?.policy_identity ? <details><summary>Exact policy provenance</summary><code>{state.policy_identity}</code></details> : null}
  </section>;
}
