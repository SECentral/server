import { EmptyState, EmptyStateBody } from "@patternfly/react-core";

export function Placeholder() {
  return (
    <EmptyState titleText="This screen is being migrated">
      <EmptyStateBody>It will be served by the React application as the migration progresses.</EmptyStateBody>
    </EmptyState>
  );
}
