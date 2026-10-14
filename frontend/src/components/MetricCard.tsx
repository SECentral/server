import { Card, CardBody, CardTitle, Title } from "@patternfly/react-core";

export function MetricCard({ label, value, detail, href, className = "" }: { label: string; value: number; detail?: string; href?: string; className?: string }) {
  return (
    <Card isClickable={Boolean(href)} isCompact className={`metric-card ${className}`} component={href ? "a" : "div"} href={href} aria-label={`${label} ${value}`}>
      <CardTitle>{label}</CardTitle>
      <CardBody>
        <Title headingLevel="h3" size="3xl" className="metric-value">{value.toLocaleString("en-US")}</Title>
        {detail && <span className="pf-v6-u-color-200 metric-detail">{detail}</span>}
      </CardBody>
    </Card>
  );
}
