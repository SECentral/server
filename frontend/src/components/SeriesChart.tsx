import { Card, CardBody, CardTitle } from "@patternfly/react-core";
import { Chart, ChartAxis, ChartBar, ChartContainer, ChartThemeColor } from "@patternfly/react-charts/victory";
import { useEffect, useRef, useState } from "react";
import type { OverviewSeriesPoint } from "../api/overview";

function dayLabel(date: string): string {
  const weekday = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][new Date(`${date}T00:00:00Z`).getUTCDay()];
  return `${weekday} ${Number(date.slice(8))}`;
}

export function SeriesChart({ title, points }: { title: string; points: OverviewSeriesPoint[] }) {
  const plotRef = useRef<HTMLDivElement>(null);
  const [chartSize, setChartSize] = useState<{ width: number; height: number } | null>(() =>
    typeof ResizeObserver === "undefined" ? { width: 420, height: 240 } : null
  );
  const total = points.reduce((sum, point) => sum + point.value, 0);
  const max = Math.max(1, ...points.map((point) => Math.ceil(point.value)));
  const data = points.map((point) => ({ x: dayLabel(point.date), y: point.value }));
  const tickValues = [...new Set([0, Math.ceil(max / 2), max])];
  const description = `${title}. Daily values: ${points.map((point) => `${dayLabel(point.date)} ${point.date}: ${point.value}`).join(", ")}. Total: ${total}.`;

  useEffect(() => {
    const plot = plotRef.current;
    if (!plot || typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver(([entry]) => {
      const width = Math.round(entry.contentRect.width);
      const height = Math.round(entry.contentRect.height);
      if (width > 0 && height > 0) {
        setChartSize((current) => current?.width === width && current.height === height ? current : { width, height });
      }
    });
    observer.observe(plot);
    return () => observer.disconnect();
  }, []);

  return (
    <Card className="overview-trend-card">
      <CardTitle component="h3">{title}</CardTitle>
      <CardBody>
        <div className="overview-trend-summary">
          <span className="pf-v6-u-color-200">Last 7 days</span>
          <strong>{total} total</strong>
        </div>
        {points.length > 0 && total === 0 && <p className="pf-v6-u-color-200">No activity recorded in this period.</p>}
        <div className="overview-chart-plot" ref={plotRef}>
          {chartSize && <Chart
            ariaTitle={title}
            ariaDesc={description}
            containerComponent={<ChartContainer responsive role="img" aria-label={title} />}
            domain={{ y: [0, max] }}
            domainPadding={{ x: 18 }}
            height={chartSize.height}
            padding={{ bottom: 42, left: 40, right: 12, top: 28 }}
            themeColor={ChartThemeColor.blue}
            width={chartSize.width}
          >
            <ChartAxis
              tickValues={data.map((point) => point.x)}
              style={{
                axis: { stroke: "var(--pf-t--global--border--color--subtle)", strokeWidth: 1 },
                tickLabels: { fill: "var(--pf-t--global--text--color--regular)", fontSize: 15 }
              }}
            />
            <ChartAxis
              dependentAxis
              showGrid
              tickValues={tickValues}
              style={{
                axis: { stroke: "var(--pf-t--global--border--color--subtle)", strokeWidth: 1 },
                grid: { stroke: "var(--pf-t--global--border--color--subtle)", strokeWidth: 1, opacity: 0.45 },
                tickLabels: { fill: "var(--pf-t--global--text--color--regular)", fontSize: 14 }
              }}
            />
            <ChartBar
              data={data}
              barRatio={0.82}
              labels={({ datum }) => datum.y === 0 ? "" : String(datum.y)}
              style={{ labels: { fill: "var(--pf-t--global--text--color--regular)", fontSize: 18 } }}
            />
          </Chart>}
        </div>
      </CardBody>
    </Card>
  );
}
