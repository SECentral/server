import { act, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { SeriesChart } from "./SeriesChart";

it("waits for usable plot dimensions and keeps the chart responsive", () => {
  let resize: (width: number, height: number) => void;
  const disconnect = vi.fn();
  vi.stubGlobal("ResizeObserver", class {
    constructor(callback: ResizeObserverCallback) {
      resize = (width, height) => callback([{ contentRect: { width, height } } as ResizeObserverEntry], this as unknown as ResizeObserver);
    }
    observe() {}
    disconnect = disconnect;
  });
  const { unmount } = render(<SeriesChart title="Daily events" points={[{ date: "2026-10-21", value: 3 }]} />);

  expect(screen.getByText("3 total")).toBeInTheDocument();
  expect(screen.queryByRole("img")).not.toBeInTheDocument();
  act(() => resize(0, 0));
  expect(screen.queryByRole("img")).not.toBeInTheDocument();
  act(() => resize(640, 200));
  const chart = screen.getByRole("img", { name: "Daily events" });
  expect(chart).toHaveAttribute("viewBox", "0 0 640 200");
  expect(document.getElementById(chart.getAttribute("aria-describedby")!)).toHaveTextContent("2026-10-21: 3");
  act(() => resize(320, 160));
  expect(screen.getByRole("img", { name: "Daily events" })).toHaveAttribute("viewBox", "0 0 320 160");
  unmount();
  expect(disconnect).toHaveBeenCalledOnce();
});
