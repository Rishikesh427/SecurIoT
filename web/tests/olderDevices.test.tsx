import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { OlderDevices } from "../src/components/OlderDevices";
import type { DashDevice } from "../src/types";

const now = Date.parse("2026-11-15T04:00:00Z");
const device = (mac: string, label: string, status: string, last_seen: string) =>
  ({ mac, label, status, last_seen, ip: "10.42.0.9", risk: 10, band: "low" }) as DashDevice;

afterEach(cleanup);

it("lists only disconnected devices, most recently seen first, and opens details", () => {
  const select = vi.fn();
  render(<OlderDevices now={now} onSelect={select} devices={[
    device("a", "Arduino UNO Q", "offline", "2026-11-15T03:58:00Z"),
    device("b", "Phone", "normal", "2026-11-15T03:59:59Z"),
    device("c", "Projector (simulated fixture)", "offline", "2026-11-15T03:30:00Z"),
    device("d", "Camera", "quarantined", "2026-11-15T03:00:00Z"),
  ]} />);
  const rows = screen.getAllByRole("button");
  expect(rows.map((row) => row.textContent)).toEqual([
    expect.stringContaining("Arduino UNO Q"),
    expect.stringContaining("Projector"),
  ]);
  expect(rows[0].textContent).toContain("Last seen 2m ago");
  expect(rows[1].textContent).not.toContain("simulated fixture");
  fireEvent.click(rows[0]);
  expect(select).toHaveBeenCalledWith("a");
});

it("explains the section when nothing has disconnected", () => {
  render(<OlderDevices now={now} onSelect={vi.fn()} devices={[device("b", "Phone", "normal", "2026-11-15T03:59:59Z")]} />);
  expect(screen.getByText(/Anything that leaves your network will appear here/)).toBeTruthy();
});
