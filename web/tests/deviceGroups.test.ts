import { expect, it } from "vitest";
import { deviceGroups } from "../src/lib/deviceGroups";
import type { DashDevice } from "../src/types";
import type { Issue } from "../src/lib/issues";

it("counts each device once and does not count system issues as devices", () => {
  const devices = [
    { mac: "camera", band: "high", status: "normal" },
    { mac: "phone", band: "low", status: "normal" },
    { mac: "arduino", band: "medium", status: "normal" },
  ] as DashDevice[];
  const issues = [
    { mac: "camera", severity: "high" },
    { mac: "camera", severity: "medium" },
    { mac: "camera", severity: "medium" },
    { severity: "high", id: "learning_mode" },
  ] as Issue[];
  expect(deviceGroups(devices, issues)).toEqual({ safe: 1, caution: 1, danger: 1 });
});

it("classifies contained and critically flagged devices as danger", () => {
  const devices = [{ mac: "one", band: "low", status: "quarantined" }, { mac: "two", band: "low", status: "normal" }] as DashDevice[];
  expect(deviceGroups(devices, [{ mac: "two", severity: "critical" }] as Issue[])).toEqual({ safe: 0, caution: 0, danger: 2 });
});

it("uses distinct device issues instead of risk points or system notices", async () => {
  const { deviceIssueCounts } = await import('../src/lib/deviceGroups');
  const devices = [{ mac: 'camera', risk: 75 }] as DashDevice[];
  const issues = [{ id: 'password', mac: 'camera' }, { id: 'telnet', mac: 'camera' }, { id: 'password', mac: 'camera' }, { id: 'learning_mode' }] as Issue[];
  expect(deviceIssueCounts(devices, issues)).toEqual({ camera: 2 });
});
