import type { DashDevice } from "../types";
import type { Issue } from "./issues";
import { isContained } from "./format";

/** Mutually exclusive device counts, excluding system-wide issues. */
export function deviceGroups(devices: DashDevice[], issues: Issue[]) {
  const groups = { safe: 0, caution: 0, danger: 0 };
  for (const device of devices) {
    const ownIssues = issues.filter((issue) => issue.mac === device.mac);
    if (isContained(device.status) || device.band === "high" || ownIssues.some((i) => i.severity === "critical")) groups.danger++;
    else if (device.status === "offline" || device.band === "medium" || ownIssues.length) groups.caution++;
    else groups.safe++;
  }
  return groups;
}

/** Count listed, actionable device issues; exclude system-wide notices. */
export function deviceIssueCounts(devices: DashDevice[], issues: Issue[]) {
  return Object.fromEntries(devices.map((device) => [device.mac,
    new Set(issues.filter((issue) => issue.mac === device.mac).map((issue) => issue.id)).size,
  ]));
}
