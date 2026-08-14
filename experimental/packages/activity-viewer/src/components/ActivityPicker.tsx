/**
 * Left pane — list of activities with substring filter, badges for
 * launcher/exported, click to select.
 */

import React, { useMemo, useState } from "react";
import type { ActivitySummary } from "../types";

export interface ActivityPickerProps {
  activities: ActivitySummary[];
  selectedName: string | null;
  onSelect: (name: string) => void;
}

export const ActivityPicker: React.FC<ActivityPickerProps> = ({
  activities, selectedName, onSelect,
}) => {
  const [filter, setFilter] = useState("");

  const filtered = useMemo(() => {
    if (!filter.trim()) return activities;
    const q = filter.toLowerCase();
    return activities.filter((a) =>
      a.name.toLowerCase().includes(q)
      || (a.label?.toLowerCase().includes(q) ?? false)
    );
  }, [activities, filter]);

  return (
    <div className="pap-picker">
      <div className="pap-picker__header">
        <span>Activities</span>
        <input
          className="pap-picker__filter"
          placeholder="filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          spellCheck={false}
        />
      </div>
      <div className="pap-picker__list">
        {filtered.length === 0 && (
          <div className="pap-empty">
            {activities.length === 0
              ? "No activities found in manifest."
              : `No matches for "${filter}".`}
          </div>
        )}
        {filtered.map((a) => {
          const isActive = a.name === selectedName;
          // Show class-name's last segment as the primary line; full FQN on hover.
          const shortName = a.name.split(".").pop() ?? a.name;
          return (
            <div
              key={a.name}
              className={[
                "pap-picker__item",
                isActive ? "pap-picker__item--active" : "",
              ].join(" ")}
              onClick={() => onSelect(a.name)}
              title={a.name}
            >
              <span className="pap-picker__item-name">{shortName}</span>
              {a.label && (
                <span className="pap-picker__item-label">{a.label}</span>
              )}
              {(a.isLauncher || a.exported) && (
                <div className="pap-picker__badges">
                  {a.isLauncher && (
                    <span className="pap-picker__badge pap-picker__badge--launcher">
                      LAUNCHER
                    </span>
                  )}
                  {a.exported && (
                    <span className="pap-picker__badge pap-picker__badge--exported">
                      EXPORTED
                    </span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
