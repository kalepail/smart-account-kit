import type { LogEntry } from "../types";

interface ActivityLogProps {
  logs: LogEntry[];
}

/** Activity log card. The `.log-box` selector is used by browser audit scripts. */
export function ActivityLog({ logs }: ActivityLogProps) {
  return (
    <div className="card">
      <h3>Activity Log</h3>
      <div className="log-box">
        {logs.length === 0 ? (
          <div className="log-entry">No activity yet...</div>
        ) : (
          logs.map((entry, i) => (
            <div key={i} className={`log-entry ${entry.type}`}>
              [{entry.timestamp.toLocaleTimeString()}] {entry.message}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
