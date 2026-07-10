/** Shared demo UI types. */

export type LogType = "info" | "success" | "error";

export interface LogEntry {
  message: string;
  type: LogType;
  timestamp: Date;
}

/** Signature for the activity-log callback threaded through the demo. */
export type LogFn = (message: string, type?: LogType) => void;
