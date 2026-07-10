import { useState, useCallback } from "react";
import type { LogEntry, LogType } from "../types";
import { MAX_LOG_ENTRIES } from "../constants";

/** Activity-log state + a stable `log()` callback (newest entry first). */
export function useLog() {
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const log = useCallback((message: string, type: LogType = "info") => {
    setLogs((prev) => [
      { message, type, timestamp: new Date() },
      ...prev.slice(0, MAX_LOG_ENTRIES - 1),
    ]);
  }, []);

  return { logs, log };
}
