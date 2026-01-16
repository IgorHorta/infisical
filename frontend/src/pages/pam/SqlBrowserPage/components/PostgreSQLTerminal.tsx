import "@xterm/xterm/css/xterm.css";

import { useCallback, useEffect, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";

import SecurityClient from "@app/components/utilities/SecurityClient";
import { getAuthToken, getMfaTempToken, getSignupTempToken } from "@app/hooks/api/reactQuery";

import { formatSqlQueryResultForTerminal } from "./terminal-formatting";

type Props = {
  accountId: string;
  sessionId: string;
};

const TERMINAL_THEME = {
  background: "#0f1419",
  foreground: "#e5e7eb",
  cursor: "#e5e7eb",
  cursorAccent: "#0f1419",
  black: "#1f2937",
  red: "#ef4444",
  green: "#10b981",
  yellow: "#f59e0b",
  blue: "#3b82f6",
  magenta: "#8b5cf6",
  cyan: "#06b6d4",
  white: "#e5e7eb",
  brightBlack: "#374151",
  brightRed: "#f87171",
  brightGreen: "#34d399",
  brightYellow: "#fbbf24",
  brightBlue: "#60a5fa",
  brightMagenta: "#a78bfa",
  brightCyan: "#22d3ee",
  brightWhite: "#f3f4f6"
};

const RECONNECT_DELAY_MS = 3000;

const getToken = () =>
  getAuthToken() || getSignupTempToken() || getMfaTempToken() || SecurityClient.getProviderAuthToken() || "";

const buildWsUrl = (accountId: string, sessionId: string, token: string) => {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const tokenParam = token ? `&token=${encodeURIComponent(token)}` : "";
  return `${protocol}//${window.location.host}/api/v1/pam/accounts/${accountId}/terminal?sessionId=${sessionId}${tokenParam}`;
};

export const PostgreSQLTerminal = ({ accountId, sessionId }: Props) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const terminalInstanceRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);

  const showPrompt = useCallback(() => {
    const terminal = terminalInstanceRef.current;
    if (!terminal) return;
    terminal.write("\r\npostgres=# ");
    terminal.focus();
  }, []);

  // Initialize terminal and WebSocket connection
  useEffect(() => {
    if (!terminalRef.current) return undefined;

    const terminal = new Terminal({
      theme: TERMINAL_THEME,
      fontSize: 14,
      fontFamily: "'Courier New', monospace",
      cursorBlink: true,
      cursorStyle: "block",
      cursorInactiveStyle: "outline",
      scrollback: 1000,
      allowTransparency: false,
      disableStdin: false
    });

    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalRef.current);
    fitAddon.fit();

    // Force cursor visibility after initial render
    requestAnimationFrame(() => {
      terminal.refresh(0, terminal.rows - 1);
      terminal.focus();
    });

    terminalInstanceRef.current = terminal;
    fitAddonRef.current = fitAddon;

    terminal.writeln("\x1b[1;32mWelcome to Infisical PostgreSQL Terminal\x1b[0m");
    terminal.writeln("Type \\h for help or SQL commands to execute.");
    terminal.writeln("");

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data as string) as {
          error?: string;
          type?: string;
          rows?: unknown[];
          columns?: string[];
          rowCount?: number;
          output?: string;
          executionTime?: number;
          message?: string;
        };

        if (data.error) {
          terminal.write(`\r\nError: ${data.error}\r\n`);
          showPrompt();
          return;
        }

        if (data.type === "output") {
          let formattedOutput: string;

          if (data.rows && Array.isArray(data.rows)) {
            const terminalWidth = Math.max(terminal.cols || 80, 80);
            const formatted = formatSqlQueryResultForTerminal(
              { rows: data.rows, columns: data.columns || [], rowCount: data.rowCount || data.rows.length },
              { terminalWidth }
            );
            formattedOutput = formatted.output;
          } else {
            formattedOutput = data.output ?? "No data received";
          }

          terminal.write(`\r\n${formattedOutput.replace(/\n/g, "\r\n")}\r\n`);

          if (data.executionTime !== undefined) {
            terminal.write(`Time: ${(data.executionTime / 1000).toFixed(3)}s\r\n`);
          }
          showPrompt();
        } else if (data.type === "exit") {
          terminal.writeln(data.message || "Connection closed");
          wsRef.current?.close();
        } else if (data.type === "connected") {
          terminal.writeln(data.message || "Connected to database");
          showPrompt();
        } else {
          showPrompt();
        }
      } catch {
        terminal.write(`\r\nInvalid response\r\n`);
        showPrompt();
      }
    };

    const handleError = () => {
      terminal.writeln("WebSocket error occurred");
    };

    const handleClose = (event: CloseEvent) => {
      if (event.wasClean) {
        terminal.writeln("Connection closed");
        return;
      }

      terminal.writeln("Connection lost - reconnecting...");
      setTimeout(() => {
        if (!wsRef.current || wsRef.current.readyState === WebSocket.CLOSED) {
          const newWs = new WebSocket(buildWsUrl(accountId, sessionId, getToken()));
          newWs.onopen = () => {
            terminal.writeln("Reconnected to terminal server.");
            showPrompt();
          };
          newWs.onmessage = handleMessage;
          newWs.onerror = handleError;
          newWs.onclose = handleClose;
          wsRef.current = newWs;
        }
      }, RECONNECT_DELAY_MS);
    };

    const ws = new WebSocket(buildWsUrl(accountId, sessionId, getToken()));
    ws.onopen = () => {
      terminal.writeln("Connected to terminal server.");
      showPrompt();
    };
    ws.onmessage = handleMessage;
    ws.onerror = handleError;
    ws.onclose = handleClose;
    wsRef.current = ws;

    const handleResize = () => fitAddon.fit();
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      terminal.dispose();
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [accountId, sessionId, showPrompt]);

  const executeCommand = useCallback(
    (command: string) => {
      const terminal = terminalInstanceRef.current;
      if (!terminal) return;

      const trimmedCommand = command.trim();

      if (trimmedCommand === "\\q" || trimmedCommand === "exit") {
        terminal.writeln("Goodbye!");
        wsRef.current?.close();
        return;
      }

      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ command: trimmedCommand }));
      } else {
        terminal.writeln("Not connected to terminal server");
        showPrompt();
      }
    },
    [showPrompt]
  );

  // Handle keyboard input
  useEffect(() => {
    const terminal = terminalInstanceRef.current;
    if (!terminal) return undefined;

    let currentLine = "";
    let historyIndex = -1;

    const handleData = (data: string) => {
      // Enter key
      if (data === "\r" || data === "\n") {
        terminal.writeln("");
        if (currentLine.trim()) {
          setCommandHistory((prev) => [...prev, currentLine]);
          executeCommand(currentLine);
          historyIndex = -1;
        } else {
          showPrompt();
        }
        currentLine = "";
        return;
      }

      // Backspace
      if (data === "\x7f" || data === "\b") {
        if (currentLine.length > 0) {
          currentLine = currentLine.slice(0, -1);
          terminal.write("\b \b");
        }
        return;
      }

      // Up arrow - navigate history
      if (data === "\x1b[A") {
        const newIndex = Math.min(historyIndex + 1, commandHistory.length - 1);
        if (newIndex < commandHistory.length) {
          historyIndex = newIndex;
          const cmd = commandHistory[commandHistory.length - 1 - newIndex];
          terminal.write(`\r${" ".repeat(currentLine.length + 12)}\rpostgres=# ${cmd}`);
          currentLine = cmd;
        }
        return;
      }

      // Down arrow - navigate history
      if (data === "\x1b[B") {
        if (historyIndex > 0) {
          historyIndex -= 1;
          const cmd = commandHistory[commandHistory.length - 1 - historyIndex];
          terminal.write(`\r${" ".repeat(currentLine.length + 12)}\rpostgres=# ${cmd || ""}`);
          currentLine = cmd || "";
        } else if (historyIndex === 0) {
          historyIndex = -1;
          terminal.write(`\r${" ".repeat(currentLine.length + 12)}\rpostgres=# `);
          currentLine = "";
        }
        return;
      }

      // Printable characters
      if (data >= " " && data <= "~") {
        currentLine += data;
        terminal.write(data);
      }
    };

    const dataDisposable = terminal.onData(handleData);
    return () => dataDisposable.dispose();
  }, [executeCommand, showPrompt, commandHistory]);

  return (
    <div className="flex flex-col overflow-hidden rounded-lg border border-mineshaft-600 bg-mineshaft-900">
      <div className="flex-shrink-0 border-b border-mineshaft-600 bg-mineshaft-800 px-4 py-2">
        <h3 className="text-lg font-semibold text-white">PostgreSQL Terminal</h3>
        <p className="text-sm text-mineshaft-400">Connected • Session active • Type \h for help</p>
      </div>
      <div
        ref={terminalRef}
        className="h-96 p-4"
        style={{ backgroundColor: TERMINAL_THEME.background, overflow: "hidden" }}
      />
    </div>
  );
};
