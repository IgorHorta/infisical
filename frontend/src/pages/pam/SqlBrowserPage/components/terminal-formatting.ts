/**
 * Format SQL query results for terminal display
 */

type QueryResult = {
  rows: unknown[];
  columns: string[];
  rowCount: number;
};

type FormattedResult = {
  output: string;
  columns: string[];
  rowCount: number;
};

const formatValue = (val: unknown, maxWidth?: number): string => {
  let str: string;

  if (val === null || val === undefined) {
    str = "NULL";
  } else if (val instanceof Date) {
    str = val.toISOString();
  } else if (typeof val === "object") {
    try {
      str = JSON.stringify(val);
    } catch {
      str = String(val);
    }
  } else {
    str = String(val);
  }

  if (maxWidth && str.length > maxWidth) {
    return `${str.slice(0, maxWidth - 1)}…`;
  }
  return str;
};

/**
 * Format query results as a table for terminal display
 */
export const formatSqlQueryResultForTerminal = (
  result: QueryResult,
  options: { terminalWidth?: number } = {}
): FormattedResult => {
  const { rows, columns, rowCount } = result;

  if (rows.length === 0) {
    return { output: "(0 rows)", columns, rowCount: 0 };
  }

  const terminalWidth = options.terminalWidth || 120;

  // For tables with many columns, use expanded (vertical) format
  if (columns.length > 6) {
    const colWidth = Math.max(...columns.map((c) => c.length), 15);
    const valueWidth = terminalWidth - colWidth - 4;
    const parts: string[] = [];

    rows.forEach((row, idx) => {
      const record = row as Record<string, unknown>;
      parts.push(`-[ RECORD ${idx + 1} ]${"-".repeat(Math.max(0, terminalWidth - 15))}`);
      columns.forEach((col) => {
        parts.push(`${col.padEnd(colWidth)} | ${formatValue(record[col], valueWidth)}`);
      });
    });

    return {
      output: `${parts.join("\n")}\n(${rowCount} row${rowCount !== 1 ? "s" : ""})`,
      columns,
      rowCount
    };
  }

  // For fewer columns, build ASCII table
  const maxColWidth = Math.floor((terminalWidth - columns.length - 1) / columns.length);
  const colWidths = columns.map((col, i) => {
    const headerLen = col.length;
    const maxDataLen = Math.max(
      ...rows.map((row) => formatValue((row as Record<string, unknown>)[columns[i]]).length),
      0
    );
    return Math.min(Math.max(headerLen, maxDataLen, 4), maxColWidth);
  });

  const lines: string[] = [];

  // Top border
  lines.push(`┌${colWidths.map((w) => "─".repeat(w + 2)).join("┬")}┐`);

  // Header row
  lines.push(`│${columns.map((col, i) => ` ${col.padEnd(colWidths[i])} `).join("│")}│`);

  // Header separator
  lines.push(`├${colWidths.map((w) => "─".repeat(w + 2)).join("┼")}┤`);

  // Data rows
  rows.forEach((row) => {
    const record = row as Record<string, unknown>;
    const cells = columns.map((col, i) => ` ${formatValue(record[col], colWidths[i]).padEnd(colWidths[i])} `);
    lines.push(`│${cells.join("│")}│`);
  });

  // Bottom border
  lines.push(`└${colWidths.map((w) => "─".repeat(w + 2)).join("┴")}┘`);

  return {
    output: `${lines.join("\n")}\n(${rowCount} row${rowCount !== 1 ? "s" : ""})`,
    columns,
    rowCount
  };
};
