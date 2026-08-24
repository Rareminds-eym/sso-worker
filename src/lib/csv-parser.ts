/**
 * Generic CSV Parser
 * Simple CSV parser without external dependencies.
 * Entity-specific row validation/mapping lives in the bulk-import adapters.
 */

export interface CSVRow {
  [key: string]: string;
}

export interface ParsedCSV {
  headers: string[];
  rows: CSVRow[];
  errors: string[];
}

/**
 * Parse a single CSV line into fields, handling quoted values with commas
 */
function parseCSVLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];

    if (char === '"') {
      if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      values.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  values.push(current.trim());
  
  // Validate quotes are balanced
  if (inQuotes) {
    throw new Error('Malformed CSV: unclosed quote in line');
  }
  
  return values;
}

/**
 * Parse CSV string into structured data
 * Simple implementation without external libraries
 */
export function parseCSV(csvText: string): ParsedCSV {
  const lines = csvText.trim().split('\n');
  const errors: string[] = [];
  
  if (lines.length === 0) {
    return { headers: [], rows: [], errors: ['CSV file is empty'] };
  }
  
  // Parse headers (first line)
  const headers = parseCSVLine(lines[0]).filter(h => h.length > 0);
  
  if (headers.length === 0) {
    return { headers: [], rows: [], errors: ['CSV headers are missing'] };
  }
  
  // Parse data rows
  const rows: CSVRow[] = [];
  
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Skip empty lines
    if (!line) continue;
    
    let values: string[];
    try {
      values = parseCSVLine(line);
    } catch (parseError) {
      errors.push(`Row ${i}: ${parseError instanceof Error ? parseError.message : 'Parse error'}`);
      continue;
    }
    
    if (values.length !== headers.length) {
      errors.push(`Row ${i}: Column count mismatch (expected ${headers.length}, got ${values.length})`);
      continue;
    }
    
    // Create row object
    const row: CSVRow = {};
    headers.forEach((header, index) => {
      row[header] = values[index];
    });
    
    rows.push(row);
  }
  
  return { headers, rows, errors };
}
