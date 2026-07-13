/**
 * CSV Parser for Bulk Learner Import
 * Simple CSV parser without external dependencies
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
    
    const values = parseCSVLine(line);
    
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

/**
 * Validate required fields in CSV row
 */
export function validateCSVRow(row: CSVRow, rowNumber: number): { valid: boolean; error?: string } {
  // Required fields
  if (!row.email || !row.email.includes('@')) {
    return { valid: false, error: `Row ${rowNumber}: Invalid or missing email` };
  }
  
  if (!row.name || row.name.trim().length < 2) {
    return { valid: false, error: `Row ${rowNumber}: Invalid or missing name` };
  }
  
  // Optional: Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(row.email)) {
    return { valid: false, error: `Row ${rowNumber}: Invalid email format` };
  }
  
  return { valid: true };
}

/**
 * Map CSV row to learner data structure
 */
export function mapCSVRowToLearnerData(row: CSVRow): {
  email: string;
  name: string;
  contact_number?: string;
  enrollment_number?: string;
  program_id?: string;
  metadata?: Record<string, unknown>;
} {
  return {
    email: row.email?.trim() || '',
    name: row.name?.trim() || '',
    contact_number: row.contact_number?.trim() || row.phone?.trim() || undefined,
    enrollment_number: row.enrollment_number?.trim() || row.roll_number?.trim() || undefined,
    program_id: row.program_id?.trim() || undefined,
    metadata: {
      // Store any additional columns in metadata
      ...Object.fromEntries(
        Object.entries(row).filter(([key]) => 
          !['email', 'name', 'contact_number', 'phone', 'enrollment_number', 'roll_number', 'program_id'].includes(key)
        )
      )
    }
  };
}
