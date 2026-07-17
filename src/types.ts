export interface User {
  id?: number;
  username: string;
  password_hash: string;
  role: 'admin' | 'viewer';
  created_at?: string;
}

export interface Asset {
  id?: number;
  name: string;
  url: string;
  is_active: number; // 0 or 1
  is_deleted: number; // 0 or 1
  interval_seconds: number;
  next_capture_at: string;
  created_at?: string;
}

export interface Snapshot {
  id?: number;
  asset_id: number;
  captured_at: string;
  http_status: number | null;
  fetch_error: string | null;
  response_headers: string; // JSON string of lowercased header names/values
  screenshot_path: string | null;
  html_path: string | null;
  phash: string | null; // 16 hex chars (64-bit dHash)
  html_sha256: string | null;
}

export interface DiffResult {
  id?: number;
  snapshot_id: number;
  prev_snapshot_id: number | null;
  visual_distance: number | null; // Hamming distance 0-64
  visual_changed: number; // 0 or 1
  text_changed: number; // 0 or 1
  text_diff_summary: string | null; // unified diff, truncated to 8KB
  created_at?: string;
}

export interface VulnCheckResult {
  id?: number;
  snapshot_id: number;
  check_type: 'header_csp' | 'header_hsts' | 'header_xfo' | 'header_xcto' | 'exposed_path' | 'outdated_js';
  passed: number; // 0 or 1
  details: string; // JSON string e.g. {"path":"/.env","status":200}
}

export interface AlertEvent {
  id?: number;
  asset_id: number;
  snapshot_id: number;
  kind: 'change' | 'vuln' | 'availability';
  title: string;
  severity: 'high' | 'medium' | 'low' | 'unscored';
  ai_explanation: string | null;
  ai_remediation: string | null;
  ai_model: string | null;
  ai_error: string | null;
  created_at?: string;
}

export interface AuditLogEntry {
  seq: number;
  created_at: string;
  actor: string;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  details_json: string;
  prev_hash: string;
  entry_hash: string;
}
