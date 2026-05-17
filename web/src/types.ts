export type RecordEnvelope<T = Record<string, unknown>> = {
  id: string;
  kind: string;
  created_at: string;
  updated_at: string;
  payload: T;
};

export type CvssState = {
  vector?: string;
  score?: number;
  severity?: string;
  metrics?: Record<string, string>;
  notes?: string;
};

export type FindingPayload = {
  title: string;
  status: string;
  severity: string;
  affected_scope: string[];
  summary: string;
  technical_details: string;
  impact: string;
  remediation: string;
  validation: string;
  references: string[];
  open_questions: string[];
  cvss?: CvssState;
};

export type FindingRecord = RecordEnvelope<FindingPayload> & {
  evidence_count?: number;
  notes?: RecordEnvelope[];
  evidence?: RecordEnvelope[];
  assets?: RecordEnvelope[];
  packet_markdown?: string;
};

export type SearchHit = {
  Kind: string;
  ID: string;
  Title: string;
  Excerpt: string;
  Score: number;
};
