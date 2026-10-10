/**
 * TypeScript interfaces for CYBERSEC URL INSPECTOR.
 * Perfectly aligned with the backend FastAPI Pydantic schemas.
 */

export interface URLForensics {
  url_length: number;
  domain_length: number;
  path_depth: number;
  param_count: number;
  digit_ratio: number;
  has_ip_host: boolean;
  has_punycode: boolean;
  host_entropy: number;
  suspicious_keywords_count: number;
  tld: string;
  is_allowlisted?: boolean;
  dangerous_protocol?: boolean;
}

export interface URLAnalysisResponse {
  url: string;
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'INTERNAL_TARGET';
  is_threat: boolean;
  threat_probability: number;
  threshold_applied: number;
  latency_ms: number;
  forensics: URLForensics;
  risk_summary?: string;
  cached?: boolean;
}

export interface URLAnalysisRequest {
  url: string;
}

export interface EngineHealthInfo {
  status: string;
  service: string;
  classifier_engine: string;
  model_calibrated_threshold: number;
  model_metrics: {
    fpr: number;
    recall: number;
    roc_auc: number;
  };
  feature_dimensions: number;
}
