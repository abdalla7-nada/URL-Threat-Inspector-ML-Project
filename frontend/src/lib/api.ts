import { URLAnalysisResponse, EngineHealthInfo } from '@/types/analysis';

export class ApiError extends Error {
  errorType?: string;
  statusCode: number;

  constructor(message: string, statusCode: number, errorType?: string) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.errorType = errorType;
  }
}

/**
 * Sends a URL to the threat inspection engine via the unified /api/analyze route bridge.
 * The server-side proxy handler dynamically routes to either local FastAPI or Vercel serverless function.
 */
export async function inspectUrl(url: string): Promise<URLAnalysisResponse> {
  const cleanUrl = url.trim();
  if (!cleanUrl) {
    throw new ApiError('Please enter a valid URL to inspect.', 400, 'EMPTY_INPUT');
  }

  const payload = { url: cleanUrl };

  // 1. If explicit NEXT_PUBLIC_API_URL is configured, attempt direct query
  if (process.env.NEXT_PUBLIC_API_URL) {
    try {
      const directBase = process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, '');
      const res = await fetch(`${directBase}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        return (await res.json()) as URLAnalysisResponse;
      }

      const errData = await res.json().catch(() => null);
      const errType =
        typeof errData?.detail === 'object' && errData?.detail !== null
          ? (errData.detail as { error_type?: string }).error_type
          : undefined;
      const detailMsg =
        typeof errData?.detail === 'object' && errData?.detail !== null && 'message' in errData.detail
          ? (errData.detail as { message: string }).message
          : typeof errData?.detail === 'string'
          ? errData.detail
          : `Inspection failed with status code ${res.status}.`;
      throw new ApiError(detailMsg, res.status, errType);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        throw err;
      }
      // Fall through to Next.js proxy route bridge
    }
  }

  // 2. Primary Route: Next.js API route bridge (/api/analyze)
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      return (await res.json()) as URLAnalysisResponse;
    }

    const errData = await res.json().catch(() => null);
    if (res.status === 502 || res.status === 503) {
      throw new ApiError(
        errData?.detail ||
          'Inspection engine unreachable. Please ensure the backend service is running.',
        res.status
      );
    }

    const errType =
      typeof errData?.detail === 'object' && errData?.detail !== null
        ? (errData.detail as { error_type?: string }).error_type
        : undefined;

    const detailMsg =
      typeof errData?.detail === 'object' && errData?.detail !== null && 'message' in errData.detail
        ? (errData.detail as { message: string }).message
        : typeof errData?.detail === 'string'
        ? errData.detail
        : `Inspection failed with status code ${res.status}.`;

    throw new ApiError(detailMsg, res.status, errType);
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const msg =
      err instanceof Error
        ? err.message
        : 'Inspection engine unreachable. Please ensure the backend service is running.';
    throw new ApiError(msg, 500);
  }
}

/**
 * Probes the backend health and metrics endpoint.
 */
export async function fetchEngineHealth(): Promise<EngineHealthInfo | null> {
  try {
    const healthUrl = process.env.NEXT_PUBLIC_API_URL
      ? `${process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, '')}/health`
      : '/api/analyze';

    const res = await fetch(healthUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    });
    if (res.ok) {
      return (await res.json()) as EngineHealthInfo;
    }
  } catch {
    // Silent fail for non-critical health telemetry
  }
  return null;
}

