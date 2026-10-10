import { URLAnalysisResponse, EngineHealthInfo } from '@/types/analysis';

/**
 * Sends a URL to the threat inspection engine via the unified /api/analyze route bridge.
 * The server-side proxy handler dynamically routes to either local FastAPI or Vercel serverless function.
 */
export async function inspectUrl(url: string): Promise<URLAnalysisResponse> {
  const cleanUrl = url.trim();
  if (!cleanUrl) {
    throw new Error('Please enter a valid URL to inspect.');
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

      if (res.status === 422) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.detail || 'Invalid URL payload format.');
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.message.includes('Invalid URL')) {
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
    throw new Error(
      errData?.detail || `Inspection failed with status code ${res.status}.`
    );
  } catch (err: unknown) {
    const msg =
      err instanceof Error
        ? err.message
        : 'Inspection engine request could not be completed.';
    throw new Error(msg);
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

