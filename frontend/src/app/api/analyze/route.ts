import { NextRequest, NextResponse } from 'next/server';
import { analysisCache } from '@/lib/cache';

const BACKEND_BASE_URL = (
  process.env.BACKEND_URL || 
  'https://url-threat-inspector-ml-project.vercel.app'
).replace(/\/$/, '');

const INTERNAL_API_SECRET = process.env.INTERNAL_API_SECRET || 'soc-secure-key-prod';

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Executes fetch with a 1-retry fallback for network drops or HTTP >= 500 cold-start timeouts.
 */
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  retries = 1,
  delayMs = 1000
): Promise<Response> {
  try {
    const response = await fetch(url, options);
    if (!response.ok && response.status >= 500 && retries > 0) {
      await delay(delayMs);
      return fetch(url, options);
    }
    return response;
  } catch (err) {
    if (retries > 0) {
      await delay(delayMs);
      return fetch(url, options);
    }
    throw err;
  }
}

/**
 * Safely parses response body:
 * - If JSON, parses via response.json().
 * - If HTML / non-JSON (e.g. Vercel 504/500 gateway page), safely reads response.text()
 *   and returns a clean 503 cold-start status without throwing SyntaxError.
 */
async function parseResponseBody(response: Response): Promise<{ data: unknown; status: number }> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      const json = await response.json();
      return { data: json, status: response.status };
    } catch {
      await response.text().catch(() => '');
      return {
        data: {
          detail: 'The inspection backend is initializing (cold start). Please retry in a moment.',
        },
        status: 503,
      };
    }
  }

  // Non-JSON or HTML gateway timeout page
  await response.text().catch(() => '');
  return {
    data: {
      detail: 'The inspection backend is initializing (cold start). Please retry in a moment.',
    },
    status: 503,
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const rawUrl = body?.url;

    // Normalize incoming URL for deterministic cache keying
    const cacheKey = typeof rawUrl === 'string' ? rawUrl.trim().toLowerCase() : '';

    // Cache hit short-circuit
    if (cacheKey) {
      const cachedData = analysisCache.get(cacheKey);
      if (cachedData && typeof cachedData === 'object') {
        return NextResponse.json(
          {
            ...(cachedData as Record<string, unknown>),
            cached: true,
            latency_ms: 0.1,
          },
          { status: 200 }
        );
      }
    }

    const targetUrl = `${BACKEND_BASE_URL}/analyze`;
    const response = await fetchWithRetry(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': INTERNAL_API_SECRET,
      },
      body: JSON.stringify(body),
    });

    const { data, status } = await parseResponseBody(response);

    // Save successful inspection in LRU cache
    if (status === 200 && cacheKey && data && typeof data === 'object') {
      analysisCache.set(cacheKey, data);
    }

    return NextResponse.json(data, { status });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        detail:
          'Inspection engine unreachable. Please ensure the backend service is running.',
      },
      { status: 502 }
    );
  }
}

export async function GET() {
  try {
    const targetUrl = `${BACKEND_BASE_URL}/health`;
    const response = await fetchWithRetry(targetUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Secret': INTERNAL_API_SECRET,
      },
    });

    const { data, status } = await parseResponseBody(response);
    return NextResponse.json(data, { status });
  } catch {
    return NextResponse.json(
      {
        status: 'UNREACHABLE',
        detail: 'Backend diagnostic health check unreachable.',
      },
      { status: 502 }
    );
  }
}
