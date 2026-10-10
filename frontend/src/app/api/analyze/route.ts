import { NextRequest, NextResponse } from 'next/server';

const BACKEND_BASE_URL = (
  process.env.BACKEND_URL || 
  'https://url-threat-inspector-ml-project.vercel.app'
).replace(/\/$/, '');

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Executes fetch with a 1-retry fallback for cold-start connection drops or gateway timeouts.
 */
async function fetchWithColdStartRetry(
  url: string,
  options: RequestInit,
  retries = 1,
  delayMs = 1000
): Promise<Response> {
  try {
    const response = await fetch(url, options);
    // If the serverless instance encounters a transient 502/503/504 gateway timeout during cold start
    if (!response.ok && [500, 502, 503, 504].includes(response.status) && retries > 0) {
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
 * Safely parses response body, ensuring non-JSON or HTML 500/504 errors do not crash JSON parsing.
 */
async function parseResponseBody(response: Response): Promise<{ data: unknown; status: number }> {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      const json = await response.json();
      return { data: json, status: response.status };
    } catch {
      const rawText = await response.text();
      return {
        data: {
          detail: rawText || 'Malformed JSON received from inspection engine.',
        },
        status: response.status,
      };
    }
  }

  const rawText = await response.text();
  return {
    data: {
      detail:
        rawText ||
        `Inspection engine returned non-JSON response (HTTP ${response.status}).`,
    },
    status: response.status,
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const targetUrl = `${BACKEND_BASE_URL}/analyze`;

    const response = await fetchWithColdStartRetry(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const { data, status } = await parseResponseBody(response);
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
    const response = await fetchWithColdStartRetry(targetUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
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
