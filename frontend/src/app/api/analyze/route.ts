import { NextRequest, NextResponse } from 'next/server';

/**
 * Resolves the target backend URL based on environment context:
 * 1. BACKEND_URL environment variable if explicitly configured.
 * 2. In production (e.g. Vercel co-deployment): internal Python serverless route (/api/py/analyze).
 * 3. In local development: direct FastAPI instance at http://127.0.0.1:8000/analyze.
 */
function resolveBackendEndpoint(req: NextRequest): string {
  // 1. Explicit backend URL override (e.g. external container or microservice)
  const envBackendUrl =
    process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL;
  if (envBackendUrl) {
    const clean = envBackendUrl.replace(/\/+$/, '');
    return clean.endsWith('/analyze') ? clean : `${clean}/analyze`;
  }

  // 2. Production Vercel monorepo / serverless deployment
  if (process.env.NODE_ENV === 'production' || process.env.VERCEL) {
    const origin = req.nextUrl.origin;
    return `${origin}/api/py/analyze`;
  }

  // 3. Local development fallback
  return 'http://127.0.0.1:8000/analyze';
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const targetUrl = resolveBackendEndpoint(req);

    const response = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (err: unknown) {
    const errorMsg =
      err instanceof Error ? err.message : 'Internal Server Error';
    return NextResponse.json(
      {
        detail: `Failed to proxy inspection to backend: ${errorMsg}`,
      },
      { status: 502 }
    );
  }
}

export async function GET(req: NextRequest) {
  try {
    const envBackendUrl =
      process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL;
    let healthUrl = 'http://127.0.0.1:8000/health';

    if (envBackendUrl) {
      const clean = envBackendUrl.replace(/\/+$/, '');
      healthUrl = `${clean}/health`;
    } else if (process.env.NODE_ENV === 'production' || process.env.VERCEL) {
      healthUrl = `${req.nextUrl.origin}/api/py/health`;
    }

    const response = await fetch(healthUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json(
      { status: 'HEALTHY', mode: 'STANDALONE_FALLBACK' },
      { status: 200 }
    );
  }
}

