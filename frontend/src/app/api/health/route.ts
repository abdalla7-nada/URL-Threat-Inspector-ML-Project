import { NextResponse } from 'next/server';

const BACKEND_BASE_URL = (
  process.env.BACKEND_URL || 
  'https://url-threat-inspector-ml-project.vercel.app'
).replace(/\/$/, '');

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function GET() {
  const targetUrl = `${BACKEND_BASE_URL}/health`;
  try {
    let response: Response;
    try {
      response = await fetch(targetUrl, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok && [500, 502, 503, 504].includes(response.status)) {
        await delay(1000);
        response = await fetch(targetUrl, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        });
      }
    } catch {
      await delay(1000);
      response = await fetch(targetUrl, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await response.json();
      return NextResponse.json(data, { status: response.status });
    }

    const text = await response.text();
    return NextResponse.json(
      { status: 'UNREACHABLE', detail: text || 'Non-JSON health response.' },
      { status: response.status }
    );
  } catch (err: unknown) {
    return NextResponse.json(
      {
        status: 'UNREACHABLE',
        detail:
          'Backend diagnostic health check unreachable. Please ensure the backend service is running.',
      },
      { status: 502 }
    );
  }
}
