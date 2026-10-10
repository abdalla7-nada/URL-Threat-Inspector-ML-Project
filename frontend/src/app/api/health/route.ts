import { NextResponse } from 'next/server';

const BACKEND_BASE_URL = (
  process.env.BACKEND_URL || 
  'https://url-threat-inspector-ml-project.vercel.app'
).replace(/\/$/, '');

export async function GET() {
  try {
    const targetUrl = `${BACKEND_BASE_URL}/health`;
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
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
