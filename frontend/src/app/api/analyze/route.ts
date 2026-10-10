import { NextRequest, NextResponse } from 'next/server';

const BACKEND_BASE_URL = (
  process.env.BACKEND_URL || 
  'https://url-threat-inspector-ml-project.vercel.app'
).replace(/\/$/, '');

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const targetUrl = `${BACKEND_BASE_URL}/analyze`;

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
    const response = await fetch(targetUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
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
