# CYBERSEC URL INSPECTOR &bull; Production Monorepo

Enterprise-grade Phishing URL Threat Assessment Platform powered by a deterministic **Lexical & Gradient Boost Engine (LightGBM)** with calibrated False Positive Rate policy ($\le 5.0\%$) and modern Dark SOC operations dashboard built on Next.js 16 (App Router), TypeScript, and Tailwind CSS.

---

## Architecture Overview

```
url_project/
├── backend/                        # FastAPI Inference Engine
│   ├── feature_extractor.py        # 29 Lexical, Structural & Lure Forensics
│   ├── main.py                     # High-Speed Deterministic API & Dynamic Paths
│   ├── model/
│   │   └── phishing_model.joblib   # Calibrated LightGBM Bundle (450 KB)
│   ├── requirements.txt            # Frozen Backend Dependencies
│   └── train_and_export.py         # Group-KFold Model Pipeline
├── frontend/                       # Next.js 16 (App Router) SOC Dashboard
│   ├── src/app/                    # App Router Layout & UI Pages
│   │   ├── api/analyze/route.ts    # Unified Server Route Bridge (Dev + Prod)
│   │   └── page.tsx                # Dynamic Operations Command Console
│   ├── src/components/             # High-End CyberSec SOC UI Components
│   ├── src/lib/api.ts              # Resilient Threat Inspection Client
│   └── src/types/analysis.ts       # Typed Schemas Aligned with FastAPI
├── api/                            # Vercel Serverless Function Handlers
│   ├── analyze.py                  # Direct /api/analyze Serverless Endpoint
│   └── index.py                    # Serverless Root & Health Proxy
├── vercel.json                     # Vercel Rewrite & Routing Configuration
├── package.json                    # Monorepo Workspaces Configuration
├── requirements.txt                # Root Python Dependency Reference
└── .gitignore                      # Strictly Excludes Datasets (*.csv) & Cache
```

---

## Deployment to Vercel (Zero-Config Single Click)

### Option 1: Native Monorepo Deployment
1. Push this repository to GitHub or GitLab.
2. In the [Vercel Dashboard](https://vercel.com/new), import the repository.
3. The root configuration automatically:
   - Serves the Next.js frontend at `/`.
   - Routes `/api/py/:path*` directly to `/backend/main.py` via `vercel.json`.
   - Resolves the model artifact dynamically from `model/phishing_model.joblib`.
   - Strictly ignores raw training data (`malicious_phish.csv`).
4. Click **Deploy**.

### Option 2: External Backend (Container / Railway / Render)
If deploying the Python backend to a dedicated container runtime (e.g. Docker, Railway, Render, Fly.io, Cloud Run):
- Set the environment variable in Vercel:
  ```env
  BACKEND_URL=https://your-backend-api.up.railway.app
  ```
- The Next.js route bridge in `frontend/src/app/api/analyze/route.ts` will automatically forward all inspection requests securely to that endpoint.

---

## Local Development Workflow

### 1. Start the FastAPI Inference Backend
```bash
# From workspace root or url_project/backend:
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Probe: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 2. Start the Next.js Frontend Dashboard
```bash
# In a second terminal:
cd frontend
npm run dev
```
- SOC Command Console: [http://localhost:3000](http://localhost:3000)

---

## Core Security & Engineering Benchmarks

- **Classification Algorithm**: LightGBM Gradient Boosted Decision Trees (300 estimators, lr=0.05, leaves=31).
- **Validation Strategy**: `StratifiedGroupKFold(n_splits=5)` grouped strictly by Registrable Domain (PSL) with 0 domain overlap.
- **Calibrated Threshold**: `0.4705` enforcing Test False Positive Rate $\le 5.00\%$.
- **Test ROC-AUC**: `0.9344` on 103,037 held-out URLs.
- **Protocol Bias Elimination**: Intentionally zero scheme recording bias (no `has_https` or `scheme_known`).
- **Inference Latency**: Sub-10ms deterministic response time.
