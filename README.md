# SecureAI Review 🛡️🤖

> **AI-Powered Secure Code Review Engine** combining deterministic AST static analysis (**Semgrep**) with contextual security explanations and remediation suggestions (**Groq Llama 3.3 70B**).

---

## 🎯 Problem Statement

Traditional Static Application Security Testing (SAST) tools generate opaque rule codes and complex security messages that developers often struggle to triage quickly. On the other hand, raw LLM-based code reviewers hallucinate vulnerabilities and lack formal AST (Abstract Syntax Tree) verification.

**SecureAI Review** bridges this gap:
1. **Deterministic Static Analysis**: Runs real **Semgrep** static analysis to detect verified code flaws (SQL injection, shell execution vulnerabilities, hardcoded credentials, insecure crypto).
2. **Secret Redaction**: Redacts API keys, credentials, and tokens from code *before* sending anything to external AI endpoints.
3. **AI Security Explanations**: Uses **Groq (Llama 3.3 70B)** to provide 2-3 plain-English sentences explaining the real-world security impact and concrete remediation code.
4. **Human-in-the-Loop Safeguard**: AI fixes are explicitly presented as suggestions for developer review — **no code changes are ever auto-applied**.
5. **Severity Cross-Check**: Compares static rule severity against LLM evaluation, flagging discrepancies (≥ 2 levels) with a visible conflict badge.

---

## 🏗️ Architecture

```text
[ Developer Browser / Next.js UI ]
           │
           │ (1) POST /api/scan  (Code Snippet)
           ▼
[ FastAPI Backend Engine ] ──► (Returns scan_id immediately; runs BackgroundTask)
           │
           ├─► (2) Semgrep Subprocess Engine (60s timeout, language-specific AST scan)
           │
           ├─► (3) Secret Redaction Layer (Masks AWS, GitHub, OpenAI, passwords before LLM)
           │
           ├─► (4) Groq API (llama-3.3-70b-versatile, structured JSON output)
           │
           ├─► (5) Severity Cross-Checker (Flags AST vs. LLM discrepancies)
           │
           ▼
[ MySQL Database / In-Memory Fallback ] ──► Scans & Findings tables
           ▲
           │ (6) Polling GET /api/scan/{scan_id} every 2 seconds
           │
[ Developer Browser / Next.js UI ] ──► Color-coded findings, explanations, and remediation
```

---

## 📸 Screenshots

*(Placeholder for application screenshots)*
- **Dashboard & Code Input**: `docs/screenshots/dashboard.png`
- **Security Findings & AI Explanations**: `docs/screenshots/findings.png`
- **Remediation & Severity Conflict Badge**: `docs/screenshots/remediation.png`

---

## 🚀 Setup & Local Installation

### Prerequisites
- Python 3.10+
- Node.js 18+ (npm 9+)
- Local MySQL instance (optional; fallback in-memory store is supported)
- Groq API Key (from [console.groq.com](https://console.groq.com))

---

### 1. Backend Setup (`/backend`)

```bash
cd backend

# Create & activate virtual environment
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and supply your GROQ_API_KEY and MySQL credentials if applicable
```

#### MySQL Database Initialization (Optional)
If running with MySQL, execute the following schema in your MySQL client:

```sql
CREATE DATABASE IF NOT EXISTS secureai_review;
USE secureai_review;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(50) NOT NULL,
    source_ref TEXT NULL,
    language VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'processing'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    line_number INT NOT NULL,
    raw_message TEXT NOT NULL,
    ai_explanation TEXT NULL,
    ai_fix_suggestion TEXT NULL,
    ai_confidence VARCHAR(50) NULL,
    severity_conflict BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

#### Run the Backend:
```bash
uvicorn app.main:app --reload --port 8000
```
- Interactive API Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

---

### 2. Frontend Setup (`/frontend`)

```bash
cd frontend

# Install dependencies
npm install

# Configure environment variables
cp .env.local.example .env.local
# Default: NEXT_PUBLIC_API_URL=http://localhost:8000

# Run development server
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🧪 Verification & Testing

### Running Standalone Semgrep Test
```bash
cd backend
.\venv\Scripts\python app\semgrep_runner.py
```

### Running End-to-End API Pipeline Test
```bash
cd backend
.\venv\Scripts\python verify_e2e.py
```

---

## ☁️ Deployment Instructions

### Backend Deployment (Render)
1. Create a new **Web Service** on [Render](https://render.com) connected to this repository with **Root Directory** set to `backend`.
2. **Build Command**: `pip install -r requirements.txt`
3. **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. **Environment Variables**:
   - `GROQ_API_KEY`: Your Groq API key
   - `MYSQL_HOST`: Remote MySQL host (e.g. Railway, PlanetScale, Aiven)
   - `MYSQL_PORT`: `3306` (or provider port)
   - `MYSQL_USER`: Database username
   - `MYSQL_PASSWORD`: Database password
   - `MYSQL_DB`: Database name (`secureai_review`)

> [!IMPORTANT]
> **Hosted MySQL Requirement**: `localhost` will not work from Render. You must provision a hosted MySQL database (e.g., Railway free MySQL add-on or Aiven) and set `MYSQL_HOST` accordingly before running in production.

### Frontend Deployment (Vercel)
1. Import the repository into [Vercel](https://vercel.com) with **Root Directory** set to `frontend`.
2. **Framework Preset**: Next.js
3. **Environment Variables**:
   - `NEXT_PUBLIC_API_URL`: The deployed Render backend URL (e.g. `https://secureai-backend.onrender.com`)

---

## ⚠️ Known Limitations
- **Language Support**: Currently configured for Python, JavaScript, TypeScript, and Java snippets.
- **Rate Limiting**: Uses an in-memory sliding window (5 requests / 60 seconds per IP); multi-instance horizontally scaled deployments should attach a Redis instance.
- **Subprocess Isolation**: Semgrep runs in sandboxed temporary directories per request with a 60-second execution deadline.

---

## 🗺️ Roadmap & Supported Features
- [x] **Paste Code Snippet Scan**: Python, JavaScript, TypeScript, and Java AST pattern scanning.
- [x] **File Upload Scan**: Drag-and-drop / file browser support with client-side 500KB validation.
- [x] **GitHub Repository Full Scanning**: Shallow git cloning (`--depth 1`) in sandboxed temporary directories with full codebase scanning.
- [ ] **One-Click Pull Request Creation**: Generating GitHub PRs with suggested remediations (auto-patching is intentionally disabled to keep developers in full control).
- [ ] **Custom Ruleset Upload**: Support for teams to upload proprietary `.semgrep.yml` organization policies.
- [ ] **CI/CD GitHub Action**: Direct integration into CI/CD pipelines as a blocking security gate.
