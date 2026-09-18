# AI Declaration & Verification Disclosure

## 🤖 AI Assistance Statement
This application (**SecureAI Review**) was scaffolded, designed, and wired using **Antigravity** (Google DeepMind agentic coding assistant). 

The runtime AI explanation feature in the application utilizes **Groq API** running the open-weights model **`llama-3.3-70b-versatile`** to interpret static analysis output, evaluate risk context, and propose remediation code.

---

## 🔍 Verification Breakdown

### Manually & Programmatically Verified Components
The following core security and infrastructure components were executed, tested, and validated against actual code samples and live subprocesses:
1. **Semgrep Static Detection**: Tested through `backend/app/semgrep_runner.py` against real vulnerable code patterns (unsanitized `subprocess.call(..., shell=True)`, hardcoded secrets, injection paths). Exit code `1` handling and execution timeouts were verified.
2. **Secret Redaction Layer (`app/redact.py`)**: Verified against simulated AWS access keys (`AKIA...`), GitHub OAuth tokens (`ghp_...`), OpenAI keys (`sk-...`), and database password variable assignments before external API dispatch.
3. **AI Defensive JSON Parser (`app/groq_client.py`)**: Tested with defensive markdown stripping (fenced code blocks) and regex fallback parsing to guarantee that non-standard LLM output formats never crash the backend scan pipeline.
4. **Severity Conflict Logic (`app/severity.py`)**: Tested against boundary conditions on the 1–4 severity ranking scale to verify threshold detection when AST and AI assessments diverge by 2 or more levels.
5. **End-to-End HTTP Flow (`backend/verify_e2e.py`)**: Executed against the running FastAPI server (`POST /api/scan` returning HTTP 202 -> `GET /api/scan/{id}` polling -> full finding delivery).
6. **Frontend Production Build**: Successfully compiled and type-checked Next.js 14 App Router and Tailwind CSS in `frontend/`.

---

### AI-Generated Components (Review Advised)
1. **Remediation Code Suggestions**: LLM-generated code fixes returned by Groq are advisory only and require human security engineering review before manual application.
2. **Third-Party Hosted Deployment Targets**: Render and Vercel configuration templates provided in documentation must be paired with user-configured production credentials and hosted databases.
