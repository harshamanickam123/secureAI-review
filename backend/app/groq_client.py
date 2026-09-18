import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")


def _extract_json_payload(content: str) -> Optional[Dict[str, Any]]:
    """
    Defensively parses raw text response into JSON:
    1. Direct JSON parse
    2. Strip markdown fences (```json ... ```)
    3. Regex search for outermost JSON object {...}
    """
    text = content.strip()

    # Attempt 1: Direct JSON parsing
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: Strip markdown fences
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if fence_match:
        fenced_text = fence_match.group(1).strip()
        try:
            return json.loads(fenced_text)
        except json.JSONDecodeError:
            pass

    # Attempt 3: Extract outermost curly braces {...}
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None


async def explain_findings_with_groq(
    redacted_code: str,
    semgrep_findings: List[Dict[str, Any]],
    api_key: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Sends redacted source code and Semgrep findings to Groq LLM (llama-3.3-70b-versatile).
    Returns a dictionary mapping rule_id to AI enrichment details:
    {
      rule_id: {
        "ai_severity": str,
        "ai_explanation": str,
        "ai_fix_suggestion": str,
        "ai_confidence": str
      }
    }
    """
    if not semgrep_findings:
        return {}

    groq_api_key = api_key or os.getenv("GROQ_API_KEY", "").strip()
    if not groq_api_key:
        logger.warning("GROQ_API_KEY is not set. Skipping LLM explanations.")
        return {}

    system_prompt = (
        "You are a helpful and approachable Senior Security Engineer mentoring a software developer.\n"
        "You will be given the source code (with sensitive credentials already redacted) and a list of Semgrep static analysis findings.\n\n"
        "Your goal is to explain security issues in clear, everyday language that any developer can easily understand, without unexplained security jargon.\n\n"
        "For each finding, provide:\n"
        "1. 'rule_id': Exact rule_id matching the input finding.\n"
        "2. 'ai_severity': Your independent assessment of severity: 'critical', 'high', 'medium', or 'low'.\n"
        "3. 'ai_explanation': A clear explanation following this EXACT two-part structure in plain English:\n"
        "   - Part 1 (The Problem): What is wrong in simple terms and what bad thing could happen if someone exploits it (e.g. an attacker could steal data or run arbitrary commands).\n"
        "   - Part 2 (How to Fix It): Concrete, step-by-step guidance on what specific function, parameter, or pattern should be used instead.\n"
        "4. 'ai_fix_suggestion': A clear, ready-to-use code snippet or precise replacement code showing the secure pattern. Keep it immediately understandable without needing external documentation.\n"
        "5. 'ai_confidence': 'high', 'medium', or 'low'.\n\n"
        "CRITICAL INSTRUCTION: You must return ONLY valid, raw JSON with NO markdown formatting, NO ```json fences, and NO preamble or postamble.\n"
        "JSON shape:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "rule_id": "string",\n'
        '      "ai_severity": "critical|high|medium|low",\n'
        '      "ai_explanation": "string",\n'
        '      "ai_fix_suggestion": "string",\n'
        '      "ai_confidence": "high|medium|low"\n'
        "    }\n"
        "  ]\n"
        "}"
    )

    user_prompt = (
        f"Source Code:\n```\n{redacted_code}\n```\n\n"
        f"Semgrep Findings:\n{json.dumps(semgrep_findings, indent=2)}\n\n"
        "Provide your analysis in the specified JSON format."
    )

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 2048,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(GROQ_ENDPOINT, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        message_content = data["choices"][0]["message"]["content"]
        parsed_json = _extract_json_payload(message_content)

        if not parsed_json or "findings" not in parsed_json:
            logger.warning(f"Groq response did not contain expected 'findings' list. Raw: {message_content[:300]}")
            return {}

        results_by_rule: Dict[str, Dict[str, Any]] = {}
        for item in parsed_json.get("findings", []):
            rule_id = item.get("rule_id")
            if rule_id:
                results_by_rule[rule_id] = {
                    "ai_severity": str(item.get("ai_severity", "medium")).lower(),
                    "ai_explanation": item.get("ai_explanation", "No explanation provided."),
                    "ai_fix_suggestion": item.get("ai_fix_suggestion", "Review code logic."),
                    "ai_confidence": str(item.get("ai_confidence", "medium")).lower(),
                }

        return results_by_rule

    except Exception as exc:
        logger.error(f"Error calling Groq API for finding explanations: {exc}", exc_info=True)
        return {}


async def independent_security_review_with_groq(
    redacted_code: str,
    language: str = "python",
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Performs an independent AI security review pass when static analysis rules detect no findings.
    Identifies vulnerabilities frequently missed by static AST tools (e.g. mass assignment,
    broken authorization, IDOR, business logic flaws, unvalidated inputs).
    Returns a list of finding dicts marked with source='ai_only'.
    """
    if not redacted_code or not redacted_code.strip():
        return []

    groq_api_key = api_key or os.getenv("GROQ_API_KEY", "").strip()
    if not groq_api_key:
        logger.warning("GROQ_API_KEY is not set. Skipping AI independent review pass.")
        return []

    system_prompt = (
        "You are an expert Application Security Engineer conducting an independent manual code audit.\n"
        "No static analysis rules matched this snippet, so you are performing a comprehensive secondary review to catch security vulnerabilities that static pattern scanners frequently miss.\n\n"
        "Audit specifically for:\n"
        "1. Mass Assignment / Object Injection (e.g. passing unvalidated `req.body` directly to ORM/ODM create/update methods like Mongoose, Prisma, Sequelize)\n"
        "2. Missing or broken authentication & authorization checks (e.g. IDOR, privilege escalation)\n"
        "3. Injection vulnerabilities (SQL, Command, NoSQL, LDAP, Server-Side Template, Regex DoS)\n"
        "4. Insecure cryptographic practices and hardcoded secrets\n"
        "5. Insecure defaults, unhandled exceptions leaking stack traces, or missing input sanitization\n\n"
        "If the code is secure and has no genuine security concerns, return an empty findings list: `{\"findings\": []}`.\n\n"
        "If you discover security issues, provide each issue in plain, approachable English with this EXACT structure:\n"
        "- 'rule_id': Concise identifier, e.g. 'ai.security.mass-assignment', 'ai.security.idor', 'ai.security.missing-auth'\n"
        "- 'severity': 'critical', 'high', 'medium', or 'low'\n"
        "- 'line_number': Approximate integer line number where the issue occurs\n"
        "- 'raw_message': Clear 1-sentence summary of the detected vulnerability\n"
        "- 'ai_explanation': A clear two-part explanation in plain English:\n"
        "    Part 1 (The Problem): What is wrong and what bad thing could happen if exploited.\n"
        "    Part 2 (How to Fix It): Specific, concrete steps on what code pattern to use instead.\n"
        "- 'ai_fix_suggestion': Concrete, ready-to-use replacement code snippet demonstrating the secure pattern\n"
        "- 'ai_confidence': 'high', 'medium', or 'low'\n\n"
        "CRITICAL INSTRUCTION: Return ONLY valid, raw JSON with NO markdown formatting, NO ```json fences, and NO preamble.\n"
        "JSON shape:\n"
        "{\n"
        '  "findings": [\n'
        "    {\n"
        '      "rule_id": "string",\n'
        '      "severity": "critical|high|medium|low",\n'
        '      "line_number": 1,\n'
        '      "raw_message": "string",\n'
        '      "ai_explanation": "string",\n'
        '      "ai_fix_suggestion": "string",\n'
        '      "ai_confidence": "high|medium|low"\n'
        "    }\n"
        "  ]\n"
        "}"
    )

    user_prompt = (
        f"Language: {language}\n\n"
        f"Source Code:\n```\n{redacted_code}\n```\n\n"
        "Perform your independent security audit and return findings in the specified JSON format."
    )

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 2048,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(GROQ_ENDPOINT, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        message_content = data["choices"][0]["message"]["content"]
        parsed_json = _extract_json_payload(message_content)

        if not parsed_json or "findings" not in parsed_json:
            return []

        ai_findings: List[Dict[str, Any]] = []
        for item in parsed_json.get("findings", []):
            rule_id = item.get("rule_id", "ai.security.manual-audit-finding")
            severity = str(item.get("severity", "MEDIUM")).upper()
            line_number = int(item.get("line_number", 1))
            raw_message = item.get("raw_message", "Security risk identified by AI independent audit.")
            ai_explanation = item.get("ai_explanation")
            ai_fix = item.get("ai_fix_suggestion")
            ai_confidence = str(item.get("ai_confidence", "medium")).lower()

            ai_findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "file_path": "source",
                "line_number": line_number,
                "raw_message": raw_message,
                "ai_explanation": ai_explanation,
                "ai_fix_suggestion": ai_fix,
                "ai_confidence": ai_confidence,
                "severity_conflict": False,
                "source": "ai_only",
            })

        return ai_findings

    except Exception as exc:
        logger.error(f"Error calling Groq API for independent review: {exc}", exc_info=True)
        return []

