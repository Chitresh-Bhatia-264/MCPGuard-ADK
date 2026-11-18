"""Live `google.genai` SDK & REST Client with Honest Token Telemetry.

Uses the official `google.genai.Client` SDK when installed (falling back to HTTPS REST
`v1beta/models/{model}:generateContent`).
- When `GEMINI_API_KEY` is active: executes real Gemini inference and returns exact
  `prompt_token_count`, `candidates_token_count`, and `thoughts_token_count`.
- When running offline (no API key): returns `live_api_called=False` and `0` billed tokens
  (never fabricates magic token constants), alongside deterministic `estimate_payload_tokens()`.
"""

from __future__ import annotations

import json
import math
import os
import urllib.request
from pathlib import Path
from typing import Any

try:
    from google import genai
    from google.genai import types as genai_types

    _HAS_GOOGLE_GENAI = True
except ImportError:  # pragma: no cover
    _HAS_GOOGLE_GENAI = False


def estimate_payload_tokens(text: str) -> int:
    """Deterministic UTF-8 BPE approximation (~4 bytes/token) for dry-run FinOps sizing."""
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 4.0))


def _load_dotenv_if_present() -> None:
    for env_path in (Path.cwd() / ".env", Path.home() / ".env"):
        if not env_path.is_file():
            continue
        try:
            for raw_line in env_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
        except Exception:
            pass


def get_active_gemini_api_key() -> str | None:
    """Return a valid `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) if configured, or None if missing."""
    _load_dotenv_if_present()
    key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if not key or key in {"your-google-ai-studio-api-key", "your-free-ai-studio-key", "changeme"}:
        return None
    return key


def call_gemini_generate_content(
    preferred_model: str,
    system_instruction: str,
    user_prompt: str,
    timeout_sec: float = 12.0,
) -> dict[str, Any]:
    """Invoke live `google.genai.Client` (or REST fallback) when `GEMINI_API_KEY` is configured."""
    api_key = get_active_gemini_api_key()
    estimated_in = estimate_payload_tokens(system_instruction + "\n" + user_prompt)
    if not api_key:
        return {
            "live_api_called": False,
            "execution_mode": "offline_deterministic",
            "resolved_model": preferred_model,
            "text": "",
            "input_tokens": 0,
            "output_tokens": 0,
            "thinking_tokens": 0,
            "estimated_dry_run_input_tokens": estimated_in,
        }

    # Try preferred model first, falling back to current Flash-Lite / GA Gemini tiers if alias is unavailable
    candidate_models = [preferred_model]
    if "lite" in preferred_model and "gemini-3.5-flash-lite" not in candidate_models:
        candidate_models.append("gemini-3.5-flash-lite")
    if "pro" in preferred_model and "gemini-2.5-pro" not in candidate_models:
        candidate_models.append("gemini-2.5-pro")
    if "gemini-2.5-flash" not in candidate_models:
        candidate_models.append("gemini-2.5-flash")

    if _HAS_GOOGLE_GENAI:
        client = genai.Client(api_key=api_key)
        for model_name in candidate_models:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents=user_prompt,
                    config=genai_types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=0.1,
                        max_output_tokens=512,
                    ),
                )
                usage = getattr(resp, "usage_metadata", None)
                return {
                    "live_api_called": True,
                    "execution_mode": "live_gemini_api",
                    "resolved_model": model_name,
                    "text": (resp.text or "").strip(),
                    "input_tokens": int(getattr(usage, "prompt_token_count", 0) or 0),
                    "output_tokens": int(getattr(usage, "candidates_token_count", 0) or 0),
                    "thinking_tokens": int(getattr(usage, "thoughts_token_count", 0) or 0),
                    "estimated_dry_run_input_tokens": estimated_in,
                }
            except Exception:
                continue

    # Zero-dependency HTTPS REST fallback
    for model_name in candidate_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 512},
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            candidates = body.get("candidates", [])
            text = ""
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "\n".join(p.get("text", "") for p in parts if "text" in p).strip()
            usage = body.get("usageMetadata", {})
            return {
                "live_api_called": True,
                "execution_mode": "live_gemini_api",
                "resolved_model": model_name,
                "text": text,
                "input_tokens": int(usage.get("promptTokenCount", 0)),
                "output_tokens": int(usage.get("candidatesTokenCount", 0)),
                "thinking_tokens": int(usage.get("thoughtsTokenCount", 0)),
                "estimated_dry_run_input_tokens": estimated_in,
            }
        except Exception:
            continue

    return {
        "live_api_called": False,
        "execution_mode": "offline_deterministic_fallback",
        "resolved_model": preferred_model,
        "text": "",
        "input_tokens": 0,
        "output_tokens": 0,
        "thinking_tokens": 0,
        "estimated_dry_run_input_tokens": estimated_in,
    }
