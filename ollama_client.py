"""Tiny client for a local Ollama server that looks like the Groq/OpenAI client.

Uses only httpx (already installed with groq), so no extra packages are needed:
    client.chat.completions.create(model=..., messages=..., tools=...)
"""

import json
import uuid
from types import SimpleNamespace

import httpx


class ApiError(Exception):
    def __init__(self, status_code, message=""):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code


def _to_namespace(obj):
    if isinstance(obj, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return [_to_namespace(v) for v in obj]
    return obj


class _Completions:
    def __init__(self, client):
        self._client = client

    def create(self, **kwargs):
        return self._client._chat(kwargs)


class OllamaClient:
    def __init__(self, base_url="http://localhost:11434", timeout=300.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.chat = SimpleNamespace(completions=_Completions(self))

    def _chat(self, payload):
        try:
            # trust_env=False: Ollama runs on this computer, so never send it through
            # a system/environment proxy (HTTP_PROXY etc.), which would break it.
            response = httpx.post(f"{self.base_url}/v1/chat/completions",
                                  json=payload, timeout=self.timeout, trust_env=False)
        except httpx.ConnectError:
            raise ApiError(0, "Cannot connect to Ollama. Is the Ollama app running?")
        except httpx.TimeoutException:
            raise ApiError(0, "Ollama took too long to answer (the model may still be loading).")
        if response.status_code >= 400:
            raise ApiError(response.status_code, response.text[:300])

        data = response.json()
        message = data["choices"][0]["message"]
        for call in message.get("tool_calls") or []:
            call["id"] = call.get("id") or f"call_{uuid.uuid4().hex[:8]}"
            arguments = call["function"].get("arguments")
            if not isinstance(arguments, str):
                call["function"]["arguments"] = json.dumps(arguments or {})
        return _to_namespace(data)