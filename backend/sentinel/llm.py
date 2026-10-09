"""Thin OpenAI wrapper: JSON-only responses and a bounded tool-calling loop."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable

from . import config, telemetry

log = logging.getLogger(__name__)

# USD per 1M tokens (input, output) for cost estimates in traces; override with SENTINEL_LLM_PRICE="in,out".
PRICES = {"gpt-4.1": (2.0, 8.0), "gpt-4.1-mini": (0.4, 1.6), "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.6)}


def _price(model: str) -> tuple[float, float]:
    if config.LLM_PRICE:
        a, b = config.LLM_PRICE.split(",")
        return float(a), float(b)
    return next((p for m, p in sorted(PRICES.items(), key=lambda kv: -len(kv[0])) if model.startswith(m)),
                (0.0, 0.0))


class LLM:
    def __init__(self, disabled: bool = False) -> None:
        self.client = None
        if config.OPENAI_API_KEY and not disabled:
            from openai import OpenAI

            self.client = OpenAI(api_key=config.OPENAI_API_KEY)
        self.model = config.OPENAI_MODEL

    @property
    def available(self) -> bool:
        return self.client is not None

    @property
    def label(self) -> str:
        return f"OpenAI {self.model}" if self.available else "offline (deterministic reasoning)"

    def _create(self, operation: str, **kw: Any):
        with telemetry.span(f"chat {self.model}", **{"gen_ai.system": "openai", "gen_ai.operation.name": "chat",
                                                      "gen_ai.request.model": self.model,
                                                      "sentinel.llm.purpose": operation,
                                                      "gen_ai.request.tools": len(kw.get("tools") or [])}) as s:
            t0 = time.monotonic()
            try:
                resp = self.client.chat.completions.create(model=self.model, temperature=0, **kw)
            except Exception as exc:
                s.fail(f"{type(exc).__name__}: {exc}")
                raise
            u = resp.usage
            pin, pout = _price(self.model)
            tin, tout = (u.prompt_tokens, u.completion_tokens) if u else (0, 0)
            msg = resp.choices[0].message
            s.set(**{"gen_ai.response.model": resp.model, "gen_ai.usage.input_tokens": tin,
                     "gen_ai.usage.output_tokens": tout, "gen_ai.response.finish_reasons": [resp.choices[0].finish_reason],
                     "sentinel.llm.cost_usd": round((tin * pin + tout * pout) / 1e6, 6),
                     "sentinel.llm.latency_ms": int((time.monotonic() - t0) * 1000),
                     "sentinel.llm.tool_calls": [tc.function.name for tc in (msg.tool_calls or [])]})
            return resp

    def json(self, system: str, user: str, operation: str = "json") -> dict[str, Any]:
        msgs = [{"role": "system", "content": system + "\nRespond with a single JSON object only."},
                {"role": "user", "content": user}]
        for _ in range(2):
            resp = self._create(operation, messages=msgs, response_format={"type": "json_object"})
            text = resp.choices[0].message.content or "{}"
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                msgs.append({"role": "assistant", "content": text})
                msgs.append({"role": "user", "content": "That was not valid JSON. Return only the JSON object."})
        raise ValueError("model did not return valid JSON")

    def tool_loop(self, system: str, user: str, tools: dict[str, tuple[dict, Callable[..., Any]]],
                  on_call: Callable[[str, dict, Any], None], max_steps: int = 8,
                  operation: str = "tool_loop") -> dict[str, Any]:
        specs = [{"type": "function", "function": {"name": n, **spec}} for n, (spec, _) in tools.items()]
        msgs: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        for step in range(max_steps):
            resp = self._create(f"{operation}.step{step + 1}", messages=msgs, tools=specs)
            m = resp.choices[0].message
            if not m.tool_calls:
                break
            msgs.append({"role": "assistant", "content": m.content or "",
                         "tool_calls": [tc.model_dump() for tc in m.tool_calls]})
            for tc in m.tool_calls:
                args = json.loads(tc.function.arguments or "{}")
                fn = tools.get(tc.function.name, (None, None))[1]
                with telemetry.span(f"tool {tc.function.name}", **{"sentinel.tool.name": tc.function.name,
                                                                   "sentinel.tool.args": json.dumps(args)[:500],
                                                                   "sentinel.tool.chosen_by": "llm"}) as s:
                    result = fn(**args) if fn else {"error": "unknown tool"}
                    if isinstance(result, dict):
                        s.set(**{"sentinel.evidence_id": result.get("evidence_id"),
                                 "sentinel.tool.error": result.get("error")})
                        if result.get("error"):
                            s.fail(str(result["error"]))
                on_call(tc.function.name, args, result)
                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, default=str)[:12000]})
        msgs.append({"role": "user", "content": "Investigation complete. Return your final answer as a single JSON "
                                                "object in the format requested."})
        resp = self._create(f"{operation}.final", messages=msgs, response_format={"type": "json_object"})
        return json.loads(resp.choices[0].message.content or "{}")
