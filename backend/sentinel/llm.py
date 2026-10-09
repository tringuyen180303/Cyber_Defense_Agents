"""Thin OpenAI wrapper: JSON-only responses and a bounded tool-calling loop."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from . import config

log = logging.getLogger(__name__)


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

    def json(self, system: str, user: str) -> dict[str, Any]:
        msgs = [{"role": "system", "content": system + "\nRespond with a single JSON object only."},
                {"role": "user", "content": user}]
        for _ in range(2):
            resp = self.client.chat.completions.create(model=self.model, messages=msgs, temperature=0,
                                                       response_format={"type": "json_object"})
            text = resp.choices[0].message.content or "{}"
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                msgs.append({"role": "assistant", "content": text})
                msgs.append({"role": "user", "content": "That was not valid JSON. Return only the JSON object."})
        raise ValueError("model did not return valid JSON")

    def tool_loop(self, system: str, user: str, tools: dict[str, tuple[dict, Callable[..., Any]]],
                  on_call: Callable[[str, dict, Any], None], max_steps: int = 8) -> dict[str, Any]:
        specs = [{"type": "function", "function": {"name": n, **spec}} for n, (spec, _) in tools.items()]
        msgs: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        for step in range(max_steps):
            resp = self.client.chat.completions.create(model=self.model, messages=msgs, tools=specs, temperature=0)
            m = resp.choices[0].message
            if not m.tool_calls:
                break
            msgs.append({"role": "assistant", "content": m.content or "",
                         "tool_calls": [tc.model_dump() for tc in m.tool_calls]})
            for tc in m.tool_calls:
                args = json.loads(tc.function.arguments or "{}")
                fn = tools.get(tc.function.name, (None, None))[1]
                result = fn(**args) if fn else {"error": "unknown tool"}
                on_call(tc.function.name, args, result)
                msgs.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, default=str)[:12000]})
        msgs.append({"role": "user", "content": "Investigation complete. Return your final answer as a single JSON "
                                                "object in the format requested."})
        resp = self.client.chat.completions.create(model=self.model, messages=msgs, temperature=0,
                                                   response_format={"type": "json_object"})
        return json.loads(resp.choices[0].message.content or "{}")
