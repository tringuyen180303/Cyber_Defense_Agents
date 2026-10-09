"""OpenTelemetry tracing + logs for the agent pipeline (OTLP → collector → ClickHouse → Grafana).

Disabled unless OTEL_EXPORTER_OTLP_ENDPOINT is set. Evaluation replays run inside `quiet()` so hundreds of
scenario runs during learning don't flood the traces; the learning jobs themselves are traced at a coarser level.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import logging
from typing import Any, Iterator

from . import config

_quiet: contextvars.ContextVar[bool] = contextvars.ContextVar("sentinel_quiet", default=False)
_tracer = None
_agent_log = logging.getLogger("sentinel.agentlog")
_agent_log.propagate = False
_agent_log.setLevel(logging.INFO)


def init() -> None:
    global _tracer
    if _tracer is not None or not config.OTEL_ENDPOINT:
        return
    from opentelemetry import trace
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({"service.name": "sentinel", "service.namespace": "cyber-defense",
                                "deployment.environment": config.ENVIRONMENT})
    tp = TracerProvider(resource=resource)
    tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{config.OTEL_ENDPOINT}/v1/traces"),
                                             schedule_delay_millis=1000))
    trace.set_tracer_provider(tp)
    lp = LoggerProvider(resource=resource)
    lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{config.OTEL_ENDPOINT}/v1/logs"),
                                                        schedule_delay_millis=1000))
    set_logger_provider(lp)
    _agent_log.addHandler(LoggingHandler(level=logging.INFO, logger_provider=lp))
    _tracer = trace.get_tracer("sentinel")


def enabled() -> bool:
    return _tracer is not None and not _quiet.get()


@contextlib.contextmanager
def quiet() -> Iterator[None]:
    token = _quiet.set(True)
    try:
        yield
    finally:
        _quiet.reset(token)


def _clean(attrs: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in attrs.items():
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            v = [str(x) for x in v]
        elif not isinstance(v, (str, bool, int, float)):
            v = str(v)
        out[k] = v
    return out


class _NoSpan:
    def set(self, **attrs: Any) -> None:
        pass

    def event(self, name: str, **attrs: Any) -> None:
        pass

    def fail(self, message: str) -> None:
        pass

    @property
    def trace_id(self) -> str | None:
        return None


class _Span(_NoSpan):
    def __init__(self, span) -> None:
        self.span = span

    def set(self, **attrs: Any) -> None:
        self.span.set_attributes(_clean(attrs))

    def event(self, name: str, **attrs: Any) -> None:
        self.span.add_event(name, _clean(attrs))

    def fail(self, message: str) -> None:
        from opentelemetry.trace import Status, StatusCode

        self.span.set_status(Status(StatusCode.ERROR, message))

    @property
    def trace_id(self) -> str:
        return format(self.span.get_span_context().trace_id, "032x")


@contextlib.contextmanager
def span(name: str, **attrs: Any) -> Iterator[_NoSpan]:
    if not enabled():
        yield _NoSpan()
        return
    with _tracer.start_as_current_span(name, attributes=_clean(attrs)) as s:
        yield _Span(s)


def traced(name: str, **static: Any):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            with span(name, **static):
                return fn(*a, **kw)
        return wrapper
    return deco


def annotate(**attrs: Any) -> None:
    """Set attributes on the current span (no-op when tracing is off)."""
    if enabled():
        from opentelemetry import trace

        trace.get_current_span().set_attributes(_clean(attrs))


def fail_current(message: str) -> None:
    if enabled():
        from opentelemetry import trace
        from opentelemetry.trace import Status, StatusCode

        trace.get_current_span().set_status(Status(StatusCode.ERROR, message))


def add_event(name: str, **attrs: Any) -> None:
    if enabled():
        from opentelemetry import trace

        trace.get_current_span().add_event(name, _clean(attrs))


def agent_log(run_id: str, agent: str, kind: str, message: str, **attrs: Any) -> None:
    if not enabled():
        return
    level = logging.ERROR if kind == "error" else logging.INFO
    _agent_log.log(level, message, extra=_clean({"sentinel.run_id": run_id, "sentinel.agent": agent,
                                                 "sentinel.kind": kind, **attrs}))


def trace_url(trace_id: str | None) -> str | None:
    if not trace_id or not config.GRAFANA_URL:
        return None
    return f"{config.GRAFANA_URL}/d/sentinel-agents/sentinel-agent-observability?var-trace_id={trace_id}"
