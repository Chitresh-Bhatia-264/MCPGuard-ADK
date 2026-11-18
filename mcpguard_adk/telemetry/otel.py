"""Real OpenTelemetry SDK & Google Cloud Trace OTLP Instrumentation for MCPGuard-ADK.

Uses the official `opentelemetry.sdk.trace` `TracerProvider` + `InMemorySpanExporter`
when available, emitting W3C TraceContext spans (`invoke_workflow`, `invoke_agent`,
`execute_tool`, `generate_content`) and exporting standard OTLP/JSON `resourceSpans`
payloads ready for Jaeger, Grafana Tempo, or Google Cloud Trace.
"""

from __future__ import annotations

import os
import time
import uuid
from contextlib import contextmanager
from typing import Any, Generator

try:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    _HAS_OTEL_SDK = True
except ImportError:  # pragma: no cover
    _HAS_OTEL_SDK = False


def configure_adk_otel_environment() -> dict[str, str]:
    """Configure and enforce safe OpenTelemetry environment variables for ADK 2.0.

    Explicitly prevents `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT='true'`, which
    Google's instrumentation guide warns breaks trace and log collection under the latest
    `gen_ai_latest_experimental` semantic conventions.
    """
    os.environ.setdefault("OTEL_SEMCONV_STABILITY_OPT_IN", "gen_ai_latest_experimental")
    current_capture = os.environ.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "EVENT_ONLY")
    if current_capture.strip().lower() == "true":
        os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "EVENT_ONLY"
    else:
        os.environ.setdefault("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "EVENT_ONLY")

    os.environ.setdefault("ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS", "false")
    os.environ.setdefault("OTEL_SERVICE_NAME", "mcpguard-adk")

    return {
        "OTEL_SEMCONV_STABILITY_OPT_IN": os.environ["OTEL_SEMCONV_STABILITY_OPT_IN"],
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT": os.environ[
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"
        ],
        "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS": os.environ["ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"],
        "OTEL_SERVICE_NAME": os.environ["OTEL_SERVICE_NAME"],
    }


def validate_otel_env_safety(env: dict[str, str] | None = None) -> list[str]:
    """Return any violations of ADK OpenTelemetry production best practices."""
    target = env if env is not None else dict(os.environ)
    issues: list[str] = []
    if target.get("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "").lower() == "true":
        issues.append(
            "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT='true' breaks trace and log "
            "collection under gen_ai_latest_experimental; use 'EVENT_ONLY'."
        )
    if target.get("ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS", "").lower() == "true":
        issues.append(
            "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS='true' leaks PII and raw repository blobs "
            "into span attributes; set to 'false'."
        )
    return issues


class OtelTraceRecorder:
    """Records real OpenTelemetry SDK spans and exports OTLP/JSON `resourceSpans`."""

    def __init__(self) -> None:
        configure_adk_otel_environment()
        self.trace_id: str = uuid.uuid4().hex
        self.spans: list[dict[str, Any]] = []
        self._sdk_exporter: Any = None
        self._tracer: Any = None

        if _HAS_OTEL_SDK:
            resource = Resource.create(
                {
                    "service.name": os.environ.get("OTEL_SERVICE_NAME", "mcpguard-adk"),
                    "service.version": "0.3.3",
                    "telemetry.sdk.language": "python",
                    "gen_ai.system": "gcp.gemini",
                }
            )
            provider = TracerProvider(resource=resource)
            self._sdk_exporter = InMemorySpanExporter()
            provider.add_span_processor(SimpleSpanProcessor(self._sdk_exporter))
            self._tracer = provider.get_tracer("mcpguard_adk.telemetry", "0.3.3")

    @contextmanager
    def span(
        self,
        operation_name: str,
        target_name: str,
        model: str = "deterministic-code-node",
        input_tokens: int = 0,
        output_tokens: int = 0,
        execution_mode: str = "deterministic",
        attributes: dict[str, Any] | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """Record a real OpenTelemetry SDK span and structured GenAI waterfall entry."""
        span_name = f"{operation_name} {target_name}"
        start_wall_ns = time.time_ns()
        start_perf_ns = time.perf_counter_ns()
        extra_attrs = attributes or {}

        span_record: dict[str, Any] = {
            "trace_id": self.trace_id,
            "span_id": uuid.uuid4().hex[:16],
            "name": span_name,
            "gen_ai.system": "gcp.gemini",
            "gen_ai.operation.name": operation_name,
            "gen_ai.agent.name": target_name,
            "gen_ai.request.model": model,
            "gen_ai.usage.input_tokens": input_tokens,
            "gen_ai.usage.output_tokens": output_tokens,
            "gen_ai.execution_mode": execution_mode,
            "adk.capture_message_content_in_spans": False,
            "start_time_unix_nano": start_wall_ns,
            "end_time_unix_nano": start_wall_ns,
            "attributes": extra_attrs,
            "duration_ms": 0.0,
        }

        if self._tracer is not None:
            with self._tracer.start_as_current_span(span_name) as otel_span:
                ctx = otel_span.get_span_context()
                self.trace_id = f"{ctx.trace_id:032x}"
                span_record["trace_id"] = self.trace_id
                span_record["span_id"] = f"{ctx.span_id:016x}"
                try:
                    yield span_record
                finally:
                    elapsed_ns = max(time.perf_counter_ns() - start_perf_ns, 10_000)
                    span_record["end_time_unix_nano"] = start_wall_ns + elapsed_ns
                    span_record["duration_ms"] = round(elapsed_ns / 1_000_000.0, 3)
                    otel_span.set_attribute("gen_ai.system", "gcp.gemini")
                    otel_span.set_attribute("gen_ai.operation.name", operation_name)
                    otel_span.set_attribute("gen_ai.agent.name", target_name)
                    otel_span.set_attribute("gen_ai.request.model", str(span_record["gen_ai.request.model"]))
                    otel_span.set_attribute(
                        "gen_ai.usage.input_tokens", int(span_record["gen_ai.usage.input_tokens"])
                    )
                    otel_span.set_attribute(
                        "gen_ai.usage.output_tokens", int(span_record["gen_ai.usage.output_tokens"])
                    )
                    otel_span.set_attribute(
                        "gen_ai.execution_mode", str(span_record["gen_ai.execution_mode"])
                    )
                    self.spans.append(span_record)
        else:  # pragma: no cover
            try:
                yield span_record
            finally:
                elapsed_ns = max(time.perf_counter_ns() - start_perf_ns, 10_000)
                span_record["end_time_unix_nano"] = start_wall_ns + elapsed_ns
                span_record["duration_ms"] = round(elapsed_ns / 1_000_000.0, 3)
                self.spans.append(span_record)

    def export_otlp_json(self) -> dict[str, Any]:
        """Export recorded spans in OTLP/JSON (`ExportTraceServiceRequest`) format for Jaeger/Tempo/Cloud Trace."""
        otlp_spans = []
        for sp in self.spans:
            otlp_spans.append(
                {
                    "traceId": sp["trace_id"],
                    "spanId": sp["span_id"],
                    "name": sp["name"],
                    "kind": 1,
                    "startTimeUnixNano": str(sp["start_time_unix_nano"]),
                    "endTimeUnixNano": str(sp["end_time_unix_nano"]),
                    "attributes": [
                        {"key": "gen_ai.system", "value": {"stringValue": "gcp.gemini"}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": sp["gen_ai.operation.name"]}},
                        {"key": "gen_ai.agent.name", "value": {"stringValue": sp["gen_ai.agent.name"]}},
                        {"key": "gen_ai.request.model", "value": {"stringValue": str(sp["gen_ai.request.model"])}},
                        {
                            "key": "gen_ai.usage.input_tokens",
                            "value": {"intValue": str(sp["gen_ai.usage.input_tokens"])},
                        },
                        {
                            "key": "gen_ai.usage.output_tokens",
                            "value": {"intValue": str(sp["gen_ai.usage.output_tokens"])},
                        },
                        {
                            "key": "gen_ai.execution_mode",
                            "value": {"stringValue": str(sp["gen_ai.execution_mode"])},
                        },
                    ],
                }
            )
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "mcpguard-adk"}},
                            {"key": "service.version", "value": {"stringValue": "0.3.3"}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "mcpguard_adk.telemetry", "version": "0.3.3"},
                            "spans": otlp_spans,
                        }
                    ],
                }
            ]
        }
