# Production Container for Google Cloud Run (`adk deploy cloud_run` / `gcloud run deploy`)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OTEL_SEMCONV_STABILITY_OPT_IN="gen_ai_latest_experimental" \
    OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT="EVENT_ONLY" \
    ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS="false" \
    PORT=8080

WORKDIR /app
COPY pyproject.toml README.md LICENSE llms.txt ./
COPY mcpguard_adk ./mcpguard_adk
COPY examples ./examples
COPY evals ./evals

RUN pip install --no-cache-dir -e .

EXPOSE 8080
CMD ["python", "-m", "mcpguard_adk.cli", "serve-a2a", "--host", "0.0.0.0", "--port", "8080"]
