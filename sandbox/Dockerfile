ARG RUNNER_BASE=python:3.12-slim
FROM ${RUNNER_BASE}
WORKDIR /runner
COPY runner.py canary.txt /runner/
USER 65532:65532
ENTRYPOINT ["python", "-I", "-B", "/runner/runner.py"]
