#!/bin/bash
cd /home/kavia/workspace/code-generation/production-log-insights-323390/production_log_analyzer_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

