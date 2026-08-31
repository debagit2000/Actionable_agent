import os

OPENSLATE_URL = "https://your-openslate-endpoint/v1/chat/completions"

OPENSLATE_API_KEY = os.getenv(
    "OPENSLATE_API_KEY"
)

MODEL_NAME = "your-model"

LOG_DIR = "logs"

GENERATED_DIR = "generated"

EXECUTION_TIMEOUT = 300
