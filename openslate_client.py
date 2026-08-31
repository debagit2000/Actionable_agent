import requests

from config import (
    OPENSLATE_URL,
    OPENSLATE_API_KEY,
    MODEL_NAME
)


class OpenSlateClient:

    def __init__(self):

        self.headers = {
            "Authorization": f"Bearer {OPENSLATE_API_KEY}",
            "Content-Type": "application/json"
        }

    def ask(self, prompt):

        payload = {
            "model": MODEL_NAME,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1
        }

        response = requests.post(
            OPENSLATE_URL,
            headers=self.headers,
            json=payload,
            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        return data["choices"][0]["message"]["content"]
