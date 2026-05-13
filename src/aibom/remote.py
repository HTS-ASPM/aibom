from __future__ import annotations

from urllib.request import Request, urlopen
import json


def fetch_json(url: str, headers: dict[str, str] | None = None) -> dict:
    request = Request(url, headers=headers or {})
    with urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))
