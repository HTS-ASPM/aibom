"""Tiny demo app used by `aibom demo`.

Imports openai + anthropic, references pinecone, and pulls training
data from S3 — touches the provider, package, vector_db, and dataset
detector layers in a single file.
"""

from __future__ import annotations

import os

import anthropic
import openai
from pinecone import Pinecone


SYSTEM_PROMPT = "You are a helpful AI assistant for the AiBOM demo fixture."

S3_TRAINING_BUCKET = "s3://aibom-demo/training/v1.parquet"


def call_openai(question: str) -> str:
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    return response.choices[0].message.content or ""


def call_anthropic(question: str) -> str:
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    message = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": question}],
    )
    return message.content[0].text


def lookup_context(query: str) -> list[str]:
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    index = pc.Index("aibom-demo")
    matches = index.query(vector=[0.0] * 1536, top_k=3, include_metadata=True)
    return [m["metadata"].get("text", "") for m in matches.get("matches", [])]
