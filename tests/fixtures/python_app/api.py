from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.post("/answer")
def answer(prompt: str) -> str:
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    )
