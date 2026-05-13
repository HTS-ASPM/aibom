from openai import OpenAI

SYSTEM_PROMPT = "You are an invoice assistant for customer billing."


def summarize_invoice(invoice_text: str) -> str:
    client = OpenAI()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": invoice_text},
    ]
    return client.chat.completions.create(model="gpt-4o", messages=messages)
