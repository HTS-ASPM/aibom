from openai import OpenAI

client = OpenAI()
client.chat.completions.create(model="claude-sonnet", messages=[{"role": "user", "content": "hi"}])
