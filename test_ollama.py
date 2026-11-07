import ollama

response = ollama.chat(
    model='qwen3.5:2b',
    messages=[
        {'role': 'system', 'content': 'You are a cybersecurity log analyst.'},
        {'role': 'user', 'content': 'Is this a security threat? GET /admin/login?id=1' }
    ]
)

print("Model Response:")
print(response['message']['content'])