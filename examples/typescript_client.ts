const baseUrl = process.env.MLX_SENTINEL_URL ?? "http://127.0.0.1:8081";
const apiKey = process.env.MLX_SENTINEL_API_KEY;

const response = await fetch(`${baseUrl}/v1/chat/completions`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
  },
  body: JSON.stringify({
    model: "local",
    messages: [{ role: "user", content: "Hello from TypeScript" }],
    max_tokens: 64,
  }),
});

if (!response.ok) throw new Error(await response.text());
const result = await response.json() as { choices: Array<{ message: { content: string } }> };
console.log(result.choices[0].message.content);
