# MLX Sentinel

True KV-cache analysis and response security for MLX inference on Apple Silicon.

MLX Sentinel runs generation through `mlx_lm.generate_step`, inspects the real `KVCache` tensors, computes privacy-preserving aggregate statistics, scores the request and response, and returns an OpenAI-compatible response with security metadata. It also provides a web dashboard and intrusion-prevention policy.

## Why it exists

Prompt and response filters miss attacks that are hidden, indirect, or expressed through model behavior. MLX Sentinel watches the actual local inference cache:

```text
prompt → MLX model → real KVCache → aggregate analysis → response + decision
```

It never uploads raw KV tensors. It reports only cache-layer count, cache-token count, K/V norm summaries, and an optional attention statistic.

## Install

Use the same Apple Silicon virtual environment as MLX-LM:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install mlx mlx-lm
```

## Run

```sh
python -m mlx_sentinel.server \
  --model mlx-community/Qwen3-0.6B-4bit \
  --port 8081
```

Then call it with an OpenAI-compatible request:

```sh
curl http://127.0.0.1:8081/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"mlx-community/Qwen3-0.6B-4bit","messages":[{"role":"user","content":"Explain MLX KV caching"}],"max_tokens":128}'
```

The response includes:

```json
{
  "_mlx_sentinel": {
    "kv": {
      "source": "mlx_lm.KVCache",
      "pages": 28,
      "cache_tokens": 128,
      "mean_norm": 1.2,
      "max_norm": 4.1
    },
    "decision": {"allowed": true, "score": 0.0, "action": "allow"}
  }
}
```

## Modes

```sh
MLX_SENTINEL_MODE=observe   # report only
MLX_SENTINEL_MODE=guard     # block critical anomalies; default
MLX_SENTINEL_MODE=enforce   # block all configured high-risk anomalies
```

`observe` is the safe rollout mode. Use held-out benign traffic and adversarial tests before enabling blocking.

Open `http://127.0.0.1:8081/` for the dashboard. It shows normal, medium, high, and critical alert counts, block counts, current mode, and recent events. The IPS inspects prompts before generation and KV statistics after generation. Critical prompt injection/jailbreak signals are blocked in `guard` mode; high and critical KV anomalies are blocked in `enforce` mode.

## Thomas AI integration

Thomas AI can consume the aggregate telemetry through its `/api/security/kv` endpoint. Set:

```sh
export MLX_SENTINEL_SECURITY_URL=http://127.0.0.1:8788/api/security/kv
```

Without that variable, MLX Sentinel performs its own local decision. The NVIDIA and Apple backends remain outside true KV analysis because hosted services do not expose their internal tensors.

## Project layout

```text
mlx_sentinel/
├── server.py       # MLX generation and OpenAI-compatible response
├── telemetry.py    # KV statistics and anomaly scoring
└── __init__.py
rust-guard/
├── src/lib.rs      # portable native Rust baseline guard
└── Cargo.toml
tests/
└── test_telemetry.py
```

## Limitations

`mlx_lm` exposes K/V tensors but not attention probability matrices, so `attention_entropy` is currently optional. The project analyzes real KV state, not a simulated proxy, but it does not claim visibility into hosted model internals.
