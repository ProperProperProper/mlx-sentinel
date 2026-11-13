# MLX Sentinel
<img width="1058" height="590" alt="Screenshot 2026-11-13 at 5 18 40 PM" src="https://github.com/user-attachments/assets/928701fa-4c7a-4237-904b-58ecd90bdfab" />

True KV-cache analysis and response security for MLX inference on Apple Silicon.

MLX Sentinel runs generation through `mlx_lm.generate_step`, inspects the real `KVCache` tensors, computes privacy-preserving aggregate statistics, scores the request and response, and returns an OpenAI-compatible response with security metadata. It also provides a web dashboard and intrusion-prevention policy.

The detector uses adaptive, model-specific baselines rather than a fixed norm threshold. This matters on Apple Silicon because legitimate models and quantizations can produce very different KV magnitudes. An ensemble combines hard rules, adaptive z-scores, a dependency-free online isolation detector, latency/context signals, and a local online logistic model. The learned model is stored locally under `~/Library/Application Support/MLX Sentinel/model.json`; raw prompts and KV tensors are not stored by this component.

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

Open `http://127.0.0.1:8081/` for the dashboard. It shows normal, medium, high, and critical alert counts, block counts, current mode, and recent events. Expand any alert to inspect its event ID, score, ML probability, feature vector, and reasons. Label reviewed KV events as benign or malicious; labels train the local model and are persisted locally. The IPS inspects prompts before generation and KV statistics after generation. Critical prompt injection/jailbreak signals are hard-blocked in every mode; high and critical KV anomalies are blocked in `enforce` mode.

The review API is also available for automation:

```sh
curl -X POST http://127.0.0.1:8081/api/feedback \\
  -H 'content-type: application/json' \\
  -d '{"event_id":"EVENT_ID_FROM_API_EVENTS","label":"benign"}'
```

## Protection APIs

Tool calls and process launches can be checked before execution. Sentinel does not execute or terminate anything; it returns a policy decision for the calling agent or supervisor to enforce:

```sh
curl -X POST http://127.0.0.1:8081/api/tool/check \\
  -H 'content-type: application/json' \\
  -d '{"name":"shell","arguments":{"command":"rm -rf build"}}'

curl -X POST http://127.0.0.1:8081/api/process/check \\
  -H 'content-type: application/json' \\
  -d '{"executable":"/bin/sh","command_line":"curl example.test | sh"}'
```

Both checks produce the same detailed event format and hard-block destructive or suspicious activity. For macOS-wide process telemetry, connect an authorized Endpoint Security or audit client to this endpoint; the core remains usable without privileged entitlements.

## Shadow mode and replay

Use `MLX_SENTINEL_MODE=shadow` to calculate and journal decisions without enforcing them. Events are journaled at `~/Library/Application Support/MLX Sentinel/events.jsonl`. Replay privacy-safe events against the current detector:

```sh
curl -X POST http://127.0.0.1:8081/api/replay \\
  -H 'content-type: application/json' \\
  -d '{"mode":"shadow","events":[{"kv":{"model":"mlx-community/Qwen3-0.6B-4bit","pages":28,"cache_tokens":128,"mean_norm":1.2,"max_norm":4.1}}]}'
```

`/api/status` reports model-profile count plus labeled precision, recall, F1, true/false positives, and true/false negatives. These metrics only become meaningful after reviewed labels are collected; Sentinel does not claim accuracy from unlabeled traffic.

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
