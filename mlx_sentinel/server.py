from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen

import mlx.core as mx
from mlx_lm import load
from mlx_lm.generate import generate_step
from mlx_lm.models.cache import make_prompt_cache

from .telemetry import Guard, KVStats

DASHBOARD = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>MLX Sentinel</title><style>body{font:15px system-ui;background:#0b1110;color:#eef5ef;max-width:1200px;margin:30px auto;padding:0 20px}h1{font-size:38px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card{background:#14201c;border:1px solid #355247;border-radius:12px;padding:18px;margin:12px 0}.normal{color:#77e0ad}.medium{color:#f4d36b}.high{color:#ffad5c}.critical{color:#ff7180}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:10px;border-bottom:1px solid #30433a;text-align:left;vertical-align:top}button{background:#233d32;color:#eef5ef;border:1px solid #58806b;border-radius:6px;padding:6px;margin:2px;cursor:pointer}pre{white-space:pre-wrap;background:#0b1511;border-radius:8px;padding:10px;color:#c8ded1}small{color:#9db0a6}.detail{display:none}.detail.open{display:table-row}.evidence{min-width:220px}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}table{font-size:12px}.hide-mobile{display:none}}</style></head><body><h1>MLX Sentinel</h1><p><small>True MLX KV-cache analysis, adaptive ML false-positive filtering, and response intrusion prevention</small></p><div id='cards' class='grid'></div><div class='card'><h2>High/critical review queue</h2><p><small>Expand an alert to inspect the evidence before labeling it. Labels train the local online model.</small></p><table><thead><tr><th>Time</th><th>Level</th><th>Score</th><th>Action</th><th class='evidence'>Evidence</th><th>Review</th></tr></thead><tbody id='events'></tbody></table></div><script>const esc=x=>String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));async function label(id,label){await fetch('/api/feedback',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_id:id,label})});refresh()}function toggle(id){document.getElementById('d-'+id).classList.toggle('open')}async function refresh(){let s=await (await fetch('/api/status')).json();let e=await (await fetch('/api/events')).json();let levels=['normal','medium','high','critical'];document.querySelector('#cards').innerHTML=levels.map(x=>`<div class='card'><div class='${x}'>${x.toUpperCase()}</div><h2>${s.levels[x]||0}</h2></div>`).join('')+`<div class='card'><small>Mode / blocked</small><h2>${s.mode} / ${s.blocked}</h2><small>ML labels: ${s.feedback_count}</small></div>`;let rows='';for(const x of e.events){let detail=JSON.stringify({event_id:x.event_id,score:x.score,ml_probability:x.ml_probability,features:x.features,reasons:x.reasons,feedback:x.feedback},null,2);rows+=`<tr><td>${new Date(x.timestamp*1000).toLocaleTimeString()}</td><td class='${x.level}'>${esc(x.level)}</td><td>${Number(x.score).toFixed(2)}</td><td>${esc(x.action)}</td><td>${x.reasons.map(esc).join(', ')}</td><td><button onclick="toggle('${x.event_id}')">Inspect</button>${x.features?`<button onclick="label('${x.event_id}','benign')">Benign</button><button onclick="label('${x.event_id}','malicious')">Malicious</button>`:''}</td></tr><tr id='d-${x.event_id}' class='detail'><td colspan='6'><pre>${esc(detail)}</pre><small>Interpretation: score combines hard safety rules, adaptive KV baselines, and (after feedback) the local ML probability. Prompt injection and invalid telemetry remain hard blocks.</small></td></tr>`}document.querySelector('#events').innerHTML=rows}refresh();setInterval(refresh,2000)</script></body></html>"""


class Engine:
    def __init__(self, model: str, max_tokens: int, mode: str, security_url: str | None) -> None:
        self.model_id = model
        self.max_tokens = max_tokens
        self.model, self.tokenizer = load(model)
        self.guard = Guard(mode)
        self.security_url = security_url
        self.lock = threading.Lock()

    def complete(self, messages: list[dict], max_tokens: int) -> tuple[str, KVStats, float]:
        prompt = "\n".join(f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages)
        tokens = self.tokenizer.encode(prompt, add_special_tokens=True)
        cache = make_prompt_cache(self.model)
        generated: list[int] = []
        started = time.perf_counter()
        with self.lock:
            for token, _logprobs in generate_step(mx.array(tokens), self.model, max_tokens=min(max_tokens, self.max_tokens), prompt_cache=cache):
                generated.append(int(token))
                if token in getattr(self.tokenizer, "eos_token_ids", set()):
                    break
            means: list[float] = []
            maxima: list[float] = []
            cache_tokens = 0
            for item in cache:
                cache_tokens = max(cache_tokens, len(item))
                state = item.state
                if not isinstance(state, (tuple, list)) or len(state) < 2:
                    continue
                keys, values = state[:2]
                mx.eval(keys, values)
                means.extend([float(mx.mean(mx.abs(keys)).item()), float(mx.mean(mx.abs(values)).item())])
                maxima.extend([float(mx.max(mx.abs(keys)).item()), float(mx.max(mx.abs(values)).item())])
        stats = KVStats(self.model_id, float(len(cache)), float(cache_tokens), sum(means) / len(means) if means else 0.0, max(maxima) if maxima else 0.0)
        return self.tokenizer.decode(generated), stats, round((time.perf_counter() - started) * 1000, 1)

    def external_decision(self, stats: KVStats) -> dict | None:
        if not self.security_url:
            return None
        try:
            request = Request(self.security_url, data=json.dumps(stats.__dict__).encode(), headers={"content-type": "application/json"})
            with urlopen(request, timeout=5) as response:
                return json.loads(response.read())
        except Exception as error:
            return {"error": str(error)}


class Handler(BaseHTTPRequestHandler):
    engine: Engine

    def send_json(self, status: int, body: dict) -> None:
        encoded = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/":
            encoded = DASHBOARD.encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        elif self.path == "/health":
            self.send_json(200, {"ok": True, "service": "MLX Sentinel", "model": self.engine.model_id})
        elif self.path == "/api/status":
            self.send_json(200, {"service": "MLX Sentinel", "model": self.engine.model_id, **self.engine.guard.status()})
        elif self.path == "/api/events":
            self.send_json(200, {"events": self.engine.guard.recent_events()})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/feedback":
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
                self.send_json(200, self.engine.guard.feedback(str(body["event_id"]), str(body["label"])))
            except (KeyError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path != "/v1/chat/completions":
            self.send_json(404, {"error": "not found"})
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
            prompt = "\n".join(str(message.get("content", "")) for message in body.get("messages", []))
            preflight = self.engine.guard.inspect_prompt(prompt)
            if not preflight.allowed:
                self.send_json(403, {"error": {"message": "request blocked by MLX Sentinel IPS", "security": preflight.__dict__}})
                return
            text, stats, latency = self.engine.complete(body.get("messages", []), int(body.get("max_tokens", self.engine.max_tokens)))
            local = self.engine.guard.inspect(stats)
            external = self.engine.external_decision(stats)
            external_decision = external.get("decision", {}) if external else {}
            allowed = local.allowed and external_decision.get("allowed", True)
            if not allowed:
                self.send_json(403, {"error": {"message": "response blocked by MLX Sentinel IPS", "security": {"local": local.__dict__, "external": external}}, "_mlx_sentinel": {"kv": stats.__dict__, "latency_ms": latency}})
                return
            self.send_json(200, {"id": "mlx-sentinel-chat", "object": "chat.completion", "model": self.engine.model_id, "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}], "_mlx_sentinel": {"kv": stats.__dict__, "preflight": preflight.__dict__, "decision": local.__dict__, "external_security": external, "latency_ms": latency}})
        except Exception as error:
            self.send_json(500, {"error": {"message": str(error)}})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=os.environ.get("MLX_SENTINEL_MODEL", "mlx-community/Qwen3-0.6B-4bit"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--mode", choices=["observe", "guard", "enforce"], default=os.environ.get("MLX_SENTINEL_MODE", "guard"))
    parser.add_argument("--security-url", default=os.environ.get("MLX_SENTINEL_SECURITY_URL"))
    args = parser.parse_args()
    Handler.engine = Engine(args.model, args.max_tokens, args.mode, args.security_url)
    print(f"MLX Sentinel listening on http://{args.host}:{args.port}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
