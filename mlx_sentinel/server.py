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
from .resources import ResourceGovernor
from .config import Settings
from .metrics import Metrics, RateLimiter
from .models import ModelRegistry

DASHBOARD = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>MLX Sentinel</title><style>body{font:15px system-ui;background:#0b1110;color:#eef5ef;max-width:1200px;margin:30px auto;padding:0 20px}h1{font-size:38px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card{background:#14201c;border:1px solid #355247;border-radius:12px;padding:18px;margin:12px 0}.normal{color:#77e0ad}.medium{color:#f4d36b}.high{color:#ffad5c}.critical{color:#ff7180}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:10px;border-bottom:1px solid #30433a;text-align:left;vertical-align:top}button{background:#233d32;color:#eef5ef;border:1px solid #58806b;border-radius:6px;padding:6px;margin:2px;cursor:pointer}pre{white-space:pre-wrap;background:#0b1511;border-radius:8px;padding:10px;color:#c8ded1}small{color:#9db0a6}.detail{display:none}.detail.open{display:table-row}.evidence{min-width:220px}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}table{font-size:12px}.hide-mobile{display:none}}</style></head><body><h1>MLX Sentinel</h1><p><small>True MLX KV-cache analysis, adaptive ML false-positive filtering, and response security monitoring</small></p><div id='cards' class='grid'></div><div class='card'><h2>High/critical review queue</h2><p><small>Expand an alert to inspect the evidence before labeling it. Labels train the local online model.</small></p><table><thead><tr><th>Time</th><th>Level</th><th>Score</th><th>Action</th><th class='evidence'>Evidence</th><th>Review</th></tr></thead><tbody id='events'></tbody></table></div><script>const esc=x=>String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));async function label(id,label){await fetch('/api/feedback',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_id:id,label})});refresh()}function toggle(id){document.getElementById('d-'+id).classList.toggle('open')}async function refresh(){let s=await (await fetch('/api/status')).json();let e=await (await fetch('/api/events')).json();let levels=['normal','medium','high','critical'];document.querySelector('#cards').innerHTML=levels.map(x=>`<div class='card'><div class='${x}'>${x.toUpperCase()}</div><h2>${s.levels[x]||0}</h2></div>`).join('')+`<div class='card'><small>Mode / blocked</small><h2>${s.mode} / ${s.blocked}</h2><small>ML labels: ${s.feedback_count}</small></div>`;let rows='';for(const x of e.events){let detail=JSON.stringify({event_id:x.event_id,score:x.score,ml_probability:x.ml_probability,features:x.features,reasons:x.reasons,feedback:x.feedback},null,2);rows+=`<tr><td>${new Date(x.timestamp*1000).toLocaleTimeString()}</td><td class='${x.level}'>${esc(x.level)}</td><td>${Number(x.score).toFixed(2)}</td><td>${esc(x.action)}</td><td>${x.reasons.map(esc).join(', ')}</td><td><button onclick="toggle('${x.event_id}')">Inspect</button>${x.features?`<button onclick="label('${x.event_id}','benign')">Benign</button><button onclick="label('${x.event_id}','malicious')">Malicious</button>`:''}</td></tr><tr id='d-${x.event_id}' class='detail'><td colspan='6'><pre>${esc(detail)}</pre><small>Interpretation: score combines hard safety rules, adaptive KV baselines, and (after feedback) the local ML probability. Prompt injection and invalid telemetry remain hard blocks.</small></td></tr>`}document.querySelector('#events').innerHTML=rows}refresh();setInterval(refresh,2000)</script></body></html>"""
# The dashboard is intentionally self-contained so it remains available in offline/local deployments.
DASHBOARD = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>MLX Sentinel</title><style>body{font:15px system-ui;background:#0b1110;color:#eef5ef;max-width:1200px;margin:30px auto;padding:0 20px}h1{font-size:38px}.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}.card{background:#14201c;border:1px solid #355247;border-radius:12px;padding:18px;margin:12px 0}.normal{color:#77e0ad}.medium{color:#f4d36b}.high{color:#ffad5c}.critical{color:#ff7180}table{width:100%;border-collapse:collapse;margin-top:20px}td,th{padding:10px;border-bottom:1px solid #30433a;text-align:left;vertical-align:top}button{background:#233d32;color:#eef5ef;border:1px solid #58806b;border-radius:6px;padding:6px;margin:2px;cursor:pointer}button:disabled{opacity:.65;cursor:default}pre{white-space:pre-wrap;background:#0b1511;border-radius:8px;padding:10px;color:#c8ded1}small{color:#9db0a6}.detail{display:none}.detail.open{display:table-row}.evidence{min-width:220px}.toast{position:fixed;right:20px;bottom:20px;background:#294b3d;border:1px solid #77e0ad;border-radius:8px;padding:12px;display:none}.toast.error{background:#5b2730;border-color:#ff7180}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}table{font-size:12px}}</style></head><body><h1>MLX Sentinel</h1><p><small>True MLX KV-cache analysis, adaptive ML false-positive filtering, and response security monitoring</small></p><div id='cards' class='grid'></div><div id='toast' class='toast'></div><div class='card'><h2>High/critical review queue</h2><p><small>Expand an alert to inspect the evidence before labeling it. Labels train the local online model.</small></p><table><thead><tr><th>Time</th><th>Level</th><th>Score</th><th>Action</th><th class='evidence'>Evidence</th><th>Review</th></tr></thead><tbody id='events'></tbody></table></div><script>const esc=x=>String(x??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));function toast(message,error=false){let t=document.getElementById('toast');t.textContent=message;t.className='toast'+(error?' error':'');t.style.display='block';setTimeout(()=>t.style.display='none',3000)}async function label(id,label){try{let response=await fetch('/api/feedback',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_id:id,label})});let result=await response.json();if(!response.ok)throw new Error(result.error||'feedback rejected');toast('Saved '+label+' review. ML labels: '+result.feedback_count);await refresh()}catch(error){toast(error.message,true)}}function toggle(id){document.getElementById('d-'+id).classList.toggle('open')}async function refresh(){let s=await (await fetch('/api/status')).json();let e=await (await fetch('/api/events')).json();let levels=['normal','medium','high','critical'];document.querySelector('#cards').innerHTML=levels.map(x=>`<div class='card'><div class='${x}'>${x.toUpperCase()}</div><h2>${s.levels[x]||0}</h2></div>`).join('')+`<div class='card'><small>Mode / blocked</small><h2>${s.mode} / ${s.blocked}</h2><small>ML labels: ${s.feedback_count}</small></div>`;let rows='';for(const x of e.events){let detail=JSON.stringify({event_id:x.event_id,score:x.score,ml_probability:x.ml_probability,features:x.features,reasons:x.reasons,feedback:x.feedback},null,2);let reviewed=x.feedback?`<span class='${x.feedback==='benign'?'normal':'critical'}'>Reviewed: ${esc(x.feedback)}</span>`:`<button onclick=\"label('${x.event_id}','benign')\">Benign</button><button onclick=\"label('${x.event_id}','malicious')\">Malicious</button>`;rows+=`<tr><td>${new Date(x.timestamp*1000).toLocaleTimeString()}</td><td class='${x.level}'>${esc(x.level)}</td><td>${Number(x.score).toFixed(2)}</td><td>${esc(x.action)}</td><td>${x.reasons.map(esc).join(', ')}</td><td><button onclick=\"toggle('${x.event_id}')\">Inspect</button>${x.features?reviewed:''}</td></tr><tr id='d-${x.event_id}' class='detail'><td colspan='6'><pre>${esc(detail)}</pre><small>Score combines hard safety rules, adaptive KV baselines, and the local ML probability. Prompt injection and invalid telemetry remain hard blocks.</small></td></tr>`}document.querySelector('#events').innerHTML=rows}refresh();setInterval(refresh,2000)</script></body></html>"""


class Engine:
    def __init__(self, settings: Settings) -> None:
        model = settings.model
        max_tokens = settings.max_tokens
        mode = settings.mode
        security_url = settings.security_url
        self.model_id = model
        self.max_tokens = max_tokens
        self.model, self.tokenizer = load(model)
        self.guard = Guard(mode, policy_path=settings.policy_path)
        self.resources = ResourceGovernor(max_load=float(os.environ["MLX_SENTINEL_MAX_LOAD"]) if os.environ.get("MLX_SENTINEL_MAX_LOAD") else None)
        self.security_url = security_url
        self.api_key = settings.api_key
        self.cors_origin = settings.cors_origin
        self.max_request_bytes = settings.max_request_bytes
        self.metrics = Metrics()
        self.rate_limiter = RateLimiter(settings.rate_limit, settings.rate_window)
        self.settings = settings
        self.models = ModelRegistry(model)
        self.lock = threading.Lock()
        self.admission = threading.BoundedSemaphore(1)

    def complete(self, messages: list[dict], max_tokens: int) -> tuple[str, KVStats, float]:
        normalized = [{"role": str(m.get("role", "user")), "content": str(m.get("content", ""))} for m in messages]
        try:
            prompt = self.tokenizer.apply_chat_template(normalized, tokenize=False, add_generation_prompt=True, chat_template_kwargs={"enable_thinking": False})
        except (AttributeError, TypeError, ValueError):
            prompt = "\n".join(f"{m['role']}: {m['content']}" for m in normalized) + "\nassistant:"
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
                cache_size = getattr(item, "size", getattr(item, "offset", 0))
                cache_size = cache_size() if callable(cache_size) else cache_size
                cache_tokens = max(cache_tokens, int(cache_size))
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
        self.engine.metrics.observe(status)
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def end_headers(self) -> None:
        if self.engine.cors_origin:
            self.send_header("access-control-allow-origin", self.engine.cors_origin)
            self.send_header("access-control-allow-headers", "authorization, content-type, x-api-key")
            self.send_header("access-control-allow-methods", "GET, POST, OPTIONS")
        super().end_headers()

    def route(self) -> str:
        return self.path.split("?", 1)[0]

    def authorized(self) -> bool:
        if not self.engine.api_key or not (self.route().startswith("/api/") or self.route().startswith("/v1/")):
            return True
        provided = self.headers.get("x-api-key", "")
        authorization = self.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        return provided == self.engine.api_key

    def rate_limited(self) -> bool:
        if not self.route().startswith(("/api/", "/v1/")):
            return False
        key = self.headers.get("x-api-key") or self.client_address[0]
        return not self.engine.rate_limiter.allow(key)

    def access_allowed(self) -> bool:
        if not self.authorized():
            self.send_json(401, {"error": {"code": "unauthorized", "message": "valid API key required"}})
            return False
        if self.rate_limited():
            self.send_json(429, {"error": {"code": "rate_limited", "message": "request rate limit exceeded"}})
            return False
        return True

    def read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError as error:
            raise ValueError("invalid content-length") from error
        if length < 0 or length > self.engine.max_request_bytes:
            raise ValueError("request body is too large")
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as error:
            raise ValueError("invalid JSON body") from error
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def validate_completion(self, body: dict) -> tuple[list[dict], int]:
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty array")
        if any(not isinstance(message, dict) for message in messages):
            raise ValueError("each message must be an object")
        try:
            max_tokens = int(body.get("max_tokens", self.engine.max_tokens))
        except (TypeError, ValueError) as error:
            raise ValueError("max_tokens must be an integer") from error
        if max_tokens < 1 or max_tokens > self.engine.max_tokens:
            raise ValueError(f"max_tokens must be between 1 and {self.engine.max_tokens}")
        return messages, max_tokens

    def send_stream(self, body: dict) -> None:
        encoded = [
            {"id": "mlx-sentinel-chat", "object": "chat.completion.chunk", "model": self.engine.model_id, "choices": [{"index": 0, "delta": {"role": "assistant", "content": body["text"]}, "finish_reason": None}]},
            {"id": "mlx-sentinel-chat", "object": "chat.completion.chunk", "model": self.engine.model_id, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        ]
        payload = "".join(f"data: {json.dumps(item)}\n\n" for item in encoded) + "data: [DONE]\n\n"
        raw = payload.encode()
        self.engine.metrics.observe(200)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if not self.access_allowed():
            return
        path = self.route()
        if path == "/":
            encoded = DASHBOARD.encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        elif path == "/health":
            self.send_json(200, {"ok": True, "service": "MLX Sentinel", "model": self.engine.model_id})
        elif path == "/api/status":
            self.send_json(200, {"service": "MLX Sentinel", "model": self.engine.model_id, "resources": self.engine.resources.check(), **self.engine.guard.status()})
        elif path == "/api/resources":
            self.send_json(200, self.engine.resources.check(force=True))
        elif path == "/api/events":
            self.send_json(200, {"events": self.engine.guard.recent_events()})
        elif path == "/api/events/export":
            self.send_json(200, {"format": "json", "events": self.engine.guard.recent_events()})
        elif path == "/api/models":
            self.send_json(200, self.engine.models.as_dict())
        elif path == "/api/metrics":
            encoded = self.engine.metrics.prometheus().encode()
            self.send_response(200)
            self.send_header("content-type", "text/plain; version=0.0.4")
            self.send_header("content-length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        elif path == "/api/config":
            self.send_json(200, {"model": self.engine.model_id, "mode": self.engine.settings.mode, "max_tokens": self.engine.max_tokens, "rate_limit": self.engine.settings.rate_limit, "rate_window": self.engine.settings.rate_window, "authentication": bool(self.engine.api_key), "cors": bool(self.engine.cors_origin), "policy_path": bool(self.engine.settings.policy_path), "policy": self.engine.guard.policy.as_dict()})
        elif path == "/v1/models":
            self.send_json(200, {"object": "list", "data": [{"id": self.engine.model_id, "object": "model", "owned_by": "mlx-sentinel"}]})
        else:
            self.send_json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:  # noqa: N802
        if self.engine.cors_origin:
            self.send_response(204)
            self.end_headers()
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.access_allowed():
            return
        path = self.route()
        if path == "/api/feedback":
            try:
                body = self.read_json_body()
                self.send_json(200, self.engine.guard.feedback(str(body["event_id"]), str(body["label"])))
            except (KeyError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/tool/check":
            try:
                body = self.read_json_body()
                decision = self.engine.guard.inspect_tool(str(body.get("name", "unknown")), body.get("arguments", {}))
                self.send_json(200, {"decision": decision.__dict__})
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/agent/step":
            try:
                body = self.read_json_body()
                decision = self.engine.guard.inspect_agent_step(str(body.get("name", "unknown")), body.get("arguments", {}), int(body.get("step", 1)))
                self.send_json(200, {"decision": decision.__dict__})
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/code/check":
            try:
                body = self.read_json_body()
                imports = body.get("allowed_imports")
                if imports is not None and (not isinstance(imports, list) or any(not isinstance(item, str) for item in imports)):
                    raise ValueError("allowed_imports must be an array of strings")
                decision = self.engine.guard.inspect_code(str(body.get("source", "")), set(imports) if imports is not None else None)
                self.send_json(200, {"decision": decision.__dict__, "execution": "not performed"})
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/tool/output/check":
            try:
                body = self.read_json_body()
                decision = self.engine.guard.inspect_tool_output(str(body.get("text", "")))
                self.send_json(200, {"decision": decision.__dict__})
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/process/check":
            try:
                body = self.read_json_body()
                decision = self.engine.guard.inspect_process(str(body.get("executable", "unknown")), str(body.get("command_line", "")))
                self.send_json(200, {"decision": decision.__dict__})
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path == "/api/replay":
            try:
                body = self.read_json_body()
                self.send_json(200, self.engine.guard.replay(body.get("events", []), str(body.get("mode", "shadow"))))
            except (TypeError, ValueError) as error:
                self.send_json(400, {"error": str(error)})
            return
        if path != "/v1/chat/completions":
            self.send_json(404, {"error": "not found"})
            return
        try:
            body = self.read_json_body()
            messages, requested_max_tokens = self.validate_completion(body)
            prompt = "\n".join(str(message.get("content", "")) for message in messages)
            preflight = self.engine.guard.inspect_prompt(prompt)
            if not preflight.allowed:
                self.send_json(403, {"error": {"message": "request blocked by MLX Sentinel security policy", "security": preflight.__dict__}})
                return
            resources = self.engine.resources.check()
            if not resources["allowed"]:
                self.send_json(429, {"error": {"message": "MLX Sentinel paused inference to protect the Mac", "resources": resources}})
                return
            if not self.engine.admission.acquire(blocking=False):
                self.send_json(429, {"error": {"message": "MLX Sentinel is at its safe inference concurrency limit", "resources": self.engine.resources.check()}})
                return
            try:
                text, stats, latency = self.engine.complete(messages, requested_max_tokens)
            finally:
                self.engine.admission.release()
            local = self.engine.guard.inspect(stats, {"prompt_chars": len(prompt), "output_chars": len(text), "latency_ms": latency})
            output = self.engine.guard.inspect_output(text)
            external = self.engine.external_decision(stats)
            external_decision = external.get("decision", {}) if external else {}
            allowed = local.allowed and output.allowed and external_decision.get("allowed", True)
            if not allowed:
                self.send_json(403, {"error": {"message": "response blocked by MLX Sentinel security policy", "security": {"local": local.__dict__, "output": output.__dict__, "external": external}}, "_mlx_sentinel": {"kv": stats.__dict__, "latency_ms": latency}})
                return
            response = {"id": "mlx-sentinel-chat", "object": "chat.completion", "model": self.engine.model_id, "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}], "_mlx_sentinel": {"kv": stats.__dict__, "preflight": preflight.__dict__, "decision": local.__dict__, "output": output.__dict__, "external_security": external, "latency_ms": latency}}
            if body.get("stream") is True:
                self.send_stream({"text": text})
            else:
                self.send_json(200, response)
        except Exception as error:
            self.send_json(500, {"error": {"message": str(error)}})

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Local MLX inference security gateway")
    settings = Settings.from_env()
    parser.add_argument("--model", default=settings.model)
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--max-tokens", type=int, default=settings.max_tokens)
    parser.add_argument("--mode", choices=["observe", "shadow", "guard", "enforce"], default=settings.mode)
    parser.add_argument("--security-url", default=settings.security_url)
    args = parser.parse_args()
    settings = Settings(settings.model, args.host, args.port, args.max_tokens, args.mode, args.security_url, settings.policy_path, settings.api_key, settings.rate_limit, settings.rate_window, settings.cors_origin, settings.max_request_bytes)
    Handler.engine = Engine(settings)
    print(f"MLX Sentinel listening on http://{args.host}:{args.port}", flush=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
