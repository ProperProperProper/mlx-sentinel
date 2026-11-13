# macOS launchd deployment

The reference Mac runs MLX Sentinel as `com.mlx-sentinel` with `KeepAlive` enabled.

The local deployment uses:

```text
/Users/local.local/Projects/TradingSystem/scripts/start_mlx_sentinel.sh
/Users/local.local/Library/LaunchAgents/com.mlx-sentinel.plist
```

For another Mac, copy the templates, replace the repository and Python paths, then load the agent:

```sh
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.mlx-sentinel.plist"
launchctl kickstart -k gui/$(id -u)/com.mlx-sentinel
```

The service binds to loopback only, uses `guard` mode by default, and forwards aggregate KV telemetry to `MLX_SENTINEL_SECURITY_URL` when configured.
