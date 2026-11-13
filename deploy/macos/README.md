# macOS launchd deployment

The reference Mac runs MLX Sentinel as `com.mlx-sentinel` with `KeepAlive` enabled.

The deployment uses:

```text
path/to/mlx-sentinel/scripts/start_mlx_sentinel.sh
~/Library/LaunchAgents/com.mlx-sentinel.plist
```

Copy the templates, replace the repository and Python paths for the target Mac, then load the agent:

```sh
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.mlx-sentinel.plist"
launchctl kickstart -k gui/$(id -u)/com.mlx-sentinel
```

The service binds to loopback only, uses `guard` mode by default, and forwards aggregate KV telemetry to `MLX_SENTINEL_SECURITY_URL` when configured.
