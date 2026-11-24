# NetFlow

**Visual multi-interface per-app & VPN traffic router for Windows 10/11 (x64).**

NetFlow lets you visually wire individual Windows applications and VPN tunnels across multiple simultaneous network interfaces (e.g., **Wi-Fi + Ethernet** at the same time) using a drag-and-drop node workflow canvas — powered by a Rust core and a bundled `sing-box` + `Wintun` L3 TUN engine.

---

## Features

- **Visual Node Canvas** — Drag interfaces, VPN tunnels, and application groups onto an interactive canvas and wire them together (`Interface → Apps`, `Interface → VPN → Apps`, or chained VPNs).
- **Simultaneous Multi-Interface Routing** — Route `msedge.exe` over Wi-Fi, `chrome.exe` through a VPN over Ethernet, and everything else through your Default node — all at the same time.
- **First-Class VPN Support (Karing & OpenVPN)** — Detects user-launched **Karing** (local proxy / TUN) and **OpenVPN** (OpenVPN GUI & OpenVPN Connect v3), automatically handling loop-free upstream binding, FakeIP DNS bypass, and interface metric prioritization.
- **Generic Third-Party VPNs as Interfaces** — Other installed VPN adapters (e.g., WireGuard, Tailscale, Cloudflare WARP) appear directly in the Interfaces list so you can wire apps to them freely.
- **Saved Workflows & Hot-Switch** — Save multiple routing setups and switch between them from the top bar or the Windows System Tray.
- **Live Traffic Log** — Inspect real-time per-app connections, matched rules, target destinations, and active outbound interfaces.
- **Zero-Leak & Atomic Crash Recovery** — Blocks IPv6 leaks on the TUN interface, runs `sing-box` inside a Windows Job Object (`KILL_ON_JOB_CLOSE`), and persists a recovery snapshot (`%APPDATA%\NetFlow\recovery.json`) to restore system proxy, interface metrics, and routing tables cleanly on Stop or after an unexpected crash/reboot.

---

## Download & Installation

1. Go to the [**Releases**](../../releases) page.
2. Download the latest Windows installer:
   - **`NetFlow_x.x.x_x64-setup.exe`** (NSIS installer — recommended)
   - **`NetFlow_x.x.x_x64_en-US.msi`** (MSI installer)
3. Run the installer and launch **NetFlow**.

> **Requirements:** Windows 10 or Windows 11 (64-bit) and **Administrator privileges** (NetFlow prompts for UAC elevation on startup because creating the `NetFlow-TUN` adapter and managing Windows routing tables requires elevation).

---

## Quick Start

1. **Add Interfaces** — Click or drag your active physical interfaces (e.g., `Wi-Fi`, `Ethernet`) from the left sidebar onto the canvas.
2. **Pick a Default Node** — Click **Set as Default** on the Interface or VPN node that should carry traffic for all apps not explicitly wired to another path.
3. **Add Apps** — Drop an **Application Group** node onto the canvas, click **+ Add App**, and select running processes or browse for `.exe` files.
4. **Wire Your Flow** — Connect handles from left to right:
   - `Interface → Apps` for direct per-app routing
   - `Interface → VPN → Apps` to route specific apps through **Karing** or **OpenVPN** over a chosen physical interface
5. **Apply** — Click **Apply** in the top bar. Toggle **Live Traffic** to verify each app's active route, and click **Stop** at any time to restore normal Windows networking.

> **OpenVPN Tip:** Make sure OpenVPN is already connected before clicking **Apply**. If your `.ovpn` profile uses a custom remote server or DCO adapter, you can optionally specify the **Server IP** in the VPN node's properties panel.

---

## Building from Source

### Prerequisites

- **Windows 10/11 (x64)**
- [**Node.js 20+**](https://nodejs.org/)
- [**Rust (stable)**](https://rustup.rs/) with **Visual Studio Build Tools (MSVC C++ workload)**
- [**WebView2 Runtime**](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (pre-installed on Windows 11)

### Setup & Run

```powershell
# 1. Install frontend dependencies
npm install

# 2. Download bundled sing-box (v1.14.4) and wintun.dll (0.14.1)
powershell -ExecutionPolicy Bypass -File scripts/fetch-sidecars.ps1

# 3. Run in development mode (launches an elevated Tauri window)
npm run tauri dev
```

### Build Windows Installers (`.exe` & `.msi`)

```powershell
npm run tauri build
```

Generated installers will be placed in:
- `target/release/bundle/nsis/NetFlow_<version>_x64-setup.exe`
- `target/release/bundle/msi/NetFlow_<version>_x64_en-US.msi`

### Run Tests

```powershell
# Rust core + Tauri backend tests
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Frontend unit & component tests
npm test -- --run
```

---

## Architecture

| Path | Description |
| --- | --- |
| `crates/netflow-core/` | Tauri-agnostic Rust core: graph validation, `sing-box` JSON compiler, Windows IP Helper / route / metric management, VPN adapters, traffic stream, and crash recovery. |
| `src-tauri/` | Tauri v2 desktop shell, elevated UAC manifest, IPC commands, and System Tray integration. |
| `src/` | React 19 + TypeScript + Tailwind CSS v4 + React Flow + Zustand frontend UI. |
| `scripts/fetch-sidecars.ps1` | Idempotent downloader for `sing-box` and `wintun.dll` (kept out of Git). |

---

## Credits

- [sing-box](https://github.com/SagerNet/sing-box) — Universal L3/L4 routing engine
- [Wintun](https://www.wintun.net/) — Signed Layer 3 TUN driver for Windows
- [Tauri v2](https://v2.tauri.app/) — Rust + WebView desktop framework
- [React Flow](https://reactflow.dev/) — Node-based workflow canvas

## License

MIT — see [LICENSE](LICENSE) for details.
