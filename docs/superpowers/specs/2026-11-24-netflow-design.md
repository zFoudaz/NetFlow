# NetFlow — Design Document

**Date:** 2026-11-24  
**Platform:** Windows 10 / 11 (x64)  
**Stack:** Tauri v2 (Rust backend + React/TypeScript + React Flow `@xyflow/react`) + bundled `sing-box` & `Wintun`

---

## 1. Intent & Why

NetFlow is a Windows desktop application that gives the user visual, drag-and-drop control over how Windows network traffic flows across multiple simultaneous physical network interfaces (e.g., Wi-Fi, LAN 1, LAN 2), multiple externally-launched VPN clients, and individual Windows applications (e.g., `chrome.exe`).

**Core real-world problem:**
- The user wants different Windows applications to use different physical network interfaces at the same time.
- Some applications go directly out of a specific physical interface (`Interface -> Apps`), while others pass through a specific VPN bound to a specific physical interface (`Interface -> VPN -> Apps`).
- One critical real-world use case is **Karing's ISP quota-conversion / SNI tunneling**: traffic must be captured at the L3 TUN level with zero TCP, UDP/QUIC, IPv6, or DNS/SNI leaks; Windows System Proxy alone fails because apps and UDP/QUIC bypass it.
- The user wants NetFlow to be **general-purpose** across browsers, downloads, games, voice calls (full TCP + UDP support across interfaces and all 3 VPNs).
- The user prefers to **launch and manage their VPN apps themselves** (picking servers/profiles inside Karing, Cloudflare WARP, and OpenVPN) rather than importing raw configs into NetFlow.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
1. **Visual Node-Based Workflow Canvas:** Left sidebar listing detected physical Interfaces and the 3 supported VPNs; main drag-and-drop canvas where users wire `Interface -> Connected Apps` or `Interface -> VPN -> Connected Apps` (matching the user's sketch).
2. **Transparent General-Purpose Per-App L3 Routing:** Capture 100% of TCP, UDP/QUIC, and DNS traffic per Windows executable (`chrome.exe`, games, voice apps, etc.) at the TUN driver level with zero app proxy configuration.
3. **User-Assignable Default Target (Catch-All):** Allow the user to mark any wired **Interface** or **VPN** node on the canvas as the **Default** route for all unlisted Windows apps (e.g., route the whole PC through Karing except one app on LAN). If none is marked, unlisted apps use Windows' primary physical interface.
4. **Multi-Interface, Multi-VPN Coexistence & VPN Chaining (Max 1 per Provider in v1):** Support running up to one **Karing**, one **Cloudflare WARP**, and one **OpenVPN** tunnel simultaneously — either in parallel on different interfaces OR chained sequentially (`Interface -> VPN 1 -> VPN 2 -> Apps`) — with each outer VPN bound to its upstream Interface or upstream VPN *(User decision)*.
5. **Named Saved Workflows & Anytime Switching:** Users can save multiple named workflows (e.g., *Gaming*, *Work*, *Quota Saver*), manage them (create, save, rename, duplicate, delete), and switch between them at any time — including hot-switching while routing is already active *(User decision)*.
6. **Safe Lifecycle & Route Restoration:** Activating or switching a workflow must never leave Windows routes or System Proxy settings broken on stop, app exit, or crash.
7. **Live Verification & Tray** *(Agent call)*: Include a collapsible Live Traffic Log drawer (via `sing-box` local Clash API) to verify zero leaks, and support minimize-to-system-tray while active.

### Non-Goals (v1)
- **Not a VPN client replacement:** NetFlow does not replace Karing, WARP, or OpenVPN UIs or manage VPN subscriptions/configs directly.
- **Not universal VPN support in v1:** Arbitrary commercial VPN apps (NordVPN, ExpressVPN, Cisco AnyConnect, FortiClient, etc.) are out of scope for v1.
- **No multiple instances of the same VPN provider in v1:** At most 1 Karing, 1 WARP, and 1 OpenVPN node on the canvas simultaneously *(User decision)*.
- **No Windows login auto-start in v1** *(User decision — deferred to v2)*: The user launches NetFlow and clicks Start manually in v1; the Rust core will be cleanly decoupled from Tauri UI commands so adding Task Scheduler / Windows Service auto-start in v2 requires no rewrite.
- **Windows 10/11 x64 only:** macOS and Linux are out of scope.

### Anti-Goals (Failure even if technically running)
1. **Zero silent leaks for VPN-assigned or interface-assigned apps:** Neither UDP/QUIC, nor IPv6, nor DNS/SNI, nor Windows System Proxy loopback, nor a mid-session VPN/interface disconnect may silently fall back to another interface or direct ISP internet.
2. **Never leave Windows networking broken:** Stopping NetFlow or crashing must always destroy `NetFlow-TUN` and restore all neutralized VPN routes and Windows System Proxy settings (with disk-persisted crash recovery on next launch).
3. **No Windows Test Signing / Secure Boot disabling:** Must run on standard Windows 10/11 with Microsoft-signed `wintun.dll` only.

---

## 3. Constraints

- **Operating System:** Windows 10 / 11 (x64).
- **Administrator Privileges:** NetFlow runs elevated (`requireAdministrator` manifest) because creating `Wintun` adapters and modifying Windows routes/interface metrics require Admin rights.
- **User Launches VPNs Externally:** Karing, WARP, and OpenVPN are installed and launched by the user; NetFlow discovers them dynamically (running processes, listening ports, virtual network adapters, optional user overrides).
- **Dev Environment Note:** The target dev machine currently has Node.js, npm, and Git installed; the Rust toolchain (`rustup` + MSVC C++ Build Tools) must be installed as a Tauri prerequisite before implementation.

---

## 4. Approaches Considered & Selection

### Approach 1: Unified `sing-box` + `Wintun` Master Router *(Selected & Spike-Validated)*
- NetFlow bundles `sing-box` (Windows amd64) and Microsoft-signed `wintun.dll` as local Tauri sidecar/resources.
- `sing-box` runs a single master L3 virtual adapter (`NetFlow-TUN`) capturing system traffic and routing by `process_name`.
- Outbound physical interface binding uses `sing-box` `direct` outbounds with `bind_interface` (Win32 `IP_UNICAST_IF`), bypassing conflicting routing tables.
- VPN outer tunnel traffic is bound to the wired upstream physical Interface via `process_name` rules (and `/32` server host-route pinning for OpenVPN DCO compatibility).
- **Trade-offs:** Bundles `sing-box.exe` + `wintun.dll` (~30 MB); requires Administrator elevation; relies on per-VPN adapter handlers for Karing, WARP, and OpenVPN.

### Approach 2: Pure Packet Interception with `WinDivert` *(Rejected)*
- Custom packet-level NAT/router built over signed `WinDivert`.
- **Why rejected:** Implementing reliable cross-interface TCP/UDP/MTU/ARP/DNS NAT and race-free PID-to-packet attribution from scratch is fragile and expensive to maintain, while still colliding with VPN routes and firewalls.

### Approach 3: Custom Windows WFP Kernel Callout Driver *(Rejected)*
- Native C/C++ `ALE_CONNECT_REDIRECT` kernel driver (Proxifier / Mullvad style).
- **Why rejected:** Requires an EV Code Signing Certificate + WHQL attestation (~$300–500/yr) or disabling Secure Boot/Test Mode, carries BSOD risk, and dramatically increases engineering cost.

### Desktop UI Stack *(Selected by User)*
- **Tauri v2 (Rust backend + React/TypeScript + React Flow `@xyflow/react`)** chosen over Electron for minimal RAM/disk footprint and direct Rust access to Windows networking APIs.

---

## 5. Empirical Spike Findings (Validated on Target Machine)

A throwaway spike was run live on the user's Windows machine with **Wi-Fi + Karing** active and confirmed the core mechanics:
1. **Interface Bypass Works (`IP_UNICAST_IF`):** `sing-box` `direct` with `bind_interface: "Wi-Fi"` returned the real ISP Wi-Fi IP (`217.54.67.1`) even while `Karing TUN Network Adapter` was active.
2. **Karing Route Neutralization Works Cleanly:** Karing TUN installs ~30 split routes (`NextHop = 10.20.0.2`). Replacing them temporarily with a single metric-500 `0.0.0.0/0` route caused **zero** fight-back from Karing (`0` re-added routes), and restoring all 30 routes on exit worked cleanly.
3. **Simultaneous Zero-Proxy Per-App TUN Splitting Works:** Under `NetFlow-TUN`, `curl-wifi.exe` (zero proxy flags) exited directly via Wi-Fi (`217.54.67.1`) while `curl-karing-socks.exe` (zero proxy flags) was captured at L3 TUN level and forwarded into Karing's local port `127.0.0.1:3067`, exiting with Karing's VPN IP (`104.28.197.9`).
4. **VPN Process Binding Works:** `NetFlow-TUN` captured `karingService.exe`'s own encrypted tunnel connections and routed them out `wifi-direct`, proving `Interface -> Karing` binding works for any chosen physical interface.
5. **Karing Connector Selection:** Routing `NetFlow-TUN -> Karing TUN Network Adapter` caused Karing to treat `sing-box.exe` traffic as direct, whereas `NetFlow-TUN -> Karing local Mixed/SOCKS5 port (127.0.0.1:3067)` worked immediately at L3 TUN level (TCP + UDP) with no manual Karing setting changes.
6. **DNS Attribution Discovery:** Windows resolves app DNS through shared `svchost.exe`, so per-process DNS rules alone miss app DNS lookups. NetFlow uses **FakeIP + protocol/SNI sniffing** so VPN-assigned apps pass the real domain/SNI without ISP DNS leaks.
7. **NetFlow-TUN Route Priority Verification:** After starting `sing-box`, NetFlow must verify `NetFlow-TUN` wins default route lookup (enforcing `InterfaceMetric = 1` + `/1` routes if Windows route priority favors a physical adapter).

---

## 6. Architecture & Component Design

### 6.1 Module Separation (v2 Auto-Start Ready)

The Rust backend is structured into two cleanly separated layers:
- **`netflow-core` (standalone Rust library/module):** Discovery, graph validation, `sing-box` config compilation, route/proxy neutralization, crash recovery, and `sing-box` sidecar supervision. Has zero dependency on Tauri UI crates so v2 can wrap it in a Windows Service or Task Scheduler CLI without rewriting core logic.
- **`netflow-tauri` (Tauri v2 shell):** Thin IPC commands, system tray integration, and event streaming to the React frontend.

### 6.2 Visual Workflow UI (React + React Flow)

Matches the user's sketch:
- **Left Sidebar (Element Palette):**
  - **Interfaces Section:** Lists physical Windows adapters (`Wi-Fi`, `Ethernet`, etc.) with live Up/Down status, IPv4 address, and refresh button. Draggable onto the canvas.
  - **VPNs Section:** Lists the 3 supported VPNs (`Karing`, `Cloudflare WARP`, `OpenVPN`) with live detection status (Running/Not Running, detected port/adapter). Draggable onto the canvas (max 1 instance per VPN provider on canvas).
  - **Apps Group:** Draggable `Connected Apps` node card (unlimited instances).
- **Main Canvas (`@xyflow/react`):**
  - **Interface Node:** Right-side output handle. Shows adapter name, IPv4, Up/Down badge, and a **"Set as Default"** toggle badge (marks this interface as catch-all for all unlisted apps).
  - **VPN Node:** Left-side input handle (connects from 1 upstream Interface **or** 1 upstream VPN), right-side output handle (connects to 1+ Connected Apps nodes and/or downstream VPN nodes). Shows live status, connector mode/port/adapter, a **"Set as Default"** toggle badge, and a small settings popover (e.g., override Karing port, switch WARP between TUN [default] and Proxy fallback mode, select OpenVPN adapter if multiple exist).
  - **Connected Apps Node:** Left-side input handle (connects from 1 Interface or 1 VPN). Displays a table/list of assigned executables (`chrome.exe`, etc.) matching the sketch, with an **Add App** picker (searchable running Windows processes + "Browse `.exe`..." dialog) and per-row remove button.
- **Graph Validation Rules (enforced live in UI & before Apply):**
  - Allowed edges: `Interface -> VPN`, `Interface -> Connected Apps`, `VPN -> VPN` (chaining), `VPN -> Connected Apps`.
  - Disallowed: `Connected Apps -> anything`, cycles (`VPN A -> VPN B -> VPN A`), >1 upstream connection into any VPN or Apps node, >1 node of the same VPN provider.
  - Every active VPN chain (any VPN with Connected Apps attached, a downstream VPN, or marked as **Default**) must trace back cleanly to a root physical Interface (finite DAG, max chain length 3 in v1).
  - If **Cloudflare WARP** is configured in **Proxy fallback mode (TCP-only)**, validation blocks/warns against placing a downstream VPN behind WARP (TUN mode is required when WARP feeds another VPN).
  - At most **1** node on the canvas may be marked **Default (All Other Apps)**; if none is marked, unlisted apps fall back to Windows' auto-detected primary physical interface.
  - Each executable name (case-insensitive, e.g., `chrome.exe`) may appear in **at most 1** Connected Apps node across the canvas; duplicates are highlighted and blocked before Apply.
- **Top Control Bar, Workflow Switcher & Live Monitor:**
  - **Workflow Switcher:** Dropdown/selector listing all saved named workflows stored in `%APPDATA%\NetFlow\workflows\`, with actions to **New**, **Save** (shows unsaved-changes `*` badge), **Save As / Duplicate**, **Rename**, and **Delete**.
  - **Anytime Switching:** Selecting a different saved workflow loads its canvas immediately. If routing is currently **Active**, the user can click **Switch & Apply** (or **Apply**) to hot-swap `sing-box` to the new workflow in ~1–2 seconds without manually stopping first (preserving original baseline `recovery.json` while reconciling any added/removed VPN route neutralizations).
  - `Start / Apply Workflow` and `Stop` buttons with state badge (`Stopped`, `Applying`, `Active`, `Warning`, `Error`).
  - Collapsible **Live Traffic Log** drawer (via `sing-box` local Clash API WebSocket) showing active connections (`process -> destination -> matched node/outbound`) so users can verify zero leaks in real time.
- **System Tray** *(Agent call)*: Closing/minimizing while active hides to Windows system tray; tray menu supports Show Window, Stop Routing, and Clean Exit.

### 6.3 VPN Provider Integrations (`vpn_adapters` Module)

| VPN | Outer Tunnel Binding to Upstream Node (Interface or Upstream VPN) | App Forwarding Mechanism | Route Neutralization on Apply |
|---|---|---|---|
| **Karing** | `process_name: ["karingService.exe", "karing.exe"]` -> upstream outbound (Interface `direct` or upstream VPN outbound) | Local Mixed/SOCKS5 port (`127.0.0.1:3067`, auto-detected from `karingService.exe` listening TCP sockets; full TCP + UDP Associate) | Snapshot & remove `Karing TUN Network Adapter` non-local IPv4/IPv6 split routes; add metric-500 fallback; restore exact routes on Stop. |
| **Cloudflare WARP** | `process_name: ["warp-svc.exe"]` -> upstream outbound (Interface `direct` or upstream VPN outbound) | **Primary (General-purpose, full TCP + UDP):** `direct` outbound with `bind_interface: "CloudflareWARP"` (TUN mode). **Optional fallback (user toggle in node settings):** `warp-cli mode proxy` (`127.0.0.1:40000`) with UDP explicitly blocked on WARP-routed apps so UDP never leaks. *(Note: Implementation plan must include an early live verification spike of WARP TUN + WFP firewall coexistence on Windows once WARP is installed.)* | In TUN mode (primary): snapshot & neutralize `CloudflareWARP` IPv4/IPv6 default/split routes to metric-500 fallback; restore on Stop. In Proxy fallback: snapshot & switch via `warp-cli`, restore previous mode on Stop. |
| **OpenVPN** | **Dual binding:** `process_name: ["openvpn.exe", "ovpnconnector.exe"]` -> upstream outbound **PLUS** remote server IP handling for kernel-mode OpenVPN DCO (`ovpn-dco.sys`, `System` PID 4): when upstream is a physical Interface, pin `/32` host route via that Interface's gateway; when upstream is another VPN, add a `sing-box` `ip_cidr: ["<ovpn_server_ip>/32"]` rule routing directly into the upstream VPN outbound *(Agent call)*. | `direct` outbound with `bind_interface` targeting the active OpenVPN virtual adapter (`OpenVPN Data Channel Offload` / `OpenVPN Wintun` / `TAP-Windows`). | Snapshot & replace OpenVPN's IPv4/IPv6 `0.0.0.0/0`, `0.0.0.0/1`, `128.0.0.0/1` (and `::/1`, `8000::/1`) hijack routes with a single metric-500 default route on the OpenVPN adapter; restore exact routes on Stop. |

### 6.4 `sing-box` Config Compilation & Zero-Leak Safeguards

1. **Dual-Stack TUN Inbound (IPv4 Routing + IPv6 Leak Prevention)** *(Agent call)*:
   - `NetFlow-TUN` configured with both IPv4 (`172.19.0.1/30`) and IPv6 (`fdfe:dcba:9876::1/126`), `auto_route: true`, `strict_route: true`, `stack: "mixed"`.
   - **IPv6 zero-leak guard:** Suppress `AAAA` DNS responses (IPv4-only strategy for hijacked DNS) and route IPv6 traffic to `reject` (`block`) so Happy Eyeballs on dual-stack networks can never silently bypass IPv4 VPN/interface rules.
2. **Windows System Proxy Neutralization** *(Agent call)*:
   - Before starting `NetFlow-TUN`, NetFlow snapshots `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`) into `recovery.json` and sets `ProxyEnable = 0` (broadcasting `InternetSetOption` refresh).
   - Why: Karing commonly enables Windows System Proxy (`127.0.0.1:3067`), which loops directly to localhost and bypasses `NetFlow-TUN`, causing apps wired to `Wi-Fi` directly to silently go through Karing instead. Restored cleanly on Stop/crash recovery.
3. **DNS & SNI Preservation:**
   - Enable `sing-box` **FakeIP** (`198.18.0.0/15`) for hijacked DNS (`protocol: "dns" -> action: "hijack-dns"`) paired with protocol/SNI sniffing (`action: "sniff"`).
   - Ensures Windows' shared `svchost.exe` DNS client never leaks VPN domains to the ISP DNS, and Karing always receives the real domain/SNI for ISP quota conversion.
   - Local/LAN ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, multicast/broadcast) route directly so LAN devices remain accessible.
4. **Strict Rule Order:**
   1. `sniff`
   2. `protocol: "dns"` -> `hijack-dns`
   3. IPv6 (`ip_version: 6`) -> `reject` (zero IPv6 leak guard)
   4. Private/LAN destination CIDRs -> `direct` (excluding FakeIP `198.18.0.0/15` and VPN local proxy ports)
   5. **VPN outer-tunnel rules (in topological order from root Interface outward):** each VPN's outer processes (`karingService.exe`/`karing.exe`, `warp-svc.exe`, `openvpn.exe`/`ovpnconnector.exe`, plus `ip_cidr: ["<ovpn_server_ip>/32"]` when OpenVPN is chained downstream of another VPN) -> its direct upstream outbound (either the root physical Interface `direct` outbound OR the upstream VPN outbound). Must precede app rules to prevent routing loops.
   6. **Connected Apps rules** (`process_name: [...]`) -> their wired VPN or physical Interface outbound (plus explicit UDP `reject` if a WARP node is using Proxy fallback mode).
   7. `final` -> user-designated **Default** node outbound (Interface or VPN), or Windows' primary physical interface (`default-direct`) if none is marked Default.

### 6.5 Lifecycle, Health Monitoring & Crash Recovery

- **One-Shot Apply / Stop Lifecycle (v1)** *(Agent call)*:
  - Wired VPNs must be connected before clicking **Apply / Start** (pre-flight validation reports any missing/disconnected VPN or Interface clearly before modifying routes).
  - While active, a background health watcher polls wired physical interfaces and VPNs every 2–3 seconds.
  - **Fail-Closed Behavior** *(Agent call)*: If a wired VPN **or** wired physical interface drops mid-session, NetFlow flags the node red in the UI, shows a clear **"Reconnect & Re-Apply"** banner (and if the dropped node is the **Default**, offers a one-click **Stop / Reset Default** action), and **never** silently falls back its assigned apps to another interface or ISP.
- **Atomic Crash Recovery (`%APPDATA%\NetFlow\recovery.json`):**
  - Written and flushed to disk **before** modifying any route, metric, System Proxy setting, or WARP mode.
  - Records: all removed/added IPv4 & IPv6 routes, original interface metrics, original Windows System Proxy registry values, and WARP mode if toggled.
  - On Stop, app exit, or `sing-box` fatal exit: terminates `sing-box`, restores everything from `recovery.json`, and deletes `recovery.json`.
  - On next app launch: if a stale `recovery.json` exists (power loss / crash / forced kill), automatically restores saved Windows network state and notifies the user.

---

## 7. What's Left to the Builder

- Visual polish, color palette, typography, and dark/light theme styling of the React Flow canvas and sidebar cards.
- Frontend state management choice (e.g., Zustand vs React Context) and exact Tauri v2 IPC command/event schemas.
- Windows networking API implementation in Rust (`windows` crate IP Helper APIs `GetAdaptersAddresses` / `GetIpForwardTable2` / `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` / `GetExtendedTcpTable` + Win32 Registry/`WinINet` APIs vs elevated PowerShell fallbacks — native Win32 APIs preferred).
- Exact `sing-box` v1.14+ JSON schema syntax for FakeIP, IPv4-only DNS strategy, sniffing, and Clash API (must be verified against `sing-box check`).
- Early verification step during implementation for **Cloudflare WARP TUN** (`CloudflareWARP` adapter + WFP firewall coexistence) and **OpenVPN DCO** (`/32` host-route detection) once those clients are available for testing.
- Sidecar bundling scripts for `sing-box.exe` + `wintun.dll` in Tauri v2 and Windows installer (NSIS/MSI).
- Removing the throwaway `spike/` folder once implementation begins.
