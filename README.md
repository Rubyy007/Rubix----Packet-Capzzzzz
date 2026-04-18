# Rubix----Packet-Capzzzzz

# RUBIX – Cargo.toml Explanation

## 📌 Overview

This `Cargo.toml` defines the **build configuration, dependencies, and features** for the RUBIX project — a high-performance network packet processing engine.

It controls:

* How the project is compiled
* What external libraries are used
* Platform-specific behavior
* Optional capabilities (webhooks, storage, eBPF)

---

## 🧱 Package Configuration

```toml
[package]
name = "rubix"
version = "0.1.0"
edition = "2021"
```

* **name** → Project name
* **version** → Current release version
* **edition** → Rust language edition (2021 = modern Rust features)

---

## ⚙️ Binary Targets

```toml
[[bin]]
name = "rubix"
path = "src/main.rs"

[[bin]]
name = "rubix-cli"
path = "cli/main.rs"
```

Defines two executables:

* **rubix** → Main engine (daemon)
* **rubix-cli** → Command-line tool to interact with the engine

---

## 📦 Core Dependencies

### 📡 Packet Processing

```toml
pcap = "1.2"
etherparse = "0.13"
```

* `pcap` → Captures network packets from NIC
* `etherparse` → Parses packet headers (TCP, UDP, IP)

---

### ⚡ Async Runtime (Control Plane)

```toml
tokio = { version = "1.35", features = ["rt-multi-thread", "macros", "net", "time"] }
async-trait = "0.1"
```

* `tokio` → Handles async tasks like CLI, export, IPC
* `async-trait` → Allows async functions in traits

👉 Important: Used only in **slow/control path**, not fast packet processing.

---

### 🔄 Concurrency & Performance

```toml
crossbeam-channel = "0.5"
dashmap = "5.5"
once_cell = "1.19"
```

* `crossbeam-channel` → Lock-free communication between threads
* `dashmap` → Thread-safe hashmap (used for caching)
* `once_cell` → Lazy static initialization

---

### 🧠 Memory Optimization

```toml
bytes = "1"
```

* Efficient buffer handling
* Helps reduce allocations in high-performance paths

---

### 📄 Serialization

```toml
serde = { version = "1.0", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1.0"
```

* `serde` → Converts Rust structs ↔ data formats
* `serde_yaml` → Loads config & rules
* `serde_json` → Used for IPC and APIs

---

### 📊 Logging & Observability

```toml
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-appender = "0.2"
```

* `tracing` → Structured logging system
* `subscriber` → Controls log format/filtering
* `appender` → Writes logs to files

---

### 📁 File System & Config Reload

```toml
notify = "6.1"
walkdir = "2"
```

* `notify` → Watches config file changes
* `walkdir` → Traverses directories

---

### 🧩 System-Level APIs

```toml
nix = { version = "0.27", features = ["socket", "net", "poll"] }
libc = "0.2"
```

* `nix` → Unix system calls (sockets, networking)
* `libc` → Low-level OS bindings

---

### 🖥️ CLI Tool

```toml
clap = { version = "4.4", features = ["derive"] }
```

* Parses CLI arguments
* Used in `rubix-cli`

---

## 🌐 Optional Dependencies

### 🔔 Webhooks

```toml
reqwest = { version = "0.11", features = ["json"], optional = true }
```

* Sends HTTP alerts/events
* Enabled only when `webhook` feature is active

---

### 💾 Storage

```toml
rusqlite = { version = "0.30", optional = true }
```

* Stores events in SQLite database
* Enabled via `storage` feature

---

## 🖥️ Platform-Specific Dependencies

### 🐧 Linux

```toml
[target.'cfg(target_os="linux")'.dependencies]
nftables = { version = "0.4", optional = true }
aya = { version = "0.12", optional = true }
```

* `nftables` → Firewall rule management
* `aya` → eBPF support for high-performance kernel filtering

---

### 🪟 Windows

```toml
[target.'cfg(target_os="windows")'.dependencies]
winapi = { version = "0.3", features = ["iphlpapi", "winerror"] }
```

* Provides Windows networking APIs
* Used for process mapping and filtering

---

## 🔧 Feature Flags

```toml
[features]
default = ["webhook"]

webhook = ["reqwest"]
storage = ["rusqlite"]
ebpf = ["aya"]

full = ["webhook", "storage", "ebpf"]
```

Defines optional capabilities:

* **default** → Enables webhook support
* **webhook** → HTTP alerts
* **storage** → SQLite persistence
* **ebpf** → Kernel-level packet filtering
* **full** → Enables everything

👉 Allows building lightweight or full versions of RUBIX.

---

## 🚀 Release Optimization

```toml
[profile.release]
lto = true
codegen-units = 1
opt-level = 3
```

Optimizes performance:

* `lto = true` → Link-time optimization (smaller + faster binary)
* `codegen-units = 1` → Better optimization (slower compile)
* `opt-level = 3` → Maximum performance

---

## 🧠 Summary

This configuration enables RUBIX to:

* Capture and analyze network packets in real time
* Process data using a high-performance, multi-threaded architecture
* Support optional features like webhooks, storage, and eBPF
* Run on both Linux and Windows
* Maintain clear separation between fast path and control plane

---

## ⚠️ Key Design Insight

* **Fast Path** → Uses `pcap`, `etherparse`, `crossbeam` (no blocking)
* **Control Plane** → Uses `tokio`, `reqwest`, `rusqlite`
* **Kernel Integration** → Optional via `nftables` and `aya`

This separation is critical for achieving **low latency and high throughput**.

---

