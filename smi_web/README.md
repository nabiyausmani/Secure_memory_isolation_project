# Secure Memory Isolation System — Web Dashboard
## CSE-316 CA2 | OS Security Project

### How to Run

#### Linux / macOS
```bash
make
./smi_server
```
Browser opens automatically at http://localhost:8080

#### Windows (MinGW / MSYS2)
```bash
make windows
smi_server.exe
```

#### Manual compile (any platform)
```bash
# Linux/macOS
gcc -o smi_server server.c -Wall -std=c11

# Windows
gcc -o smi_server.exe server.c -lws2_32 -Wall -std=c11
```

---

### Features

| Feature | Description |
|---|---|
| **Create Process** | Spawn named processes with unique color coding |
| **Allocate Memory** | Assign blocks from the 64-block page table |
| **Deallocate** | Click any block on map → auto-fills address |
| **Isolation Test** | Attempt cross-process READ/WRITE — violations blocked |
| **Attack Simulation** | Full demo: browser + database + malware scenario |
| **Live Memory Map** | Visual 8×8 grid, colour-coded per process |
| **Event Log** | Real-time feed of all accesses and violations |
| **Reset** | Wipe everything and start fresh |

---

### Architecture

```
server.c  (single file)
├── Memory Isolation Engine   — page table, isolation checks
├── HTTP Server               — handles GET/POST on port 8080
├── REST API                  — /api/state, /api/create, /api/alloc ...
└── Embedded HTML Dashboard   — full browser UI (no extra files needed)
```
