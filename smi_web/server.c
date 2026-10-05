/*
 * server.c  —  Secure Memory Isolation System
 * Self-contained C HTTP server + Memory Isolation Engine
 * Opens a browser dashboard on http://localhost:8080
 *
 * Compile:  gcc -o smi_server server.c -Wall -std=c11
 * Run:      ./smi_server
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #define close closesocket
  #define sleep(x) Sleep((x)*1000)
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/stat.h>
#endif

/* ════════════════════════════════════════════════════
   MEMORY ISOLATION ENGINE
   ════════════════════════════════════════════════════ */

#define TOTAL_BLOCKS  64
#define BLOCK_SIZE    64
#define BASE_ADDRESS  0x1000
#define MAX_PROCESSES 16
#define MAX_EVENTS    256
#define MAX_NAME      32
#define NO_OWNER      -1
#define PORT          8080

typedef struct {
    int  address;
    int  owner_pid;
    int  is_free;
    int  access_count;
    unsigned char data[BLOCK_SIZE];
} MemBlock;

typedef struct {
    int  pid;
    char name[MAX_NAME];
    int  is_alive;
    int  owned[TOTAL_BLOCKS];
    int  num_owned;
    char color[16];
} Process;

typedef struct {
    int  pid;
    int  address;
    int  action;   /* 0=READ 1=WRITE 2=ALLOC 3=DEALLOC 4=CREATE 5=TERMINATE */
    int  success;
    int  viol_owner;
    char ts[20];
} Event;

typedef struct {
    MemBlock  blocks[TOTAL_BLOCKS];
    Process   procs[MAX_PROCESSES];
    int       proc_count;
    Event     events[MAX_EVENTS];
    int       event_count;
    int       next_pid;
} MM;

static MM mm;

static const char *PROC_COLORS[] = {
    "#6366f1","#ec4899","#f59e0b","#10b981","#3b82f6","#ef4444",
    "#8b5cf6","#06b6d4","#84cc16","#f97316","#14b8a6","#e11d48"
};

static void mm_timestamp(char *buf) {
    time_t t = time(NULL);
    struct tm *ti = localtime(&t);
    strftime(buf, 20, "%H:%M:%S", ti);
}

static int mm_find_proc(int pid) {
    for (int i = 0; i < mm.proc_count; i++)
        if (mm.procs[i].pid == pid && mm.procs[i].is_alive) return i;
    return -1;
}

static int mm_find_block(int addr) {
    for (int i = 0; i < TOTAL_BLOCKS; i++)
        if (mm.blocks[i].address == addr) return i;
    return -1;
}

static void mm_log(int pid, int addr, int action, int success, int vowner) {
    if (mm.event_count >= MAX_EVENTS) {
        memmove(mm.events, mm.events+1, (MAX_EVENTS-1)*sizeof(Event));
        mm.event_count = MAX_EVENTS-1;
    }
    Event *e = &mm.events[mm.event_count++];
    e->pid=pid; e->address=addr; e->action=action;
    e->success=success; e->viol_owner=vowner;
    mm_timestamp(e->ts);
}

static void mm_init(void) {
    memset(&mm, 0, sizeof(MM));
    mm.next_pid = 1;
    for (int i = 0; i < TOTAL_BLOCKS; i++) {
        mm.blocks[i].address   = BASE_ADDRESS + i*BLOCK_SIZE;
        mm.blocks[i].owner_pid = NO_OWNER;
        mm.blocks[i].is_free   = 1;
    }
}

static int api_create(const char *name) {
    if (mm.proc_count >= MAX_PROCESSES) return -1;
    Process *p = &mm.procs[mm.proc_count++];
    p->pid = mm.next_pid++;
    p->is_alive = 1;
    p->num_owned = 0;
    strncpy(p->name, name && name[0] ? name : "process", MAX_NAME-1);
    strncpy(p->color, PROC_COLORS[(p->pid-1) % 12], 15);
    mm_log(p->pid, 0, 4, 1, NO_OWNER);
    return p->pid;
}

static int api_terminate(int pid) {
    int idx = mm_find_proc(pid);
    if (idx < 0) return -1;
    Process *p = &mm.procs[idx];
    for (int i = 0; i < p->num_owned; i++) {
        int bi = mm_find_block(p->owned[i]);
        if (bi >= 0) {
            mm.blocks[bi].owner_pid = NO_OWNER;
            mm.blocks[bi].is_free   = 1;
            memset(mm.blocks[bi].data, 0, BLOCK_SIZE);
        }
    }
    p->num_owned = 0;
    p->is_alive  = 0;
    mm_log(pid, 0, 5, 1, NO_OWNER);
    return 0;
}

static int api_alloc(int pid, int n, int *out) {
    int pidx = mm_find_proc(pid);
    if (pidx < 0) return -1;
    int free_count = 0;
    for (int i = 0; i < TOTAL_BLOCKS; i++) if (mm.blocks[i].is_free) free_count++;
    if (free_count < n) return -2;
    int got = 0;
    for (int i = 0; i < TOTAL_BLOCKS && got < n; i++) {
        if (mm.blocks[i].is_free) {
            mm.blocks[i].is_free = 0;
            mm.blocks[i].owner_pid = pid;
            for (int b = 0; b < BLOCK_SIZE; b++)
                mm.blocks[i].data[b] = (unsigned char)(rand()%256);
            mm.procs[pidx].owned[mm.procs[pidx].num_owned++] = mm.blocks[i].address;
            if (out) out[got] = mm.blocks[i].address;
            got++;
            mm_log(pid, mm.blocks[i].address, 2, 1, NO_OWNER);
        }
    }
    return got;
}

static int api_dealloc(int pid, int addr) {
    int pidx = mm_find_proc(pid);
    if (pidx < 0) return -1;
    int bi = mm_find_block(addr);
    if (bi < 0) return -2;
    if (mm.blocks[bi].owner_pid != pid) return -3;
    mm.blocks[bi].is_free = 1;
    mm.blocks[bi].owner_pid = NO_OWNER;
    memset(mm.blocks[bi].data, 0, BLOCK_SIZE);
    Process *p = &mm.procs[pidx];
    for (int i = 0; i < p->num_owned; i++) {
        if (p->owned[i] == addr) {
            p->owned[i] = p->owned[--p->num_owned];
            break;
        }
    }
    mm_log(pid, addr, 3, 1, NO_OWNER);
    return 0;
}

static int api_read(int pid, int addr) {
    int bi = mm_find_block(addr);
    if (bi < 0) return -1;
    MemBlock *b = &mm.blocks[bi];
    if (b->is_free || b->owner_pid != pid) {
        int vo = b->is_free ? NO_OWNER : b->owner_pid;
        mm_log(pid, addr, 0, 0, vo);
        return -2;
    }
    b->access_count++;
    mm_log(pid, addr, 0, 1, NO_OWNER);
    return 0;
}

static int api_write(int pid, int addr, unsigned char val) {
    int bi = mm_find_block(addr);
    if (bi < 0) return -1;
    MemBlock *b = &mm.blocks[bi];
    if (b->is_free || b->owner_pid != pid) {
        int vo = b->is_free ? NO_OWNER : b->owner_pid;
        mm_log(pid, addr, 1, 0, vo);
        return -2;
    }
    b->access_count++;
    b->data[0] = val;
    mm_log(pid, addr, 1, 1, NO_OWNER);
    return 0;
}

static void api_run_demo(void) {
    int p1 = api_create("browser");
    int p2 = api_create("database");
    int p3 = api_create("malware");
    int b1[4], b2[4], b3[2];
    api_alloc(p1, 4, b1);
    api_alloc(p2, 3, b2);
    api_alloc(p3, 1, b3);
    api_read(p1, b1[0]); api_write(p1, b1[1], 0xAB);
    api_read(p2, b2[0]); api_write(p2, b2[1], 0xCD);
    api_read(p3, b1[0]); api_write(p3, b1[1], 0xFF);
    api_read(p3, b2[0]); api_write(p3, b2[2], 0xEE);
    api_read(p3, b1[2]);
}

/* ════════════════════════════════════════════════════
   JSON BUILDERS
   ════════════════════════════════════════════════════ */

static int json_state(char *buf, int max) {
    int n = 0;
    n += snprintf(buf+n, max-n, "{\"blocks\":[");
    for (int i = 0; i < TOTAL_BLOCKS; i++) {
        MemBlock *b = &mm.blocks[i];
        const char *col = "#f1f5f9";
        if (!b->is_free) {
            int pi = mm_find_proc(b->owner_pid);
            if (pi >= 0) col = mm.procs[pi].color;
        }
        n += snprintf(buf+n, max-n,
            "%s{\"addr\":%d,\"free\":%d,\"owner\":%d,\"ac\":%d,\"color\":\"%s\"}",
            i?",":"", b->address, b->is_free, b->owner_pid, b->access_count, col);
    }
    n += snprintf(buf+n, max-n, "],\"procs\":[");
    int first = 1;
    for (int i = 0; i < mm.proc_count; i++) {
        Process *p = &mm.procs[i];
        if (!p->is_alive) continue;
        n += snprintf(buf+n, max-n,
            "%s{\"pid\":%d,\"name\":\"%s\",\"blocks\":%d,\"color\":\"%s\"}",
            first?"":",", p->pid, p->name, p->num_owned, p->color);
        first = 0;
    }
    int used=0, viols=0, succ=0;
    for (int i=0;i<TOTAL_BLOCKS;i++) if(!mm.blocks[i].is_free) used++;
    for (int i=0;i<mm.event_count;i++) {
        if(!mm.events[i].success) viols++;
        else if(mm.events[i].action<2) succ++;
    }
    n += snprintf(buf+n, max-n,
        "],\"stats\":{\"total\":%d,\"used\":%d,\"free\":%d,"
        "\"procs\":%d,\"events\":%d,\"violations\":%d,\"success\":%d},",
        TOTAL_BLOCKS, used, TOTAL_BLOCKS-used,
        mm.proc_count, mm.event_count, viols, succ);

    n += snprintf(buf+n, max-n, "\"events\":[");
    static const char *anames[]={"READ","WRITE","ALLOC","DEALLOC","CREATE","TERMINATE"};
    int start = mm.event_count > 40 ? mm.event_count-40 : 0;
    for (int i = mm.event_count-1; i >= start; i--) {
        Event *e = &mm.events[i];
        n += snprintf(buf+n, max-n,
            "%s{\"ts\":\"%s\",\"pid\":%d,\"addr\":\"0x%X\","
            "\"action\":\"%s\",\"ok\":%d,\"vo\":%d}",
            i==mm.event_count-1?"":",",
            e->ts, e->pid, e->address,
            anames[e->action], e->success, e->viol_owner);
    }
    n += snprintf(buf+n, max-n, "]}");
    return n;
}

/* ════════════════════════════════════════════════════
   EMBEDDED HTML DASHBOARD
   ════════════════════════════════════════════════════ */

static const char *HTML =
"<!DOCTYPE html><html lang='en'><head>"
"<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Memory Isolation Lab</title>"
"<link href='https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap' rel='stylesheet'>"
"<style>"
":root{"
"--bg:#f8fafc;--surface:#fff;--border:#e2e8f0;--border2:#cbd5e1;"
"--text:#1e293b;--text2:#64748b;--text3:#94a3b8;"
"--primary:#6366f1;--primary-lt:#eef2ff;"
"--success:#10b981;--success-lt:#ecfdf5;"
"--danger:#ef4444;--danger-lt:#fef2f2;"
"--warning:#f59e0b;--warning-lt:#fffbeb;"
"--sh:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);"
"--sh2:0 4px 6px rgba(0,0,0,.07),0 2px 4px rgba(0,0,0,.05);"
"--r:12px;--rs:8px}"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;font-size:14px;line-height:1.5}"
".nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;"
"display:flex;align-items:center;justify-content:space-between;height:60px;"
"position:sticky;top:0;z-index:100;box-shadow:var(--sh)}"
".nav-brand{display:flex;align-items:center;gap:10px}"
".nav-icon{width:34px;height:34px;background:linear-gradient(135deg,#6366f1,#8b5cf6);"
"border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px}"
".nav-title{font-weight:700;font-size:15px}"
".nav-sub{font-size:11px;color:var(--text2)}"
".nav-right{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text2)}"
".dot{width:7px;height:7px;border-radius:50%;background:var(--success);animation:blink 2s infinite}"
"@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}"
".layout{display:grid;grid-template-columns:296px 1fr 296px;height:calc(100vh - 60px);overflow:hidden}"
".sidebar,.sidebar-r{background:var(--surface);overflow-y:auto;padding:20px}"
".sidebar{border-right:1px solid var(--border)}"
".sidebar-r{border-left:1px solid var(--border)}"
".main{overflow-y:auto;padding:20px;background:var(--bg)}"
".sec{margin-bottom:22px}"
".sec-title{font-size:11px;font-weight:600;letter-spacing:.7px;text-transform:uppercase;"
"color:var(--text2);margin-bottom:10px;display:flex;align-items:center;gap:6px}"
".sec-title::before{content:'';width:3px;height:11px;background:var(--primary);border-radius:2px}"
"input,select{width:100%;background:var(--bg);border:1.5px solid var(--border);"
"color:var(--text);font-family:'DM Sans',sans-serif;font-size:13px;"
"padding:8px 11px;border-radius:var(--rs);margin-bottom:7px;outline:none;transition:.15s}"
"input:focus,select:focus{border-color:var(--primary);background:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.1)}"
"input::placeholder{color:var(--text3)}"
"button{width:100%;padding:9px 14px;font-family:'DM Sans',sans-serif;font-size:13px;font-weight:500;"
"border-radius:var(--rs);cursor:pointer;transition:all .15s;border:1.5px solid transparent;"
"margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:6px}"
".bp{background:var(--primary);color:#fff;border-color:var(--primary)}"
".bp:hover{background:#4f46e5;transform:translateY(-1px);box-shadow:var(--sh2)}"
".bs{background:var(--success);color:#fff;border-color:var(--success)}"
".bs:hover{background:#059669;transform:translateY(-1px);box-shadow:var(--sh2)}"
".bd{background:var(--danger);color:#fff;border-color:var(--danger)}"
".bd:hover{background:#dc2626;transform:translateY(-1px);box-shadow:var(--sh2)}"
".bw{background:var(--warning);color:#fff;border-color:var(--warning)}"
".bw:hover{background:#d97706;transform:translateY(-1px);box-shadow:var(--sh2)}"
".bg2{background:transparent;color:var(--text2);border-color:var(--border)}"
".bg2:hover{background:var(--bg);border-color:var(--border2);color:var(--text)}"
".bdemo{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none}"
".bdemo:hover{opacity:.9;transform:translateY(-1px);box-shadow:var(--sh2)}"
".pc{border:1.5px solid var(--border);border-radius:var(--rs);padding:11px;margin-bottom:7px;"
"cursor:pointer;transition:all .15s;background:var(--surface)}"
".pc:hover{border-color:var(--primary);background:var(--primary-lt)}"
".pc.sel{border-color:var(--primary);background:var(--primary-lt);box-shadow:0 0 0 3px rgba(99,102,241,.1)}"
".pc-top{display:flex;align-items:center;gap:9px}"
".pc-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}"
".pc-name{font-weight:600;font-size:13px;flex:1}"
".pc-pid{font-size:11px;color:var(--text3);font-family:'DM Mono',monospace}"
".pc-stat{font-size:11px;color:var(--text2);margin-top:3px;padding-left:19px}"
".sgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin-bottom:18px}"
".sc{background:var(--surface);border:1.5px solid var(--border);border-radius:var(--r);"
"padding:15px;text-align:center;box-shadow:var(--sh)}"
".sn{font-size:28px;font-weight:700;line-height:1;margin-bottom:3px}"
".sl{font-size:11px;color:var(--text2);font-weight:500;text-transform:uppercase;letter-spacing:.5px}"
".su .sn{color:var(--primary)}.sf .sn{color:var(--success)}"
".sv .sn{color:var(--danger)}.se .sn{color:var(--warning)}"
".mc{background:var(--surface);border:1.5px solid var(--border);border-radius:var(--r);"
"padding:20px;box-shadow:var(--sh)}"
".mh{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}"
".mt{font-weight:700;font-size:15px}"
".mhint{font-size:11px;color:var(--text3)}"
".mgrid{display:grid;grid-template-columns:repeat(16,1fr);gap:4px;margin-bottom:14px}"
".mb{aspect-ratio:1;border-radius:5px;cursor:pointer;transition:all .12s;position:relative;border:1.5px solid transparent}"
".mb.free{background:#f1f5f9;border-color:#e2e8f0}"
".mb.used{border-color:rgba(0,0,0,.08)}"
".mb:hover{transform:scale(1.4);z-index:20;box-shadow:0 4px 12px rgba(0,0,0,.15)}"
".mb.hi{outline:2.5px solid var(--primary);outline-offset:2px;z-index:5}"
".tip{display:none;position:absolute;bottom:125%;left:50%;transform:translateX(-50%);"
"background:#1e293b;color:#fff;padding:6px 10px;border-radius:6px;"
"font-size:11px;white-space:nowrap;z-index:100;pointer-events:none;font-family:'DM Mono',monospace;"
"box-shadow:var(--sh2)}"
".tip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);"
"border:4px solid transparent;border-top-color:#1e293b}"
".mb:hover .tip{display:block}"
".leg{display:flex;flex-wrap:wrap;gap:10px}"
".li{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--text2)}"
".ld{width:10px;height:10px;border-radius:3px;flex-shrink:0}"
".le{display:flex;align-items:center;gap:7px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}"
".le:last-child{border-bottom:none}"
".lb{flex-shrink:0;width:58px;text-align:center;padding:2px 5px;border-radius:5px;"
"font-size:10px;font-weight:600;letter-spacing:.3px}"
".ok .lb{background:var(--success-lt);color:var(--success)}"
".viol .lb{background:var(--danger-lt);color:var(--danger)}"
".la{font-family:'DM Mono',monospace;font-size:11px;width:58px;flex-shrink:0;font-weight:500}"
".laddr{font-family:'DM Mono',monospace;color:var(--primary);font-size:11px;width:58px;flex-shrink:0}"
".ldesc{color:var(--text2);flex:1;font-size:12px}"
".lts{color:var(--text3);font-size:10px;font-family:'DM Mono',monospace;flex-shrink:0}"
".lempty{text-align:center;color:var(--text3);padding:28px 0;font-size:13px}"
".div{height:1px;background:var(--border);margin:14px 0}"
".empty{text-align:center;padding:20px;color:var(--text3);font-size:13px;"
"border:1.5px dashed var(--border);border-radius:var(--rs)}"
".toast{position:fixed;bottom:22px;right:22px;padding:11px 16px;border-radius:var(--rs);"
"font-size:13px;font-weight:500;z-index:9999;animation:sup .2s ease;"
"box-shadow:var(--sh2);display:flex;align-items:center;gap:7px;max-width:300px}"
"@keyframes sup{from{transform:translateY(16px);opacity:0}to{transform:translateY(0);opacity:1}}"
".tok{background:var(--success);color:#fff}"
".terr{background:var(--danger);color:#fff}"
".twarn{background:var(--warning);color:#fff}"
".tinfo{background:var(--primary);color:#fff}"
"::-webkit-scrollbar{width:5px}"
"::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}"
"</style></head><body>"

"<nav class='nav'>"
"<div class='nav-brand'>"
"<div class='nav-icon'>🔒</div>"
"<div><div class='nav-title'>Memory Isolation Lab</div>"
"<div class='nav-sub'>CSE-316 &middot; OS Security Simulation</div></div>"
"</div>"
"<div class='nav-right'><div class='dot'></div><span>Server live on port 8080</span></div>"
"</nav>"

"<div class='layout'>"

"<div class='sidebar'>"
"<div class='sec'>"
"<div class='sec-title'>Create Process</div>"
"<input type='text' id='pname' placeholder='Enter process name...' maxlength='16'>"
"<button class='bp' onclick='createProc()'>&#xFF0B; Create Process</button>"
"</div>"
"<div class='sec'>"
"<div class='sec-title'>Active Processes</div>"
"<div id='proc-list'><div class='empty'>No processes yet.<br>Create one to start!</div></div>"
"</div>"
"<div class='div'></div>"
"<div class='sec'>"
"<div class='sec-title'>Memory Operations</div>"
"<select id='op-pid'><option value=''>Choose a process...</option></select>"
"<input type='number' id='op-blocks' placeholder='Blocks to allocate' min='1' max='20' value='2'>"
"<button class='bs' onclick='doAlloc()'>&#128230; Allocate Memory</button>"
"<input type='text' id='op-addr' placeholder='Address to free (click a block)'>"
"<button class='bw' onclick='doDealloc()'>&#128465; Deallocate Block</button>"
"<button class='bg2' onclick='terminateProc()'>&#9760; Terminate Process</button>"
"</div>"
"<div class='div'></div>"
"<div class='sec'>"
"<div class='sec-title'>Isolation Test</div>"
"<select id='atk-pid'><option value=''>Choose attacker process...</option></select>"
"<input type='text' id='atk-addr' placeholder='Target address (click a block)'>"
"<button class='bd' onclick='doRead()'>&#9889; Attempt Read</button>"
"<button class='bd' onclick='doWrite()'>&#9889; Attempt Write</button>"
"</div>"
"<div class='div'></div>"
"<div class='sec'>"
"<div class='sec-title'>Quick Actions</div>"
"<button class='bdemo' onclick='runDemo()'>&#9654; Run Attack Demo</button>"
"<button class='bg2' onclick='resetAll()'>&#8635; Reset Everything</button>"
"</div>"
"</div>"

"<div class='main'>"
"<div class='sgrid'>"
"<div class='sc su'><div class='sn' id='s-used'>0</div><div class='sl'>Used Blocks</div></div>"
"<div class='sc sf'><div class='sn' id='s-free'>64</div><div class='sl'>Free Blocks</div></div>"
"<div class='sc sv'><div class='sn' id='s-viols'>0</div><div class='sl'>Violations</div></div>"
"<div class='sc se'><div class='sn' id='s-events'>0</div><div class='sl'>Total Events</div></div>"
"</div>"
"<div class='mc'>"
"<div class='mh'>"
"<div class='mt'>Memory Map <span style='color:var(--text3);font-weight:400;font-size:13px'>64 blocks &times; 64 bytes each</span></div>"
"<div class='mhint'>&#128161; Click any block to select it</div>"
"</div>"
"<div class='mgrid' id='mem-grid'></div>"
"<div class='leg' id='legend'>"
"<div class='li'><div class='ld' style='background:#f1f5f9;border:1.5px solid #e2e8f0'></div><span>Free</span></div>"
"</div>"
"</div>"
"</div>"

"<div class='sidebar-r'>"
"<div class='sec-title'>Activity Log</div>"
"<div style='font-size:11px;color:var(--text3);margin-bottom:11px' id='log-count'>No events yet</div>"
"<div id='log-list'><div class='lempty'>Waiting for events...</div></div>"
"</div>"

"</div>"

"<script>"
"let state={blocks:[],procs:[],stats:{},events:[]};"
"let selPid=null,selAddr=null;"
"async function api(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});return r.json();}"
"async function refresh(){const r=await fetch('/api/state');state=await r.json();render();}"
"function render(){renderGrid();renderProcs();renderStats();renderLog();renderLegend();fillSel();}"

"function renderGrid(){"
"  const g=document.getElementById('mem-grid');g.innerHTML='';"
"  state.blocks.forEach(b=>{"
"    const d=document.createElement('div');"
"    d.className='mb '+(b.free?'free':'used')+(b.addr===selAddr?' hi':'');"
"    if(!b.free)d.style.background=b.color;"
"    d.innerHTML=`<div class='tip'>0x${b.addr.toString(16).toUpperCase()}<br>${b.free?'Free':'PID '+b.owner} &middot; Hits:${b.ac}</div>`;"
"    d.onclick=()=>{selAddr=b.addr;"
"      document.getElementById('atk-addr').value=b.addr.toString(16).toUpperCase();"
"      document.getElementById('op-addr').value=b.addr.toString(16).toUpperCase();"
"      if(b.owner>0)document.getElementById('op-pid').value=b.owner;"
"      renderGrid();"
"    };"
"    g.appendChild(d);"
"  });"
"}"

"function renderProcs(){"
"  const el=document.getElementById('proc-list');"
"  if(!state.procs||!state.procs.length){el.innerHTML=\"<div class='empty'>No processes yet.<br>Create one to start!</div>\";return;}"
"  el.innerHTML=state.procs.map(p=>`<div class='pc${selPid===p.pid?' sel':''}' onclick='selP(${p.pid})'>`+"
"    `<div class='pc-top'><div class='pc-dot' style='background:${p.color}'></div>`+"
"    `<div class='pc-name'>${p.name}</div><div class='pc-pid'>PID ${p.pid}</div></div>`+"
"    `<div class='pc-stat'>${p.blocks} block${p.blocks!==1?'s':''} allocated</div></div>`"
"  ).join('');"
"}"

"function selP(pid){selPid=pid;document.getElementById('op-pid').value=pid;document.getElementById('atk-pid').value=pid;renderProcs();}"

"function renderStats(){"
"  const s=state.stats||{};"
"  document.getElementById('s-used').textContent=s.used||0;"
"  document.getElementById('s-free').textContent=s.free||64;"
"  document.getElementById('s-viols').textContent=s.violations||0;"
"  document.getElementById('s-events').textContent=s.events||0;"
"}"

"const AC={READ:'#3b82f6',WRITE:'#f59e0b',ALLOC:'#10b981',DEALLOC:'#f97316',CREATE:'#8b5cf6',TERMINATE:'#ef4444'};"
"const AE={READ:'👁',WRITE:'✏️',ALLOC:'📦',DEALLOC:'🗑',CREATE:'✅',TERMINATE:'☠'};"

"function renderLog(){"
"  const el=document.getElementById('log-list'),cnt=document.getElementById('log-count');"
"  if(!state.events||!state.events.length){cnt.textContent='No events yet';el.innerHTML=\"<div class='lempty'>Waiting for events...</div>\";return;}"
"  cnt.textContent=`${state.stats.events||0} total events`;"
"  el.innerHTML=state.events.map(e=>{"
"    const col=AC[e.action]||'#888',em=AE[e.action]||'·';"
"    const desc=e.ok?`PID ${e.pid} &middot; ${e.addr}`:`PID ${e.pid} tried ${e.addr}`+(e.vo>=0?` (owned by PID ${e.vo})`:' (unowned)');"
"    return `<div class='le ${e.ok?'ok':'viol'}'>`+"
"      `<span class='lb'>${e.ok?'OK':'BLOCKED'}</span>`+"
"      `<span class='la' style='color:${col}'>${em} ${e.action}</span>`+"
"      `<span class='ldesc'>${desc}</span>`+"
"      `<span class='lts'>${e.ts}</span></div>`;"
"  }).join('');"
"}"

"function renderLegend(){"
"  const el=document.getElementById('legend');"
"  let h=\"<div class='li'><div class='ld' style='background:#f1f5f9;border:1.5px solid #e2e8f0'></div><span>Free</span></div>\";"
"  if(state.procs)state.procs.forEach(p=>{h+=`<div class='li'><div class='ld' style='background:${p.color}'></div><span>${p.name}</span></div>`;});"
"  el.innerHTML=h;"
"}"

"function fillSel(){"
"  const opts=state.procs?state.procs.map(p=>`<option value='${p.pid}'>${p.name} (PID ${p.pid})</option>`).join(''):'';"
"  ['op-pid','atk-pid'].forEach(id=>{const el=document.getElementById(id);const prev=el.value;el.innerHTML=\"<option value=''>Choose a process...</option>\"+opts;if(prev)el.value=prev;});"
"}"

"function toast(msg,t){const d=document.createElement('div');d.className=`toast t${t}`;d.textContent=msg;document.body.appendChild(d);setTimeout(()=>{d.style.opacity='0';d.style.transform='translateY(10px)';d.style.transition='.2s';setTimeout(()=>d.remove(),200);},3000);}"

"async function createProc(){"
"  const name=document.getElementById('pname').value.trim()||'process';"
"  const r=await api('/api/create',{name});"
"  if(r.pid>0)toast(`Process \"${name}\" created (PID ${r.pid})`,'ok');else toast('Could not create — limit reached','err');"
"  document.getElementById('pname').value='';refresh();"
"}"

"async function terminateProc(){"
"  const pid=parseInt(document.getElementById('op-pid').value);"
"  if(!pid){toast('Please select a process first','warn');return;}"
"  const r=await api('/api/terminate',{pid});"
"  if(r.ok)toast(`PID ${pid} terminated`,'ok');else toast('Terminate failed','err');refresh();"
"}"

"async function doAlloc(){"
"  const pid=parseInt(document.getElementById('op-pid').value);"
"  const n=parseInt(document.getElementById('op-blocks').value)||1;"
"  if(!pid){toast('Please select a process first','warn');return;}"
"  const r=await api('/api/alloc',{pid,n});"
"  if(r.got>0)toast(`Allocated ${r.got} block(s) to PID ${pid}`,'ok');else toast('Not enough free blocks','err');refresh();"
"}"

"async function doDealloc(){"
"  const pid=parseInt(document.getElementById('op-pid').value);"
"  const raw=document.getElementById('op-addr').value.trim().replace(/^0x/i,'');"
"  const addr=parseInt(raw,16);"
"  if(!pid||!addr){toast('Select a process and click a block on the map','warn');return;}"
"  const r=await api('/api/dealloc',{pid,addr});"
"  if(r.ok)toast(`Block 0x${addr.toString(16).toUpperCase()} freed`,'ok');else toast('Wrong owner or address','err');refresh();"
"}"

"async function doRead(){"
"  const pid=parseInt(document.getElementById('atk-pid').value);"
"  const raw=document.getElementById('atk-addr').value.trim().replace(/^0x/i,'');"
"  const addr=parseInt(raw,16);"
"  if(!pid||!addr){toast('Select a process and click a block on the map','warn');return;}"
"  const r=await api('/api/read',{pid,addr});"
"  if(r.ok)toast('PID '+pid+' READ 0x'+addr.toString(16).toUpperCase()+' - Allowed','ok');"
"  else toast('BLOCKED! PID '+pid+' cannot read that block','err');refresh();"
"}"

"async function doWrite(){"
"  const pid=parseInt(document.getElementById('atk-pid').value);"
"  const raw=document.getElementById('atk-addr').value.trim().replace(/^0x/i,'');"
"  const addr=parseInt(raw,16);"
"  if(!pid||!addr){toast('Select a process and click a block on the map','warn');return;}"
"  const r=await api('/api/write',{pid,addr,val:255});"
"  if(r.ok)toast('PID '+pid+' WRITE 0x'+addr.toString(16).toUpperCase()+' - Allowed','ok');"
"  else toast('BLOCKED! PID '+pid+' cannot write that block','err');refresh();"
"}"

"async function runDemo(){toast('Running attack demo...','info');await api('/api/demo',{});setTimeout(refresh,300);}"
"async function resetAll(){await api('/api/reset',{});selPid=null;selAddr=null;toast('System reset - fresh start!','ok');refresh();}"
"setInterval(refresh,2000);refresh();"
"</script></body></html>";

/* ════════════════════════════════════════════════════
   HTTP SERVER
   ════════════════════════════════════════════════════ */

static void send_response(int sock, int code, const char *ct,
                          const char *body, int blen) {
    char hdr[256];
    const char *status = (code==200)?"OK":"Not Found";
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        code, status, ct, blen);
    send(sock, hdr, hlen, 0);
    if (blen > 0) send(sock, body, blen, 0);
}

static int json_str(const char *json, const char *key, char *out, int olen) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p==' '||*p==':') p++;
    if (*p=='"') {
        p++;
        int i=0;
        while (*p && *p!='"' && i<olen-1) out[i++]=*p++;
        out[i]=0;
        return 1;
    }
    return 0;
}

static int json_int(const char *json, const char *key, int def) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return def;
    p += strlen(search);
    while (*p==' '||*p==':') p++;
    if (isdigit((unsigned char)*p) || *p=='-') return atoi(p);
    return def;
}

static void handle(int sock) {
    char req[4096];
    int n = recv(sock, req, sizeof(req)-1, 0);
    if (n <= 0) return;
    req[n] = 0;

    char method[8]={0}, path[128]={0};
    sscanf(req, "%7s %127s", method, path);

    const char *body_start = strstr(req, "\r\n\r\n");
    const char *body = body_start ? body_start+4 : "";

    if (strcmp(method,"OPTIONS")==0) {
        const char *h="HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
        send(sock, h, strlen(h), 0); return;
    }

    if (strcmp(method,"GET")==0 && (strcmp(path,"/")==0||strcmp(path,"/index.html")==0)) {
        send_response(sock, 200, "text/html; charset=utf-8",
                      HTML, (int)strlen(HTML));
        return;
    }

    if (strcmp(path,"/api/state")==0) {
        static char jbuf[32768];
        int jlen = json_state(jbuf, sizeof(jbuf));
        send_response(sock, 200, "application/json", jbuf, jlen);
        return;
    }

    char rbuf[256];

    if (strcmp(path,"/api/create")==0) {
        char name[MAX_NAME]={0};
        json_str(body, "name", name, MAX_NAME);
        int pid = api_create(name);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"pid\":%d}",pid);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/terminate")==0) {
        int pid = json_int(body,"pid",-1);
        int ok = api_terminate(pid);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":%d}",ok==0?1:0);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/alloc")==0) {
        int pid = json_int(body,"pid",-1);
        int nb  = json_int(body,"n",1);
        if(nb<1) nb=1; if(nb>20) nb=20;
        int out[20];
        int got = api_alloc(pid, nb, out);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"got\":%d}",got>0?got:0);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/dealloc")==0) {
        int pid  = json_int(body,"pid",-1);
        int addr = json_int(body,"addr",-1);
        int ok = api_dealloc(pid, addr);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":%d}",ok==0?1:0);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/read")==0) {
        int pid  = json_int(body,"pid",-1);
        int addr = json_int(body,"addr",-1);
        int r = api_read(pid, addr);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":%d,\"viol\":%d}",r==0?1:0,r==-2?1:0);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/write")==0) {
        int pid  = json_int(body,"pid",-1);
        int addr = json_int(body,"addr",-1);
        int val  = json_int(body,"val",0);
        int r = api_write(pid, addr, (unsigned char)val);
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":%d,\"viol\":%d}",r==0?1:0,r==-2?1:0);
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/demo")==0) {
        api_run_demo();
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":1}");
        send_response(sock,200,"application/json",rbuf,rlen);

    } else if (strcmp(path,"/api/reset")==0) {
        mm_init();
        int rlen = snprintf(rbuf,sizeof(rbuf),"{\"ok\":1}");
        send_response(sock,200,"application/json",rbuf,rlen);

    } else {
        send_response(sock,404,"text/plain","Not found",9);
    }
}

/* ════════════════════════════════════════════════════
   MAIN
   ════════════════════════════════════════════════════ */

int main(void) {
    srand((unsigned int)time(NULL));
    mm_init();

#ifdef _WIN32
    WSADATA wd;
    WSAStartup(MAKEWORD(2,2),&wd);
#endif

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PORT);

    if (bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0) {
        perror("bind"); return 1;
    }
    listen(srv, 10);

    printf("\n");
    printf("  +---------------------------------------+\n");
    printf("  |   Memory Isolation Lab                |\n");
    printf("  |   CSE-316 . OS Security Simulation    |\n");
    printf("  +---------------------------------------+\n");
    printf("  |                                       |\n");
    printf("  |   Open in your browser:               |\n");
    printf("  |   http://localhost:%d               |\n", PORT);
    printf("  |                                       |\n");
    printf("  |   Press Ctrl+C to stop the server.    |\n");
    printf("  |                                       |\n");
    printf("  +---------------------------------------+\n\n");

#ifdef _WIN32
    system("start http://localhost:8080");
#elif __APPLE__
    system("open http://localhost:8080");
#else
    system("xdg-open http://localhost:8080 2>/dev/null || true");
#endif

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv,(struct sockaddr*)&client,&clen);
        if (csock < 0) continue;
        handle(csock);
        close(csock);
    }
    return 0;
}
