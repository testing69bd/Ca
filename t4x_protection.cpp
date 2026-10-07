// t4x_core.cpp — Ultimate Hardened Enterprise Native Engine || Architecture: ARM64 / AArch64 (Direct SVC + Multi-Layer Anti-Tamper) || Targets: Anti-Debug, Anti-Frida, Anti-Hook, Anti-Root, Signature Lock
#include <android/fdsan.h>
#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/system_properties.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <elf.h>
#include <atomic>
#include <android/log.h>

// 0. CONFIGURATION LAYER (App-Specific Hardening Target)
// --- Per-build obfuscation seed // Override via -DT4_BUILD_SEED=0x.... per release build so every APK // variant carries a different keystream (defeats a single shared // decryptor script working across all your builds/releases).
#ifndef T4_BUILD_SEED
#define T4_BUILD_SEED 0x9E3779B97F4A7C15ULL
#endif
//constexpr unsigned char XK = 0xB3; // legacy byte, kept only for layout compat

// Multiplicative, seed-mixed keystream instead of a flat "XK + i" ramp. // A fixed-add keystream is recoverable in bulk with one script across every // string in the binary; splitmix64-derived bytes are not linear in i, so an // attacker has to defeat the derivation per-build, not just subtract a known // constant. This still isn't "unbreakable" -- it's reachable at runtime by // definition -- it just stops casual `strings`/bulk-XOR extraction.
constexpr uint64_t t4_mix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}
constexpr unsigned char t4_ks(size_t i) {
    return (unsigned char)(t4_mix64((uint64_t)T4_BUILD_SEED + i * 0x2545F4914F6CDD1DULL) & 0xFF);
}

template <size_t N>
struct Xe {
    char d[N];
    constexpr Xe(const char (&s)[N]) : d{} {
        for (size_t i = 0; i < N; i++)
            d[i] = (char)((unsigned char)s[i] ^ t4_ks(i));
    }
};

struct Xd {
    char b[256];
    template <size_t N>
    Xd(const Xe<N> &e) : b{} {
        for (size_t i = 0; i < N; i++)
            b[i] = (char)((unsigned char)e.d[i] ^ t4_ks(i));
    }
    ~Xd() {
        volatile char *p = b;
        for (size_t i = 0; i < sizeof(b); i++) p[i] = 0;
    }
    operator const char *() const { return b; }
};

#define XS(s) ((const char *)(Xd(Xe(s))))

// লক্ষিত প্যাকেজ নেম (এনক্রিপ্টেড)
static constexpr auto CFG_TARGET_PACKAGE = Xe("com.example.whiteapp");

// APK রিলিজ সাইনিং সার্টিফিকেটের ৩২-বাইট SHA-256 হ্যাশ (বাইট অ্যারে)
// তোমার আসল রিলিজ কি-এর SHA-256 হ্যাশ দিয়ে এই ৩২টি বাইট রিপ্লেস করে নিবে:
// APK রিলিজ সাইনিং সার্টিফিকেটের ৩২-বাইট SHA-256 হ্যাশ (বাইট অ্যারে)
static const uint8_t CFG_TARGET_CERT_SHA256[32] = {
    0xEA, 0x7D, 0xCF, 0x29, 0x1D, 0x74, 0xB3, 0x7A,
    0x72, 0x1A, 0xBA, 0x8C, 0xC5, 0x6C, 0x9E, 0xC9,
    0xE8, 0x3B, 0xFD, 0x12, 0x0B, 0x94, 0xDB, 0x17,
    0x31, 0xA6, 0x7F, 0x68, 0xC2, 0x57, 0xAC, 0x59
};

typedef int (*set_fdsan_fn)(int);
static set_fdsan_fn g_set_fdsan_level = nullptr;
static std::atomic<bool> g_fdsan_resolved{false};

static void disable_fdsan() {
    void *lib = dlopen("libc.so", RTLD_NOLOAD);
    if (!lib) lib = dlopen("libc.so", RTLD_NOW);
    if (lib) {
        typedef void (*set_level_fn)(int);
        set_level_fn set_level = (set_level_fn)dlsym(lib, "android_fdsan_set_error_level");
        if (set_level) {
            set_level(0); // ANDROID_FDSAN_ERROR_LEVEL_DISABLED
        }
        dlclose(lib);
    }
}


// 1. EMBEDDED SHA-256 ENGINE (External Dependency Free)

struct T4_SHA256_CTX {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
};

#define T4_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define T4_Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define T4_Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define T4_S0(x) (T4_ROR(x, 2) ^ T4_ROR(x, 13) ^ T4_ROR(x, 22))
#define T4_S1(x) (T4_ROR(x, 6) ^ T4_ROR(x, 11) ^ T4_ROR(x, 25))
#define T4_s0(x) (T4_ROR(x, 7) ^ T4_ROR(x, 18) ^ ((x) >> 3))
#define T4_s1(x) (T4_ROR(x, 17) ^ T4_ROR(x, 19) ^ ((x) >> 10))

static const uint32_t T4_K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void t4_sha256_transform(T4_SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    for (int i = 16; i < 64; i++)
        w[i] = T4_s1(w[i - 2]) + w[i - 7] + T4_s0(w[i - 15]) + w[i - 16];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + T4_S1(e) + T4_Ch(e, f, g) + T4_K256[i] + w[i];
        uint32_t t2 = T4_S0(a) + T4_Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void t4_sha256_init(T4_SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void t4_sha256_update(T4_SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0, idx = (ctx->count >> 3) & 63;
    ctx->count += (uint64_t)len << 3;
    size_t partLen = 64 - idx;
    if (len >= partLen) {
        memcpy(&ctx->buffer[idx], data, partLen);
        t4_sha256_transform(ctx, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64)
            t4_sha256_transform(ctx, &data[i]);
        idx = 0;
    }
    memcpy(&ctx->buffer[idx], &data[i], len - i);
}

static void t4_sha256_final(T4_SHA256_CTX *ctx, uint8_t hash[32]) {
    static const uint8_t pad[64] = { 0x80 };
    uint8_t bits[8];
    for (int i = 0; i < 8; i++)
        bits[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 0xFF);
    size_t idx = (ctx->count >> 3) & 63;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    t4_sha256_update(ctx, pad, padLen);
    t4_sha256_update(ctx, bits, 8);
    for (int i = 0; i < 8; i++) {
        hash[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8)  & 0xFF);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
}

static bool safe_mem_cmp(const void *a, const void *b, size_t n) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (pa[i] ^ pb[i]);
    return (diff == 0);
}
// 2. DIRECT SYSCALL ENGINE (L0: AArch64 SVC Raw Calls)

#if defined(__aarch64__)
static inline long rs(long n, long a = 0, long b = 0, long c = 0,
                      long d = 0, long e = 0, long f = 0) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    register long x5 asm("x5") = f;
    asm volatile("svc #0" : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory", "cc");
    return x0;
}
#else
static inline long rs(long n, long a = 0, long b = 0, long c = 0,
                      long d = 0, long e = 0, long f = 0) {
    long r = syscall(n, a, b, c, d, e, f);
    return (r == -1 && errno) ? -errno : r;
}
#endif

static long r_open(const char *p, long fl)         { return rs(__NR_openat, AT_FDCWD, (long)p, fl); }
static long r_read(long fd, void *b, long n)       { return rs(__NR_read, fd, (long)b, n); }
static long r_write(long fd, const void *b, long n){ return rs(__NR_write, fd, (long)b, n); }
static long r_close(long fd)                       { return rs(__NR_close, fd); }
static long r_kill(long pid, long sig)             { return rs(__NR_kill, pid, sig); }
static long r_getpid()                             { return rs(__NR_getpid); }
static long r_getppid()                            { return rs(__NR_getppid); }
static long r_faccessat(const char *p)             { return rs(__NR_faccessat, AT_FDCWD, (long)p, F_OK); }
static long r_getdents(long fd, void *b, long n)   { return rs(__NR_getdents64, fd, (long)b, n); }
static long r_ptrace(long rq, long pid, long a, long d) { return rs(__NR_ptrace, rq, pid, a, d); }
static long r_wait4(long pid, int *st, long o)     { return rs(__NR_wait4, pid, (long)st, o, 0); }
static long r_prctl(long o, long v)                { return rs(__NR_prctl, o, v); }
static long r_fork()                               { return rs(__NR_clone, SIGCHLD, 0, 0, 0, 0, 0); }
static long r_socket(long d, long t, long p)       { return rs(__NR_socket, d, t, p); }
static long r_connect(long fd, const void *sa, long l) { return rs(__NR_connect, fd, (long)sa, l); }
static long r_pipe2(int *fds, long fl) { return rs(__NR_pipe2, (long)fds, fl); }
[[noreturn]] static void r_exit(long c)            { rs(__NR_exit_group, c); for (;;) {} }

static long r_clock_ms() {
    struct timespec ts {};
    rs(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void r_sleep_ms(long ms) {
    struct timespec ts { ms / 1000, (ms % 1000) * 1000000L };
    rs(__NR_nanosleep, (long)&ts, 0);
}


// 3. DEFENSE AND DEFERRED TERMINATION ENGINE


static long g_pid = 0;
static std::atomic<int> g_hits{0};
static std::atomic<long> g_kill_at{0};
static unsigned g_rng = 0x6D2B79F5u;
static JavaVM *g_jvm = nullptr;

static unsigned xr() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static void threat() {
    g_hits.fetch_add(1, std::memory_order_relaxed);
    long now = r_clock_ms();
    long want = now + 800 + (long)(xr() % 1500); // ৮০০ms - ২.৩ সেকেন্ডের মধ্যে নিশ্চিত কিল
    long cur = g_kill_at.load(std::memory_order_relaxed);
    
    // যদি টাইমার আগে সেট না থাকে অথবা নতুন ডেডলাইন আরও দ্রুত হয়, তখনই সেট হবে
    if (cur == 0 || want < cur) {
        g_kill_at.store(want, std::memory_order_relaxed);
    }
}


// 3b. INTEGRITY-GATED RUNTIME KEY

// IMPORTANT ARCHITECTURAL NOTE: every check above this point only flips a// flag. A single patched branch (one `cbz`/`b` NOP) defeats a flag-based// gate completely, regardless of how many checks feed it. The fix is to// stop gating with a boolean and instead derive a key material value that// your *real* sensitive logic needs to function correctly://   - decrypt critical strings/config/license data//   - compute an HMAC the server checks before accepting a request//   - unlock a code path (not just "run or don't run" -- produce wrong//     output silently if checks fail, which is far harder to notice and//     patch around than a crash)// g_ikey only comes out correct if every sweep has been passing since// init. A hooked/patched check doesn't just fail to detect -- it corrupts// the key your app actually needs, so "bypass" requires reproducing the// correct key material, not just suppressing a kill call.
static std::atomic<uint64_t> g_ikey{0};

static void fold_key(bool check_passed, uint64_t salt) {
    uint64_t cur = g_ikey.load(std::memory_order_relaxed);
    uint64_t next = check_passed
        ? t4_mix64(cur ^ salt)
        : t4_mix64(cur ^ salt ^ 0xFFFFFFFFFFFFFFFFULL); // divergent, not zero/obvious
    g_ikey.store(next, std::memory_order_relaxed);
}

// Call this once after your real checks have run (see run_sweep) to get a// value you can XOR sensitive runtime data against. Treat it as "the key// is only right if history has been clean" -- do NOT branch on it with a// simple == comparison anywhere an attacker can find and patch; USE it as// key material in an actual decrypt/HMAC operation instead.
static uint64_t runtime_key() { return g_ikey.load(std::memory_order_relaxed); }

[[noreturn]] static void terminate_now() {
    // Several independent kill mechanisms: a crash-prone null-page write, a
    // signal to self, a direct syscall exit, and an abort via libc as a
    // fourth path. A patch that defeats any one of these (e.g. mapping the
    // low page so the null-deref stops crashing) still leaves the others
    // live -- there's no single branch an attacker can NOP to survive all
    // four. This still isn't foolproof: an attacker who fully controls
    // execution can trap/suppress all of them with enough effort, same as
    // with any client-side kill switch.
    *(volatile uint32_t *)(uintptr_t)(xr() & 7) = 0;
    r_kill(g_pid, SIGSEGV);
    r_kill(g_pid, SIGKILL);
    abort();
    r_exit(9);
}

// 4. LOW-LEVEL INSPECTION UTILITIES
static long slurp(const char *path, char *buf, long cap) {
    long fd = r_open(path, O_RDONLY);
    if (fd < 0) return -1;
    long t = 0, r;
    while (t < cap - 1 && (r = r_read(fd, buf + t, cap - 1 - t)) > 0) t += r;
    r_close(fd);
    if (t <= 0) return -1;
    buf[t] = 0;
    return t;
}

static uint64_t fnv1a(const void *p, size_t n) {
    const unsigned char *b = (const unsigned char *)p;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

static char *put_s(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *put_u(char *p, unsigned long v) {
    char t[24]; int i = 0;
    do { t[i++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (i) *p++ = t[--i];
    return p;
}

static const char *memfind(const char *h, size_t hn, const char *n, size_t nn) {
    if (!nn) return h;
    for (size_t i = 0; i + nn <= hn; i++)
        if (h[i] == n[0] && !memcmp(h + i, n, nn)) return h + i;
    return nullptr;
}

template <size_t N>
static char *find_enc(char *hay, size_t hn, const char (&enc)[N]) {
    char nd[N];
    for (size_t i = 0; i < N; i++)
        nd[i] = (char)((unsigned char)enc[i] ^ t4_ks(i));
    const char *p = memfind(hay, hn, nd, N - 1);
    volatile char *w = nd; for (size_t i = 0; i < N; i++) w[i] = 0;
    return (char *)(uintptr_t)p;
}

template <size_t N>
static bool fexists_enc(const char (&enc)[N]) {
    char p[N];
    for (size_t i = 0; i < N; i++)
        p[i] = (char)((unsigned char)enc[i] ^ t4_ks(i));
    long r = r_faccessat(p);
    volatile char *w = p; for (size_t i = 0; i < N; i++) w[i] = 0;
    return r == 0;
}

// 5. PACKAGE & SIGNATURE INTEGRITY CHECKS
static bool verify_process_name_native() {
    char cmd[128] = {0};
    long n = slurp(XS("/proc/self/cmdline"), cmd, sizeof(cmd));
    if (n <= 0) return false;

    Xd expected(CFG_TARGET_PACKAGE);
    size_t exp_len = strlen(expected);
    if ((size_t)n < exp_len) return false;
    if (memcmp(cmd, (const char *)expected, exp_len) != 0) return false;

    char term = cmd[exp_len];
    return (term == '\0' || term == ':');
}

static bool verify_app_signature_jni(JNIEnv *env, jobject context) {
    if (!env || !context) return false;

    // ১. JNI দিয়ে Context.getPackageName() যাচাই
    jclass context_cls = env->GetObjectClass(context);
    jmethodID mid_get_pkg = env->GetMethodID(context_cls, XS("getPackageName"), XS("()Ljava/lang/String;"));
    if (!mid_get_pkg || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jstring j_pkg = (jstring)env->CallObjectMethod(context, mid_get_pkg);
    if (!j_pkg || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    const char *pkg_chars = env->GetStringUTFChars(j_pkg, nullptr);
    Xd expected_pkg(CFG_TARGET_PACKAGE);
    bool pkg_valid = (pkg_chars && strcmp(pkg_chars, expected_pkg) == 0);
    if (pkg_chars) env->ReleaseStringUTFChars(j_pkg, pkg_chars);
    if (!pkg_valid) return false;


// ApplicationInfo থেকে dataDir বের করে পাথ ভ্যালিডেশন
    // ApplicationInfo থেকে dataDir বের করে ভার্চুয়াল স্পেস পাথ ভ্যালিডেশন
    jmethodID mid_get_ai = env->GetMethodID(context_cls, XS("getApplicationInfo"), XS("()Landroid/content/pm/ApplicationInfo;"));
    if (mid_get_ai && !env->ExceptionCheck()) {
        jobject ai = env->CallObjectMethod(context, mid_get_ai);
        if (ai && !env->ExceptionCheck()) {
            jclass ai_cls = env->GetObjectClass(ai);
            jfieldID fid_dd = env->GetFieldID(ai_cls, XS("dataDir"), XS("Ljava/lang/String;"));
            if (fid_dd && !env->ExceptionCheck()) {
                jstring j_dd = (jstring)env->GetObjectField(ai, fid_dd);
                if (j_dd && !env->ExceptionCheck()) {
                    const char *dd = env->GetStringUTFChars(j_dd, nullptr);
                    if (dd) {
                        //Xd expected_pkg(CFG_TARGET_PACKAGE);
                        // ক্লোনারে ডেটা পাথে /virtual/ থাকে অথবা নিজস্ব প্যাকেজ নাম থাকে না
                        if (strstr(dd, XS("/virtual/")) != nullptr || strstr(dd, (const char *)expected_pkg) == nullptr) {
                            env->ReleaseStringUTFChars(j_dd, dd);
                            return false; // Virtual Space Detected!
                        }
                        env->ReleaseStringUTFChars(j_dd, dd);
                    }
                } else {
                    env->ExceptionClear();
                }
            } else {
                env->ExceptionClear();
            }
        } else {
            env->ExceptionClear();
        }
    } else {
        env->ExceptionClear();
    }



    // ২. PackageManager থেকে সার্টিফিকেট বের করা
    jmethodID mid_get_pm = env->GetMethodID(context_cls, XS("getPackageManager"), XS("()Landroid/content/pm/PackageManager;"));
    if (!mid_get_pm || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jobject pm = env->CallObjectMethod(context, mid_get_pm);
    if (!pm || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jclass pm_cls = env->GetObjectClass(pm);
    jfieldID fid_flags = env->GetStaticFieldID(pm_cls, XS("GET_SIGNING_CERTIFICATES"), XS("I"));
    jint flags = 0;
    bool use_signing_info = false;

    if (env->ExceptionCheck() || !fid_flags) {
        env->ExceptionClear();
        flags = 0x00000040; // GET_SIGNATURES (API < 28 Fallback)
    } else {
        flags = env->GetStaticIntField(pm_cls, fid_flags);
        use_signing_info = true;
    }

    jmethodID mid_get_pkg_info = env->GetMethodID(pm_cls, XS("getPackageInfo"), XS("(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"));
    if (!mid_get_pkg_info || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jobject pkg_info = env->CallObjectMethod(pm, mid_get_pkg_info, j_pkg, flags);
    if (!pkg_info || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }

    jclass pkg_info_cls = env->GetObjectClass(pkg_info);
    jbyteArray cert_bytes_arr = nullptr;

    if (use_signing_info) {
        jfieldID fid_signing_info = env->GetFieldID(pkg_info_cls, XS("signingInfo"), XS("Landroid/content/pm/SigningInfo;"));
        if (!env->ExceptionCheck() && fid_signing_info) {
            jobject signing_info = env->GetObjectField(pkg_info, fid_signing_info);
            if (signing_info) {
                jclass si_cls = env->GetObjectClass(signing_info);
                jmethodID mid_has_multi = env->GetMethodID(si_cls, XS("hasMultipleSigners"), XS("()Z"));
                jboolean multi = false;
                if (mid_has_multi && !env->ExceptionCheck()) {
                    multi = env->CallBooleanMethod(signing_info, mid_has_multi);
                }

                // Lifetime Safe Direct JNI Call
                jmethodID mid_get_sigs = multi
                    ? env->GetMethodID(si_cls, XS("getApkContentsSigners"), XS("()[Landroid/content/pm/Signature;"))
                    : env->GetMethodID(si_cls, XS("getSigningCertificateHistory"), XS("()[Landroid/content/pm/Signature;"));

                if (mid_get_sigs && !env->ExceptionCheck()) {
                    jobjectArray sigs = (jobjectArray)env->CallObjectMethod(signing_info, mid_get_sigs);
                    if (sigs && env->GetArrayLength(sigs) > 0) {
                        jobject sig = env->GetObjectArrayElement(sigs, 0);
                        if (sig) {
                            jclass sig_cls = env->GetObjectClass(sig);
                            jmethodID mid_to_byte = env->GetMethodID(sig_cls, XS("toByteArray"), XS("()[B"));
                            if (mid_to_byte && !env->ExceptionCheck()) {
                                cert_bytes_arr = (jbyteArray)env->CallObjectMethod(sig, mid_to_byte);
                            }
                        }
                    }
                } else {
                    env->ExceptionClear();
                }
            }
        } else {
            env->ExceptionClear();
        }
    }

    // Fallback: Legacy Signatures (Android 8 ও এর পূর্বের জন্য)
    if (!cert_bytes_arr) {
        jfieldID fid_sigs = env->GetFieldID(pkg_info_cls, XS("signatures"), XS("([Landroid/content/pm/Signature;)"));
        if (!env->ExceptionCheck() && fid_sigs) {
            jobjectArray sigs = (jobjectArray)env->GetObjectField(pkg_info, fid_sigs);
            if (sigs && env->GetArrayLength(sigs) > 0) {
                jobject sig = env->GetObjectArrayElement(sigs, 0);
                if (sig) {
                    jclass sig_cls = env->GetObjectClass(sig);
                    jmethodID mid_to_byte = env->GetMethodID(sig_cls, XS("toByteArray"), XS("()[B"));
                    if (mid_to_byte && !env->ExceptionCheck()) {
                        cert_bytes_arr = (jbyteArray)env->CallObjectMethod(sig, mid_to_byte);
                    }
                }
            }
        } else {
            env->ExceptionClear();
        }
    }

    if (!cert_bytes_arr) return false;

    // ৩. মেমোরিতে সরাসরি DER সার্টিফিকেটের SHA-256 গণনা
    jsize len = env->GetArrayLength(cert_bytes_arr);
    jbyte *raw = env->GetByteArrayElements(cert_bytes_arr, nullptr);
    if (!raw) return false;

    T4_SHA256_CTX sha_ctx;
    uint8_t computed_hash[32];
    t4_sha256_init(&sha_ctx);
    t4_sha256_update(&sha_ctx, (const uint8_t *)raw, (size_t)len);
    t4_sha256_final(&sha_ctx, computed_hash);

    env->ReleaseByteArrayElements(cert_bytes_arr, raw, JNI_ABORT);

    // ৪. হার্ডকোডেড SHA-256 হ্যাশের সাথে মিল যাচাই
    return safe_mem_cmp(computed_hash, CFG_TARGET_CERT_SHA256, 32);
}
// 6. CORE SECURITY INSPECTORS
static long g_guard_child = 0;
static std::atomic<int> g_guard_on{0};
static long g_guard_pipe = -1;
static constexpr auto XN_tp = Xe("TracerPid:");

static bool tracer_clean() {
    char b[8192];
    long n = slurp(XS("/proc/self/status"), b, sizeof b);
    if (n <= 0) return true;
    char *p = find_enc(b, (size_t)n, XN_tp.d);
    if (!p) return true;
    long tp = strtol(p + 10, nullptr, 10);
    if (tp == 0) return true; // কোনো ট্রেসার নেই -> ক্লিন
    if (g_guard_on.load() && tp == g_guard_child) return true; // আমাদের নিজস্ব গার্ড চাইল্ড -> বৈধ
    return false; // বাইরের কোনো ডিবাগার -> থ্রেট!
}

static constexpr auto XM_frida   = Xe("frida");
static constexpr auto XM_gadget  = Xe("gadget");
static constexpr auto XM_linj    = Xe("linjector");
static constexpr auto XM_xposed  = Xe("xposed");
static constexpr auto XM_lsp     = Xe("lsposed");
static constexpr auto XM_edxp    = Xe("edxp");
static constexpr auto XM_riru    = Xe("riru");
static constexpr auto XM_zygisk  = Xe("zygisk");
static constexpr auto XM_sub     = Xe("substrate");
static constexpr auto XM_dobby   = Xe("dobby");
static constexpr auto XM_shk     = Xe("shadowhook");
static constexpr auto XM_bhook   = Xe("bytehook");
static constexpr auto XM_mag     = Xe("magisk");
static constexpr auto XM_fagent  = Xe("frida-agent");
static constexpr auto XM_fsrv    = Xe("re.frida.server");
static constexpr auto XM_fhelp   = Xe("frida-helper");
static constexpr auto XM_fhook   = Xe("whale");
// --- Purono XM_houdini er pashe egulo add koro ---
static constexpr auto XM_houdini = Xe("houdini");
static constexpr auto XM_ndk     = Xe("libndk_translation");
//static constexpr auto XM_nb      = Xe("native_bridge");
// Signature Killers
static constexpr auto XM_sigkill1 = Xe("SignatureKiller");
static constexpr auto XM_sigkill2 = Xe("signaturekiller");
static constexpr auto XM_sigkill3 = Xe("kill_sig");
static constexpr auto XM_sigkill4 = Xe("fakesig");
static constexpr auto XM_np       = Xe("libnp.so");
static constexpr auto XM_corep    = Xe("corepatch");
static constexpr auto XM_chelp    = Xe("chelpus");
// Emulator Device Pipes & Drivers
static constexpr auto XD_pipe1   = Xe("/dev/qemu_pipe");
static constexpr auto XD_pipe2   = Xe("/dev/goldfish_pipe");
static constexpr auto XD_vbox    = Xe("/dev/vboxguest");
// CPU ও কার্নেল চেকের স্ট্রিং
static constexpr auto XC_intel  = Xe("GenuineIntel");
static constexpr auto XC_amd    = Xe("AuthenticAMD");
static constexpr auto XK_qemu   = Xe("qemu");
static constexpr auto XK_vbox   = Xe("vbox");
//static constexpr auto XK_kvm    = Xe("kvm");
static constexpr auto XK_ranchu = Xe("ranchu");
static constexpr auto XK_droid  = Xe("droid4x");
static constexpr auto XK_nox    = Xe("nox");
static constexpr auto XK_ttvm   = Xe("ttVM");
// Virtual-Space / App-Cloner Signatures
static constexpr auto XV_va       = Xe("io.va.");            // VirtualApp Core
static constexpr auto XV_chaos    = Xe("com.by.chaos");     // VirtualApp Variant
static constexpr auto XV_parallel = Xe("com.lbe.parallel"); // Parallel Space
static constexpr auto XV_dualaid  = Xe("com.excelliance."); // MultiAccount / DualAid
static constexpr auto XV_dual     = Xe("com.ludashi.dualspace"); // Dual Space
static constexpr auto XV_vmos     = Xe("com.vmos");         // VMOS Package
static constexpr auto XV_vphone   = Xe("com.vphonegaga");   // VPhoneGaGa
static constexpr auto XV_f1       = Xe("com.f1player");     // F1 VM
static constexpr auto XV_blackbox = Xe("blackbox");         // BlackBox Engine
static constexpr auto XV_sandhook = Xe("sandhook");         // Virtual Hook Engine
static constexpr auto XV_virtual  = Xe("/virtual/");        // VA Redirected PATH 
// Virtual Master / Mini-VM Markers
static constexpr auto XV_vmast1   = Xe("com.bumo.vm");        // Virtual Master Package
static constexpr auto XV_vmast2   = Xe("vmaster");            // Virtual Master Native Lib
static constexpr auto XV_vmast3   = Xe("virtualmaster");

// APK Path Verification Markers
static constexpr auto XP_baseapk  = Xe("base.apk");
static constexpr auto XP_ddata    = Xe("/data/data/");
static constexpr auto XP_duser    = Xe("/data/user/");



static bool maps_clean() {
    long fd = r_open(XS("/proc/self/maps"), O_RDONLY);
    if (fd < 0) return true;

    char buf[4096];
    char line[1024];
    size_t line_idx = 0;
    bool clean = true;
    long bytes_read = 0;

    // Fast 4KB chunked stream — 200KB+ maps file-o bina frame-drop e scan hobe
    while ((bytes_read = r_read(fd, buf, sizeof(buf))) > 0) {
        for (long i = 0; i < bytes_read; i++) {
            char ch = buf[i];
            if (ch == '\n' || line_idx >= sizeof(line) - 1) {
                line[line_idx] = '\0';
                
                // Emulator & Translation Checks
                 if (find_enc(line, line_idx, XM_houdini.d) ||
                    find_enc(line, line_idx, XM_ndk.d)     ||
                   // find_enc(line, line_idx, XM_nb.d)      ||
                    find_enc(line, line_idx, XM_frida.d)   ||
                    find_enc(line, line_idx, XM_gadget.d)  ||
                    find_enc(line, line_idx, XM_linj.d)    ||
                    find_enc(line, line_idx, XM_xposed.d)  ||
                    find_enc(line, line_idx, XM_lsp.d)     ||
                    find_enc(line, line_idx, XM_edxp.d)    ||
                    find_enc(line, line_idx, XM_riru.d)    ||
                    find_enc(line, line_idx, XM_zygisk.d)  ||
                    find_enc(line, line_idx, XM_sub.d)     ||
                    find_enc(line, line_idx, XM_dobby.d)   ||
                    find_enc(line, line_idx, XM_shk.d)     ||
                    find_enc(line, line_idx, XM_bhook.d)   ||
                    find_enc(line, line_idx, XM_mag.d)     ||
                    find_enc(line, line_idx, XM_fagent.d)  ||
                    find_enc(line, line_idx, XM_fsrv.d)    ||
                    find_enc(line, line_idx, XM_fhelp.d)   ||
                    find_enc(line, line_idx, XM_fhook.d)   ||
                    find_enc(line, line_idx, XM_sigkill1.d)||
                    find_enc(line, line_idx, XM_sigkill2.d)||
                    find_enc(line, line_idx, XM_sigkill3.d)||
                    find_enc(line, line_idx, XM_sigkill4.d)||
                    find_enc(line, line_idx, XM_np.d)      ||
                    find_enc(line, line_idx, XM_corep.d)   ||
                    find_enc(line, line_idx, XM_chelp.d)  ||
                    // maps_clean() এর find_enc চেকের ভেতরে এগুলো যুক্ত করো:
                    find_enc(line, line_idx, XV_va.d)       ||
                    find_enc(line, line_idx, XV_chaos.d)    ||
                    find_enc(line, line_idx, XV_parallel.d) ||
                    find_enc(line, line_idx, XV_dualaid.d)  ||
                    find_enc(line, line_idx, XV_dual.d)     ||
                    find_enc(line, line_idx, XV_vmos.d)     ||
                    find_enc(line, line_idx, XV_vphone.d)   ||
                    find_enc(line, line_idx, XV_f1.d)       ||
                    find_enc(line, line_idx, XV_blackbox.d) ||
                    find_enc(line, line_idx, XV_sandhook.d) ||
                    find_enc(line, line_idx, XV_vmast1.d)   ||
                    find_enc(line, line_idx, XV_vmast2.d)   ||
                    find_enc(line, line_idx, XV_vmast3.d)   ||
                    find_enc(line, line_idx, XV_virtual.d))  {
                    clean = false;
                    break;
                }
                line_idx = 0;
            } else {
                line[line_idx++] = ch;
            }
        }
        if (!clean) break;
    }
    r_close(fd);
    return clean;
}

// কার্নেল রিপোর্টেড base.apk পাথ যাচাই (Zero False-Positive)
static bool apk_path_clean() {
    long fd = r_open(XS("/proc/self/maps"), O_RDONLY);
    if (fd < 0) return true;

    char buf[4096];
    char line[1024];
    size_t li = 0;
    long br;
    bool clean = true;

    while (clean && (br = r_read(fd, buf, sizeof(buf))) > 0) {
        for (long i = 0; i < br; i++) {
            char ch = buf[i];
            if (ch == '\n' || li >= sizeof(line) - 1) {
                line[li] = '\0';
                
                // base.apk ক্লোনারে থাকলে /data/data/ বা /data/user/-এ ম্যাপ হয়
                if (find_enc(line, li, XP_baseapk.d)) {
                    if (find_enc(line, li, XP_ddata.d) || find_enc(line, li, XP_duser.d)) {
                        clean = false;
                        break;
                    }
                }
                li = 0;
            } else {
                line[li++] = ch;
            }
        }
    }
    r_close(fd);
    return clean;
}



static bool emulator_clean() {
    // ১. Translation Bridge চেক (স্যামসাং ফোনে "0" বা খালি থাকে)
    char bridge[PROP_VALUE_MAX] = {0};
    __system_property_get(XS("ro.dalvik.vm.native.bridge"), bridge);
    if (bridge[0] != '\0' && strcmp(bridge, "0") != 0) {
        if (strstr(bridge, "houdini") || strstr(bridge, "ndk") || strstr(bridge, "bridge")) {
            return false;
        }
    }

    // ২. /proc/cpuinfo চেক (PC-এর Intel/AMD প্রসেসর)
    char cpu[4096];
    long cn = slurp(XS("/proc/cpuinfo"), cpu, sizeof(cpu));
    if (cn > 0) {
        if (find_enc(cpu, (size_t)cn, XC_intel.d) || find_enc(cpu, (size_t)cn, XC_amd.d)) {
            return false;
        }
    }

    // ৩. /proc/version চেক (নিশ্চিত এমুলেটর কার্নেল ব্যানার)
    char ver[1024];
    long vn = slurp(XS("/proc/version"), ver, sizeof(ver));
    if (vn > 0) {
        if (find_enc(ver, (size_t)vn, XK_qemu.d)   || find_enc(ver, (size_t)vn, XK_vbox.d) ||
            find_enc(ver, (size_t)vn, XK_ranchu.d) || find_enc(ver, (size_t)vn, XK_droid.d) ||
            find_enc(ver, (size_t)vn, XK_nox.d)    || find_enc(ver, (size_t)vn, XK_ttvm.d)) {
            return false;
        }
    }

    // ৪. পাইপ ড্রাইভার চেক
    if (fexists_enc(XD_pipe1.d) || fexists_enc(XD_pipe2.d) || fexists_enc(XD_vbox.d)) {
        return false;
    }

    // ৫. VMOS & Container ROM প্রপার্টিজ
    char vmos[PROP_VALUE_MAX] = {0};
    __system_property_get(XS("ro.vmos.version"), vmos);
    if (vmos[0] != '\0') return false;

    memset(vmos, 0, sizeof(vmos));
    __system_property_get(XS("ro.vphonegaga.version"), vmos);
    if (vmos[0] != '\0') return false;

    if (r_faccessat(XS("/dev/vmos")) == 0 || r_faccessat(XS("/dev/vphonegaga")) == 0) {
        return false;
    }

    // ৬. হার্ডওয়্যার প্রপার্টিজ
    char v[PROP_VALUE_MAX] = {0};
    __system_property_get(XS("ro.hardware"), v);
    if (strstr(v, XS("goldfish")) || strstr(v, XS("ranchu")) || strstr(v, XS("vbox86"))) return false;

    memset(v, 0, sizeof(v));
    __system_property_get(XS("ro.product.board"), v);
    if (strstr(v, XS("goldfish")) || strstr(v, XS("ranchu"))) return false;

    return true;
}

static bool root_clean() {
    char mounts[32768];
    long mn = slurp(XS("/proc/self/mountinfo"), mounts, sizeof(mounts));
    if (mn <= 0) mn = slurp(XS("/proc/mounts"), mounts, sizeof(mounts));
    if (mn > 0) {
        if (find_enc(mounts, (size_t)mn, XM_mag.d) || strstr(mounts, "/.magisk/") || strstr(mounts, "core/mirror")) {
            return false;
        }
    }

    const char *p = getenv("PATH");
    if (p) {
        char path_buf[512];
        const char *s = p;
        while (*s) {
            const char *e = strchr(s, ':');
            if (!e) e = s + strlen(s);
            size_t len = e - s;
            if (len + 4 < sizeof(path_buf)) {
                memcpy(path_buf, s, len);
                path_buf[len] = '/';
                path_buf[len + 1] = 's';
                path_buf[len + 2] = 'u';
                path_buf[len + 3] = '\0';
                if (r_faccessat(path_buf) == 0) return false;
            }
            if (*e == '\0') break;
            s = e + 1;
        }
    }
    
    // ৩. SELinux Enforcing চেক (আসল ফোনে সবসময় 1 থাকে, Virtual Master রুটে 0 থাকে)
    char se[8] = {0};
    long sfd = r_open(XS("/sys/fs/selinux/enforce"), O_RDONLY);
    if (sfd >= 0) {
       long sr = r_read(sfd, se, sizeof(se) - 1);
        r_close(sfd);
        if (sr > 0 && se[0] == '0') {
            return false; // Permissive SELinux -> Rooted Container / Custom ROM!
        }
    }

    // ৪. SuperSU / VM Root Daemons চেক
    if (r_faccessat(XS("/dev/socket/su-daemon")) == 0 ||
        r_faccessat(XS("/dev/socket/supersu_daemon")) == 0) {
        return false;
    }
    return true; 
    }



// --- /proc/self/stat trace-state check -------------------------------// TracerPid in /proc/self/status is the common check and the common// bypass target (many Frida/Xposed unpackers patch exactly this field// read). The process state char in /proc/self/stat ('t' = tracing stop,// field 3) is a second, independently-read signal that isn't defeated by// the same patch.
static bool trace_state_clean() {
    char b[512];
    long n = slurp(XS("/proc/self/stat"), b, sizeof b);
    if (n <= 0) return true;
    // Field 3 (after the ")" that closes the comm field) is process state.
    const char *p = (const char *)memchr(b, ')', (size_t)n);
    if (!p) return true;
    p += 2; // skip ") "
    if (p < b + n && *p == 't') return false;
    return true;
}

// --- Timing-based single-step / breakpoint detection -------------------// A debugger single-stepping through or sitting on a breakpoint inside a// tight, known-cost loop inflates its wall-clock time far beyond native// execution, independent of ptrace-attach detection (catches hardware// breakpoints and some anti-anti-debug tooling that spoofs TracerPid).// Thresholds are intentionally loose to avoid false positives on loaded// low-end devices; tune per your target hardware before shipping.
static bool timing_clean() {
    long t0 = r_clock_ms();
    volatile uint64_t acc = 0;
    for (volatile int i = 0; i < 2000000; i++) acc += (uint64_t)i * 2654435761u;
    long elapsed = r_clock_ms() - t0;
    (void)acc;
    return elapsed < 700; // native: low single-digit ms on any real device/emulator
}

static constexpr auto XT_gum   = Xe("gum-js-loop");
static constexpr auto XT_gmain = Xe("gmain");
static constexpr auto XT_gdb   = Xe("gdbus");
static constexpr auto XT_pool  = Xe("pool-frida");

static bool threads_clean() {
    static int sweep_skip = 0;
    if ((++sweep_skip % 5) != 0) return true; // প্রতি ৫ বারে একবার স্ক্যান হবে

    bool clean = true;
    long dfd = r_open(XS("/proc/self/task"), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return true;

    char pre[24], sfx[8];
    { Xd p1(Xe("/proc/self/task/")); Xd p2(Xe("/comm"));
      memcpy(pre, p1, strlen(p1) + 1); memcpy(sfx, p2, strlen(p2) + 1); }

    char db[4096];
    for (;;) {
        long n = r_getdents(dfd, db, sizeof db);
        if (n <= 0) break;
        for (long off = 0; off < n;) {
            unsigned short rl; memcpy(&rl, db + off + 16, 2);
            const char *nm = db + off + 19;
            off += rl;
            if (nm[0] < '0' || nm[0] > '9') continue;
            char path[96], *p = path;
            p = put_s(p, pre); p = put_s(p, nm); p = put_s(p, sfx); *p = 0;
            char comm[64];
            long cn = slurp(path, comm, sizeof comm);
            if (cn <= 0) continue;
            if (find_enc(comm, (size_t)cn, XT_gum.d)  || find_enc(comm, (size_t)cn, XT_gmain.d) ||
                find_enc(comm, (size_t)cn, XT_gdb.d)  || find_enc(comm, (size_t)cn, XT_pool.d)) {
                clean = false; break;
            }
        }
        if (!clean) break;
    }
    r_close(dfd);
    return clean;
}

static bool ports_clean() {
    char b[65536];
    long n = slurp(XS("/proc/net/tcp"), b, sizeof b);
    if (n <= 0) return true; // Android 10+ SELinux ব্লক করলে বাইপাস
    for (long i = 0; i < n;) {
        long e = i; while (e < n && b[e] != '\n') e++;
        const char *tok[6]; int tl[6]; int nt = 0; long s = i;
        for (long j = i; j <= e && nt < 6; j++) {
            if (j == e || b[j] == ' ' || b[j] == '\n') {
                if (j > s) { tok[nt] = b + s; tl[nt] = (int)(j - s); nt++; }
                s = j + 1;
            }
        }
        if (nt >= 4 && tl[1] >= 5 && tok[1][tl[1] - 5] == ':') {
            const char *port = tok[1] + tl[1] - 4;
            bool fport = (port[0]=='6' && port[1]=='9' && port[2]=='A' &&
                          (port[3]=='2' || port[3]=='3'));
            bool listen = (tl[3] == 2 && tok[3][0]=='0' && tok[3][1]=='A');
            if (fport && listen) return false;
        }
        i = e + 1;
    }
    return true;
}

static bool connect_clean() {
    struct sockaddr_in sa {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    long fd = r_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return true;
    long r = r_connect(fd, &sa, sizeof sa);
    r_close(fd);
    return !(r == 0 || r == -EINPROGRESS);
}

static constexpr auto XR1  = Xe("/system/bin/su");
static constexpr auto XR2  = Xe("/system/xbin/su");
static constexpr auto XR3  = Xe("/sbin/su");
static constexpr auto XR4  = Xe("/system/su");
static constexpr auto XR5  = Xe("/system/bin/.ext/.su");
static constexpr auto XR6  = Xe("/data/local/xbin/su");
static constexpr auto XR7  = Xe("/data/local/bin/su");
static constexpr auto XR8  = Xe("/data/local/su");
static constexpr auto XR9  = Xe("/sbin/.magisk");
static constexpr auto XR10 = Xe("/data/adb/magisk");
static constexpr auto XR11 = Xe("/data/adb/modules");
static constexpr auto XR12 = Xe("/system/app/Superuser.apk");
static constexpr auto XN_tk  = Xe("test-keys");
static constexpr auto XN_ldp = Xe("LD_PRELOAD");

static bool env_clean() {
    if (fexists_enc(XR1.d)||fexists_enc(XR2.d)||fexists_enc(XR3.d)||fexists_enc(XR4.d)||
        fexists_enc(XR5.d)||fexists_enc(XR6.d)||fexists_enc(XR7.d)||fexists_enc(XR8.d)||
        fexists_enc(XR9.d)||fexists_enc(XR10.d)||fexists_enc(XR11.d)||fexists_enc(XR12.d))
        return false;
    char v[PROP_VALUE_MAX] = {0};
    __system_property_get(XS("ro.build.tags"), v);
    if (find_enc(v, strlen(v), XN_tk.d)) return false;
    __system_property_get(XS("ro.debuggable"), v);
    if (v[0] == '1') return false;
    __system_property_get(XS("ro.kernel.qemu"), v);
    if (v[0] == '1') return false;
    char eb[16384];
    long en = slurp(XS("/proc/self/environ"), eb, sizeof eb);
    if (en > 0 && find_enc(eb, (size_t)en, XN_ldp.d)) return false;
    return true;
}

struct HW { void *fn; uint64_t h; };
static HW g_hw[5];
static int g_hwn = 0;

//No need,  unused
//static bool prologue_branchy(const void *fn) {
 //   uint32_t in; memcpy(&in, fn, 4);
//#if defined(__aarch64__)
//    if ((in & 0xFFFFFC00u) == 0xD61F0000u) return true;
 //   if ((in & 0xFC000000u) == 0x14000000u && (in & 0x03FFFFFFu)) return true;
 //   if ((in & 0xFC000000u) == 0x94000000u) return true;
//#elif defined(__arm__)
 //   if (in == 0xE51FF004u) return true;
    //if ((in & 0xFF000000u) == 0xEA000000u) return true;
//#endif
  //  return false;
//}

static void capture_hook_baselines() {
    const char *names[5] = {
        "open",
        "read",
        "mmap",
        "dlopen",
        "pthread_create"
    };

    for (int i = 0; i < 5; i++) {
        void *f = dlsym(RTLD_DEFAULT, names[i]);
        if (!f) continue;

        g_hw[g_hwn].fn = f;
        g_hw[g_hwn].h = fnv1a(f, 24);
        g_hwn++;
    }
}

static bool hooks_clean() {
    for (int i = 0; i < g_hwn; i++) {
        if (!g_hw[i].fn) continue;
        if (fnv1a(g_hw[i].fn, 24) != g_hw[i].h) return false;
    }
    return true;
}

static uintptr_t g_tx = 0;
static size_t g_tx_n = 0;
static uint64_t g_tx_h = 0;

static void capture_self_text() {
    Dl_info di;
    if (!dladdr((void *)&capture_self_text, &di) || !di.dli_fbase) return;
    char *base = (char *)di.dli_fbase;
#if __SIZEOF_POINTER__ == 8
    Elf64_Ehdr *e = (Elf64_Ehdr *)base;
    Elf64_Phdr *ph = (Elf64_Phdr *)(base + e->e_phoff);
#else
    Elf32_Ehdr *e = (Elf32_Ehdr *)base;
    Elf32_Phdr *ph = (Elf32_Phdr *)(base + e->e_phoff);
#endif
    for (int i = 0; i < e->e_phnum; i++, ph++) {
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            g_tx = (uintptr_t)base + ph->p_vaddr;
            g_tx_n = (size_t)ph->p_filesz;
            g_tx_h = fnv1a((void *)g_tx, g_tx_n);
            return;
        }
    }
}

static bool selftext_clean() {
    return !g_tx_h || fnv1a((void *)g_tx, g_tx_n) == g_tx_h;
}

// 7. PTRACE GUARD (FORKED MONITOR)
static void start_ptrace_guard() {
    int fds[2] = {-1, -1}; // [FIXED: ৩২-বিট int অ্যারে]
    if (r_pipe2(fds, 0) != 0) return;
    long c = r_fork();
    if (c < 0) { r_close(fds[0]); r_close(fds[1]); return; }

    if (c == 0) {
        r_close(fds[0]);
        long ppid = r_getppid();
        char verdict = 'K';
        {
            char st[4096], path[48];
            Xd p1(Xe("/proc/")), p2(Xe("/status"));
            char *p = put_s(path, p1);
            p = put_u(p, (unsigned long)ppid);
            put_s(p, p2); *p = 0;
            long n = slurp(path, st, sizeof st);
            if (n > 0) {
                char *t = find_enc(st, (size_t)n, XN_tp.d);
                if (t && strtol(t + 10, nullptr, 10) != 0) verdict = 'D';
            }
        }
        if (verdict == 'K') {
            long a = r_ptrace((long)PTRACE_SEIZE, ppid, 0, 0);
            if (a < 0) {
                a = r_ptrace((long)PTRACE_ATTACH, ppid, 0, 0);
                if (a == 0) {
                    int ws = 0; r_wait4(ppid, &ws, 0);
                    r_ptrace((long)PTRACE_CONT, ppid, 0, 0);
                }
            }
            if (a < 0) verdict = 'E';
        }
        r_write(fds[1], &verdict, 1);
        r_close(fds[1]);
        if (verdict != 'K') r_exit(0);

        for (;;) {
            int ws = 0;
            long w = r_wait4(ppid, &ws, __WALL | WNOHANG);
            if (w == ppid) {
                if (WIFEXITED(ws) || WIFSIGNALED(ws)) r_exit(0);
                if (WIFSTOPPED(ws)) {
                    long sg = WSTOPSIG(ws);
                    r_ptrace((long)PTRACE_CONT, ppid, 0, sg == SIGTRAP ? 0 : sg);
                }
            } else r_sleep_ms(300);
        }
    }
    r_close(fds[1]);
    g_guard_child = c;

    char v = 0;
    long r = r_read(fds[0], &v, 1);
    if (r == 1 && v == 'K') {
        g_guard_on.store(1, std::memory_order_relaxed);
    } else if (r == 1 && v == 'D') {
        threat();
    }
    r_close(fds[0]);
    g_guard_pipe = -1;
}


static void poll_guard_pipe() {
    if (g_guard_pipe < 0) return;
    char v = 0;
    long r = r_read(g_guard_pipe, &v, 1);
    if (r == 1 && v == 'D') threat();
    if (r == 1 || r == 0 || (r < 0 && r != -EAGAIN)) {
        if (v == 'K') g_guard_on.store(1);
        r_close(g_guard_pipe);
        g_guard_pipe = -1;
    }
}


// 8. DUAL JITTERED WATCHDOG THREADS
static std::atomic<uint32_t> g_hb[2] = {std::atomic<uint32_t>(0), std::atomic<uint32_t>(0)};

static void run_sweep() {
    poll_guard_pipe();
    bool c1 = verify_process_name_native();
    bool c2 = tracer_clean();
    bool c3 = maps_clean();
    bool c4 = threads_clean();
    bool c5 = ports_clean();
    bool c6 = connect_clean();
    bool c7 = hooks_clean();
    bool c8 = selftext_clean();
    bool c9 = env_clean();
    bool c10 = trace_state_clean();
    bool c11 = timing_clean();
    bool c12 = emulator_clean();
    bool c13 = root_clean();
    bool c14 = apk_path_clean();

    // [DIAGNOSTIC LOG] প্রতি সুইপে কোন চেক কী দিচ্ছে তা দেখা যাবে
    __android_log_print(ANDROID_LOG_INFO, "T4_DEBUG",
        "SWEEP: c1=%d c2=%d c3=%d c4=%d c5=%d c6=%d c7=%d c8=%d c9=%d c10=%d c11=%d c12=%d c13=%d c14=%d | hits=%d",
        c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, g_hits.load());

    fold_key(c1, 0x1); fold_key(c2, 0x2);   fold_key(c3, 0x3);
    fold_key(c4, 0x4); fold_key(c5, 0x5);   fold_key(c6, 0x6);
    fold_key(c7, 0x7); fold_key(c8, 0x8);   fold_key(c9, 0x9);
    fold_key(c10, 0xA); fold_key(c11, 0xB); fold_key(c12, 0xC);
    fold_key(c13, 0xD); fold_key(c14, 0xE);

    if (!c1 || !c2 || !c3 || !c4 || !c5 || !c6 || !c7 || !c8 || !c9 || !c10 || !c11 || !c12 || !c13 || !c14) {
        threat();
    }
}


static void *wd_main(void *arg) {
    const int id = (int)(intptr_t)arg;
    pthread_setname_np(pthread_self(), id ? "RenderThd2" : "RenderThd1");
    uint32_t seen = 0;
    long seen_at = r_clock_ms();
    for (;;) {
        // [FIXED] সুইপ রান করার আগেই ডেডলাইন এক্সপায়ার হয়েছে কিনা চেক হবে
        long now = r_clock_ms();
        long ka = g_kill_at.load(std::memory_order_relaxed);
        if (ka && now >= ka) terminate_now();
        disable_fdsan();
        g_hb[id].fetch_add(1, std::memory_order_relaxed);
        run_sweep();

        uint32_t pc = g_hb[1 - id].load(std::memory_order_relaxed);
        if (pc != seen) { seen = pc; seen_at = now; }
        else if (now - seen_at > 15000) threat();

        r_sleep_ms(1000 + (long)(xr() % 1000));
    }
    return nullptr;
}

// 9. INITIALIZATION & JNI EXPORTS
__attribute__((constructor))
static void t4_core_init() {
    g_pid = r_getpid();
    g_rng = (unsigned)r_clock_ms() ^ (unsigned)(g_pid << 13) ^ 0x9E3779B9u;
    if (!g_rng) g_rng = 1;

    r_prctl(PR_SET_DUMPABLE, 0);

    capture_hook_baselines();
    capture_self_text();

    start_ptrace_guard(); 

    run_sweep();

    pthread_t t1, t2;
    pthread_create(&t1, nullptr, wd_main, (void *)(intptr_t)0); pthread_detach(t1);
    pthread_create(&t2, nullptr, wd_main, (void *)(intptr_t)1); pthread_detach(t2);

    // [FIXED] r_sleep_ms(300) এবং g_hb চেক মুছে দেওয়া হয়েছে। 
    // ওয়াচডগ থ্রেডগুলো নিজেরাই রানিং অবস্থায় ১৫ সেকেন্ড পর পর হার্টবিট ট্র্যাক করবে।
}


// JNI Entrypoint
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *) {
    g_jvm = vm;
    disable_fdsan();
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    return JNI_VERSION_1_6;
}

// জাভা সাইড (ProxyApplication) থেকে কল করার ভ্যালিডেশন মেথড
extern "C" JNIEXPORT jboolean JNICALL
Java_com_t4_protection_T4ProxyApplication_validateEnvironment(JNIEnv *env, jclass, jobject context) {
    run_sweep();

    bool sig_ok = verify_app_signature_jni(env, context);

    // সিগনেচার ফেক বা ট্যাম্পারড হলে সরাসরি টার্মিনেট করবে
    if (!sig_ok) {
        __android_log_print(ANDROID_LOG_ERROR, "T4_DEBUG", "KILL: Signature verification failed!");
        terminate_now();
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

// Call this from your real decrypt/HMAC code -- NEVER from a simple// if/else you could NOP out. Treat a "wrong" key as normal operation that// silently produces garbage output, rather than a visible crash/refusal,// wherever that's workable for your use case.
extern "C" JNIEXPORT jlong JNICALL
Java_com_t4_protection_T4ProxyApplication_getRuntimeKey(JNIEnv *, jclass) {
    return (jlong)runtime_key();
}

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif
#ifndef T4_IV_SEED
#define T4_IV_SEED 0x7C1D3A5F2E8B9046ULL
#endif


static long r_lseek(long fd, long off, long wh) { return rs(__NR_lseek, fd, off, wh); }
static uint32_t rd32(const uint8_t *p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t rd64(const uint8_t *p){ uint64_t v=0; for(int i=7;i>=0;i--) v=(v<<8)|p[i]; return v; }

static bool rb_at(long fd, long off, void *buf, size_t n) {
    return r_lseek(fd, off, SEEK_SET) == off && r_read(fd, buf, (long)n) == (long)n;
}

static bool lp32(const uint8_t *b, long blen, long &off, long &vlen) {
    if (off + 4 > blen) return false;
    vlen = (long)rd32(b + off); off += 4;
    return (vlen >= 0 && off + vlen <= blen);
}

static bool v2_first_cert_sha256(const uint8_t *v, long len, uint8_t out[32]) {
    long off = 0, n, skip;
    if (!lp32(v, len, off, n)) return false;
    long end = off + n;
    if (!lp32(v, end, off, n)) return false;
    if (!lp32(v, end, off, n)) return false;
    long dend = off + n;
    if (!lp32(v, dend, off, skip)) return false;
    off += skip;
    if (!lp32(v, dend, off, skip)) return false;
    if (!lp32(v, dend, off, skip)) return false;
    if (skip < 16) return false;
    T4_SHA256_CTX c; t4_sha256_init(&c);
    t4_sha256_update(&c, v + off, (size_t)skip);
    t4_sha256_final(&c, out);
    return true;
}

static bool find_cert_in_block(long fd, long cd_off, uint8_t out[32]) {
    uint8_t hdr[24];
    if (cd_off < 40 || !rb_at(fd, cd_off - 24, hdr, 24)) return false;
    if (memcmp(hdr + 8, "APK Sig Block 42", 16) != 0) return false;
    uint64_t S = rd64(hdr);
    if (S < 24 || S > (uint64_t)cd_off || S > 0x1000000ull) return false;
    long p = cd_off - (long)S, pend = cd_off - 24;
    while (p + 12 <= pend) {
        uint8_t ph[12];
        if (!rb_at(fd, p, ph, 12)) return false;
        uint64_t plen = rd64(ph); uint32_t pid = rd32(ph + 8);
        if (plen < 4 || p + 8 + (long)plen > pend) return false;
        if (pid == 0x7109871a) {
            long vlen = (long)plen - 4;
            uint8_t *v = (uint8_t *)malloc((size_t)vlen);
            if (!v) return false;
            bool ok = rb_at(fd, p + 12, v, (size_t)vlen) && v2_first_cert_sha256(v, vlen, out);
            free(v);
            return ok;
        }
        p += 8 + (long)plen;
    }
    return false;
}

static bool apk_cert_sha256(const char *path, uint8_t out[32]) {
    long fd = r_open(path, O_RDONLY);
    if (fd < 0) return false;
    long size = r_lseek(fd, 0, SEEK_END);
    bool ok = false;
    if (size > 4096) {
        long flen = size < 69632 ? size : 69632;
        uint8_t *foot = (uint8_t *)malloc((size_t)flen);
        if (foot && r_lseek(fd, size - flen, SEEK_SET) == size - flen &&
            r_read(fd, foot, flen) == flen) {
            for (long i = flen - 22; i >= 0 && !ok; i--) {
                if (foot[i]==0x50 && foot[i+1]==0x4B && foot[i+2]==0x05 && foot[i+3]==0x06) {
                    unsigned cm = (unsigned)foot[i+20] | ((unsigned)foot[i+21] << 8);
                    if (i + 22 + (long)cm == flen)
                        ok = find_cert_in_block(fd, (long)rd32(foot + i + 16), out);
                }
            }
        }
        free(foot);
    }
    r_close(fd);
    return ok;
}

static bool jni_source_dir(JNIEnv *env, jobject ctx, char *out, size_t cap) {
    jclass cc = env->GetObjectClass(ctx);
    jmethodID gi = env->GetMethodID(cc, XS("getApplicationInfo"), XS("()Landroid/content/pm/ApplicationInfo;"));
    if (!gi) { env->ExceptionClear(); return false; }
    jobject ai = env->CallObjectMethod(ctx, gi);
    if (!ai) { env->ExceptionClear(); return false; }
    jfieldID sf = env->GetFieldID(env->GetObjectClass(ai), XS("sourceDir"), XS("Ljava/lang/String;"));
    if (!sf) { env->ExceptionClear(); return false; }
    jstring sd = (jstring)env->GetObjectField(ai, sf);
    if (!sd) return false;
    const char *p = env->GetStringUTFChars(sd, nullptr);
    if (!p) return false;
    bool ok = strlen(p) < cap; if (ok) strcpy(out, p);
    env->ReleaseStringUTFChars(sd, p);
    return ok;
}

static uint64_t det_state() {
    uint64_t s = 0x5DEECE66DULL;
    s = t4_mix64(s ^ (verify_process_name_native() ? 0xA5A5A5A5ULL : 0x5A5A5A5AULL));
    s = t4_mix64(s ^ (selftext_clean()             ? 0xC3C3C3C3ULL : 0x3C3C3C3CULL));
    return s;
}

// [FIXED] Stack Overflow Bug Fixed Here:
static void derive_payload_keys(const uint8_t cert[32], uint64_t det,
                                uint8_t key[32], uint8_t iv[16], uint8_t mk[32]) {
    uint8_t s1[8], s2[8], d8[8];
    for (int i = 0; i < 8; i++) {
        s1[i] = (uint8_t)(((uint64_t)T4_BUILD_SEED >> (8*i)) & 0xFF);
        s2[i] = (uint8_t)(((uint64_t)T4_IV_SEED   >> (8*i)) & 0xFF);
        d8[i] = (uint8_t)((det >> (8*i)) & 0xFF);
    }
    T4_SHA256_CTX c;
    t4_sha256_init(&c); t4_sha256_update(&c,(const uint8_t*)"T4-PK-v2",8);
    t4_sha256_update(&c, cert,32); t4_sha256_update(&c, s1,8); t4_sha256_update(&c, d8,8);
    t4_sha256_final(&c, key);

    uint8_t full_iv[32]; // Fixed: 32 bytes buffer
    t4_sha256_init(&c); t4_sha256_update(&c,(const uint8_t*)"T4-IV-v2",8);
    t4_sha256_update(&c, cert,32); t4_sha256_update(&c, s2,8); t4_sha256_update(&c, d8,8);
    t4_sha256_final(&c, full_iv);
    memcpy(iv, full_iv, 16);

    t4_sha256_init(&c); t4_sha256_update(&c,(const uint8_t*)"T4-MK-v2",8);
    t4_sha256_update(&c, cert,32); t4_sha256_update(&c, s1,8); t4_sha256_update(&c, d8,8);
    t4_sha256_final(&c, mk);
}

static void hmac_sha256(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]) {
    uint8_t kb[64] = {0}, ip[64], op[64], ih[32];
    if (kl > 64) { T4_SHA256_CTX c; t4_sha256_init(&c); t4_sha256_update(&c,k,kl); t4_sha256_final(&c,kb); }
    else memcpy(kb, k, kl);
    for (int i = 0; i < 64; i++) { ip[i] = kb[i]^0x36; op[i] = kb[i]^0x5C; }
    T4_SHA256_CTX c;
    t4_sha256_init(&c); t4_sha256_update(&c,ip,64); t4_sha256_update(&c,m,ml); t4_sha256_final(&c,ih);
    t4_sha256_init(&c); t4_sha256_update(&c,op,64); t4_sha256_update(&c,ih,32); t4_sha256_final(&c,out);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_t4_protection_T4ProxyApplication_nativeUnpackPayload(JNIEnv *env, jclass, jobject ctx, jbyteArray jdata) {
    jbyteArray out = env->NewByteArray(48);
    uint8_t cert[32]; char apk[256];
    
    // Primary check using reliable sourceDir
    bool got = jni_source_dir(env, ctx, apk, sizeof apk) && apk_cert_sha256(apk, cert);

    if (!got) {
        threat();
        uint8_t junk[48]; for (int i = 0; i < 48; i++) junk[i] = (uint8_t)xr();
        env->SetByteArrayRegion(out, 0, 48, (jbyte *)junk);
        return out;
    }

    uint8_t key[32], iv[16], mk[32];
    derive_payload_keys(cert, det_state(), key, iv, mk);

    jsize len = env->GetArrayLength(jdata);
    jbyte *d = env->GetByteArrayElements(jdata, nullptr);
    bool ok = len > 36 && memcmp(d, "T4P1", 4) == 0;
    if (ok) {
        uint8_t tag[32];
        hmac_sha256(mk, 32, (const uint8_t *)d + 36, (size_t)(len - 36), tag);
        ok = safe_mem_cmp(tag, (const uint8_t *)d + 4, 32);
    }
    env->ReleaseByteArrayElements(jdata, d, JNI_ABORT);

       // এমুলেটর, রুট, ক্লোনার বা হুক ম্যাপস পেলেই কি পয়জন হবে এবং সাথে সাথে কিল শিডিউল হবে
    if (!maps_clean() || !emulator_clean() || !root_clean() || !apk_path_clean()) {
        ok = false;
        threat();
    }


    if (!ok) {
        threat();
        // নিশ্চিত ধ্বংস: সরাসরি ডেডলাইন কমিয়ে দিয়ে পয়জন করা
        g_kill_at.store(r_clock_ms() + 500, std::memory_order_relaxed);
    }


    uint8_t kv[48];
    memcpy(kv, key, 32); memcpy(kv + 32, iv, 16);
    if (!ok) for (int i = 0; i < 48; i++) kv[i] ^= (uint8_t)(xr() | 1); // Key poison: wrong payload -> instant silent crash


    env->SetByteArrayRegion(out, 0, 48, (jbyte *)kv);
    return out;
}
