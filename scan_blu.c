/*
 to guarantee null-termination when strncpy hits field boundaries.
 * Build (Arch Linux):
 *   sudo pacman -S bluez bluez-libs sqlite
 *   gcc bleeding.c -o bleeding \
 *       $(pkg-config --cflags --libs bluez) \
 *       -lsqlite3 -lm -Wall -Wextra -O2
 *
 * Usage:
 *   sudo ./bleeding scan          # BR/EDR scan
 *   sudo ./bleeding scan --ble    # BLE scan
 *   sudo ./bleeding list          # quick BLE list
 *   sudo ./bleeding enum <MAC>    # enumerate GATT services
 *   sudo ./bleeding security <MAC>
 *   sudo ./bleeding monitor
 *   sudo ./bleeding history <MAC>
 *   sudo ./bleeding vendors
 *   sudo ./bleeding --help
 */

/* ---- feature-test macros (must come before any include) ---- */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>       /* strcasecmp */
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>   /* socklen_t, setsockopt */
#include <sys/types.h>    /* ssize_t */
#include <sys/stat.h>     /* stat, file mode bits */
#include <fcntl.h>        /* open, O_* flags */
#include <netinet/in.h>   /* sockaddr_in, IPPROTO_* */
#include <arpa/inet.h>    /* inet_ntop, inet_pton */
#include <syslog.h>       /* openlog, syslog, closelog */

/* BlueZ */
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

/* SQLite */
#include <sqlite3.h>

/* ============================================================
 * COMPILE-TIME CONFIGURATION
 * ============================================================ */
#define DB_PATH            "ble_devices.db"
#define MAX_DEVICES        512
#define MAX_SERVICES       128
#define MAX_CHARS          64
#define MAC_STR_LEN        18   /* "XX:XX:XX:XX:XX:XX\0" */
#define NAME_LEN           128
#define UUID_LEN           64
#define TS_LEN             32
#define REASON_LEN         128
#define BORDERED_WIDTH     38

/* ============================================================
 * ANSI COLOUR CODES
 * ============================================================ */
#define COL_RESET    "\033[0m"
#define COL_CYAN     "\033[36m"
#define COL_GREEN    "\033[32m"
#define COL_YELLOW   "\033[33m"
#define COL_RED      "\033[31m"
#define COL_MAGENTA  "\033[35m"
#define COL_LGRAY    "\033[90m"
#define COL_LGREEN   "\033[92m"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */
static bool g_headless   = false;
static volatile sig_atomic_t g_interrupted = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
}

/* ============================================================
 * LOGGER
 * ============================================================ */
static void log_msg(const char *level, const char *color, const char *fmt, va_list ap) {
    if (g_headless) {
        fprintf(stderr, "%s ", level);
        vfprintf(stderr, fmt, ap);
    } else {
        fprintf(stderr, "%s%-5s%s ", color, level, COL_RESET);
        vfprintf(stderr, fmt, ap);
    }
    fputc('\n', stderr);
}

static void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_msg("INFO", COL_CYAN,   fmt, ap);
    va_end(ap);
}
static void log_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_msg("WARN", COL_YELLOW, fmt, ap);
    va_end(ap);
}
static void log_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_msg("ERR",  COL_RED,    fmt, ap);
    va_end(ap);
}

/* ============================================================
 * BANNER
 * ============================================================ */
static void print_banner(void) {
    if (g_headless) return;
    printf("%s\n"
           "       Bluetooth / BLE Scanner & Enumerator\n"
           "%s\n", COL_CYAN, COL_RESET);
}

static void print_bordered(const char *text) {
    if (!text) text = "";
    int tlen = (int)strlen(text);
    int w    = BORDERED_WIDTH;
    char centered[BORDERED_WIDTH + 1];
    memset(centered, ' ', sizeof(centered));
    centered[w] = '\0';

    if (tlen >= w) {
        memcpy(centered, text, (size_t)w);
    } else {
        int pad  = w - tlen;
        int left = pad / 2;
        memcpy(centered + left, text, (size_t)tlen);
    }

    const char *c = g_headless ? "" : COL_CYAN;
    const char *r = g_headless ? "" : COL_RESET;
    printf("%s\u2554", c);
    for (int i = 0; i < w + 2; i++) printf("\u2550");
    printf("\u2557%s\n", r);
    printf("%s\u2551 %s \u2551%s\n", c, centered, r);
    printf("%s\u255a", c);
    for (int i = 0; i < w + 2; i++) printf("\u2550");
    printf("\u255d%s\n", r);
}

/* ============================================================
 * VENDOR OUI TABLE
 * ============================================================ */
typedef struct { const char *name; const char *oui; } VendorEntry;

static const VendorEntry VENDORS[] = {
    {"Acer",      "C0:98:79"},
    {"Apple",     "FC:FC:48"},
    {"Asus",      "FC:C2:33"},
    {"Dell",      "D8:D0:90"},
    {"Google",    "F8:8F:CA"},
    {"HP",        "B0:5C:DA"},
    {"HTC",       "98:0D:2E"},
    {"Intel",     "FC:F8:AE"},
    {"Lenovo",    "A4:8C:DB"},
    {"LG",        "F8:A9:D0"},
    {"Microsoft", "C4:9D:ED"},
    {"Motorola",  "F8:F1:B6"},
    {"Samsung",   "FC:F1:36"},
    {"Sony",      "D4:38:9C"},
    {"Toshiba",   "EC:21:E5"},
    {"Xiaomi",    "FC:64:BA"},
};
#define NUM_VENDORS ((int)(sizeof(VENDORS)/sizeof(VENDORS[0])))

static const char *lookup_vendor(const char *mac) {
    /* mac is "XX:XX:XX:XX:XX:XX"; prefix is first 8 chars */
    char prefix[9];
    if (!mac || strlen(mac) < 8) return "";
    for (int i = 0; i < 8; i++) prefix[i] = (char)toupper((unsigned char)mac[i]);
    prefix[8] = '\0';
    for (int i = 0; i < NUM_VENDORS; i++) {
        char oui[9];
        for (int j = 0; j < 8; j++) oui[j] = (char)toupper((unsigned char)VENDORS[i].oui[j]);
        oui[8] = '\0';
        if (strcmp(oui, prefix) == 0) return VENDORS[i].name;
    }
    return "";
}

/* ============================================================
 * MAC VALIDATION
 * ============================================================ */
static bool validate_mac(const char *mac) {
    if (!mac || strlen(mac) != 17) return false;
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) { if (mac[i] != ':') return false; }
        else { if (!isxdigit((unsigned char)mac[i])) return false; }
    }
    return true;
}

/* uppercase in-place */
static void mac_upper(char *mac) {
    if (!mac) return;
    for (char *p = mac; *p; p++) *p = (char)toupper((unsigned char)*p);
}

/* ============================================================
 * DEVICE / SERVICE STRUCTS
 * ============================================================ */
typedef struct {
    char  address[MAC_STR_LEN];
    char  name[NAME_LEN];
    char  type[16];    /* "BLE" or "BR/EDR" */
    char  vendor[64];
    int   rssi;        /* INT_MIN when unavailable */
    bool  has_rssi;
    /* monitor extras */
    char  first_seen[TS_LEN];
    char  last_seen[TS_LEN];
} Device;

typedef struct {
    char uuid[UUID_LEN];
    char description[NAME_LEN];
    char properties[256];   /* comma-separated */
} GattChar;

typedef struct {
    char      name[NAME_LEN];
    char      description[NAME_LEN];
    char      protocol[32];
    char      provider[32];
    int       port;
    char      uuid[UUID_LEN];
    GattChar  chars[MAX_CHARS];
    int       num_chars;
} Service;

typedef struct {
    char severity[16];   /* "LOW" / "MEDIUM" / "HIGH" */
    char service[NAME_LEN];
    char uuid[UUID_LEN];
    char reason[REASON_LEN];
} Finding;

/* ============================================================
 * FORWARD DECLARATIONS
 * (validate_mac / mac_upper already defined above)
 * ============================================================ */
static void iso_now(char *buf, size_t len);
static void db_record_device(const Device *dev);
static void display_devices(Device *devs, int n);
static void display_services(Service *svcs, int n);
static int  ble_scan(int timeout_sec, Device *out, int max_out);
static int  bredr_scan(Device *out, int max_out);
static int  bredr_enum_services(const char *mac, Service *out, int max_out);
static int  ble_enum_services(const char *mac, Service *out, int max_out);
static void perform_security_scan(const char *mac);
static void monitor_continuous_scan(int duration, double interval);
static void show_device_history(const char *mac, int limit);
static void export_csv(Device *devs, int n, const char *path);
static void interactive_mode(bool use_ble);
static void list_vendors(void);
static void usage(const char *prog);

/* ============================================================
 * TIMESTAMP HELPER
 * ============================================================ */
static void iso_now(char *buf, size_t len) {
    if (!buf || len == 0) return;
    time_t t = time(NULL);
    struct tm tmbuf;
    struct tm *tm = localtime_r(&t, &tmbuf);   /* reentrant; no shared static buffer */
    if (!tm) { snprintf(buf, len, "unknown"); return; }
    if (strftime(buf, len, "%Y-%m-%dT%H:%M:%S", tm) == 0)
        snprintf(buf, len, "unknown");           /* strftime returns 0 on truncation/failure */
}

/* ============================================================
 * DATABASE
 * ============================================================ */
static sqlite3 *db_open(void) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK) {
        log_err("DB open failed: %s", db ? sqlite3_errmsg(db) : sqlite3_errstr(rc));
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);
    {
        char *wal_err = NULL;
        if (sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, &wal_err) != SQLITE_OK) {
            log_warn("DB WAL pragma failed: %s", wal_err ? wal_err : "unknown");
            sqlite3_free(wal_err);
        }
    }
    const char *sql =
        "CREATE TABLE IF NOT EXISTS device_history ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  mac_address TEXT    NOT NULL,"
        "  name        TEXT,"
        "  rssi        INTEGER,"
        "  vendor      TEXT,"
        "  device_type TEXT,"
        "  seen_at     TEXT    NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS device_profiles ("
        "  mac_address  TEXT PRIMARY KEY,"
        "  name         TEXT,"
        "  vendor       TEXT,"
        "  device_type  TEXT,"
        "  first_seen   TEXT,"
        "  last_seen    TEXT,"
        "  times_seen   INTEGER DEFAULT 1"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_history_mac ON device_history(mac_address);";
    char *errmsg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        log_err("DB init failed: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static void db_record_device(const Device *dev) {
    if (!dev) { log_err("db_record_device: NULL device pointer"); return; }
    sqlite3 *db = db_open();
    if (!db) return;
    char ts[TS_LEN]; iso_now(ts, sizeof(ts));
    const char *sql =
        "INSERT INTO device_history"
        " (mac_address,name,rssi,vendor,device_type,seen_at)"
        " VALUES (?,?,?,?,?,?)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_err("db_record_device: prepare failed: %s", sqlite3_errmsg(db));
        goto done;
    }
    sqlite3_bind_text(stmt, 1, dev->address, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, dev->name,    -1, SQLITE_STATIC);
    if (dev->has_rssi) sqlite3_bind_int(stmt, 3, dev->rssi);
    else               sqlite3_bind_null(stmt, 3);
    sqlite3_bind_text(stmt, 4, dev->vendor,  -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, dev->type,    -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, ts,           -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE)
        log_warn("DB record insert may have failed: %s", sqlite3_errmsg(db));
done:
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/* ============================================================
 * DISPLAY HELPERS
 * ============================================================ */
static void display_devices(Device *devs, int n) {
    if (!devs || n == 0) { log_warn("No devices found."); return; }
    printf("\n  %-20s %-8s %-8s %-12s %s\n",
           "Address","Type","RSSI","Vendor","Name");
    printf("  %-20s %-8s %-8s %-12s %s\n",
           "--------------------","--------","--------","------------","--------------------");
    for (int i = 0; i < n; i++) {
        char rssi_str[16];
        if (devs[i].has_rssi) snprintf(rssi_str, sizeof(rssi_str), "%d", devs[i].rssi);
        else                   snprintf(rssi_str, sizeof(rssi_str), "N/A");
        printf("  %s%-20s%s %s%-8s%s %s%-8s%s %s%-12s%s %s%s%s\n",
               g_headless?"":COL_CYAN,    devs[i].address, g_headless?"":COL_RESET,
               g_headless?"":COL_YELLOW,  devs[i].type,    g_headless?"":COL_RESET,
               g_headless?"":COL_LGRAY,   rssi_str,        g_headless?"":COL_RESET,
               g_headless?"":COL_MAGENTA, devs[i].vendor,  g_headless?"":COL_RESET,
               g_headless?"":COL_LGREEN,  devs[i].name,    g_headless?"":COL_RESET);
    }
    printf("\n  %s[+] %d device(s) found.%s\n\n",
           g_headless?"":COL_GREEN, n, g_headless?"":COL_RESET);
}

static void display_services(Service *svcs, int n) {
    if (!svcs || n == 0) { log_warn("No services found."); return; }
    printf("\n");
    for (int i = 0; i < n; i++) {
        printf("  %s\u25b8 %s%s\n",
               g_headless?"":COL_CYAN, svcs[i].name, g_headless?"":COL_RESET);
        printf("    %sDescription : %s%s\n",
               g_headless?"":COL_LGRAY, g_headless?"":COL_RESET, svcs[i].description);
        printf("    %sProtocol    : %s%s\n",
               g_headless?"":COL_LGRAY, g_headless?"":COL_RESET, svcs[i].protocol);
        printf("    %sProvider    : %s%s\n",
               g_headless?"":COL_LGRAY, g_headless?"":COL_RESET, svcs[i].provider);
        if (svcs[i].port > 0)
            printf("    %sPort        : %s%d\n",
                   g_headless?"":COL_LGRAY, g_headless?"":COL_RESET, svcs[i].port);
        printf("    %sUUID        : %s%s\n",
               g_headless?"":COL_LGRAY, g_headless?"":COL_RESET, svcs[i].uuid);
        if (svcs[i].num_chars > 0) {
            printf("    %sCharacteristics:%s\n",
                   g_headless?"":COL_LGRAY, g_headless?"":COL_RESET);
            for (int j = 0; j < svcs[i].num_chars; j++) {
                printf("      %s- %s%s [%s]\n",
                       g_headless?"":COL_LGRAY, g_headless?"":COL_RESET,
                       svcs[i].chars[j].description, svcs[i].chars[j].uuid);
                printf("        %sProperties: %s%s\n",
                       g_headless?"":COL_LGRAY, g_headless?"":COL_RESET,
                       svcs[i].chars[j].properties);
            }
        }
        printf("\n");
    }
    printf("  %s[+] %d service(s) found.%s\n\n",
           g_headless?"":COL_GREEN, n, g_headless?"":COL_RESET);
}

/* ============================================================
 * BLE SCAN  (BlueZ HCI raw scan)
 * ============================================================ */
static int ble_scan(int timeout_sec, Device *out, int max_out) {
    if (!out || max_out <= 0) { log_err("ble_scan: invalid output buffer"); return -1; }
    if (timeout_sec <= 0) timeout_sec = 5;
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) { log_err("No Bluetooth adapter found"); return -1; }

    int sock = hci_open_dev(dev_id);
    if (sock < 0) { log_err("Cannot open HCI device: %s", strerror(errno)); return -1; }

    log_info("Starting BLE scan (%ds)...", timeout_sec);

    /* LE Set Scan Parameters */
    if (hci_le_set_scan_parameters(sock,
            0x01,   /* active scan */
            htobs(0x0010), htobs(0x0010),
            0x00,   /* own addr public */
            0x00,   /* accept all */
            1000) < 0) {
        log_err("Set scan parameters failed: %s", strerror(errno));
        hci_close_dev(sock);
        return -1;
    }

    if (hci_le_set_scan_enable(sock, 0x01, 0x00, 1000) < 0) {
        log_err("Enable scan failed: %s", strerror(errno));
        hci_close_dev(sock);
        return -1;
    }

    struct hci_filter nf, of;
    socklen_t olen = sizeof(of);
    if (getsockopt(sock, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        log_warn("ble_scan: getsockopt failed: %s — filter restore on exit may be incomplete", strerror(errno));
        memset(&of, 0, sizeof(of));  /* safe fallback: restore to empty filter */
    }
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        log_warn("ble_scan: setsockopt (set filter) failed: %s", strerror(errno));
    }

    int n = 0;
    time_t end = time(NULL) + timeout_sec;

    while (time(NULL) < end && !g_interrupted && n < max_out) {
        unsigned char buf[HCI_MAX_EVENT_SIZE];
        if (sock < 0) break;  /* guard against invalid fd */
        int len = (int)read(sock, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            log_warn("ble_scan: read error: %s", strerror(errno));
            break;
        }
        if (len == 0) continue;
        /* need at minimum: 1 (pkt type) + HCI_EVENT_HDR_SIZE + subevent byte */
        if (len < (int)(1 + HCI_EVENT_HDR_SIZE + sizeof(evt_le_meta_event))) continue;

        evt_le_meta_event *meta = (evt_le_meta_event *)(buf + 1 + HCI_EVENT_HDR_SIZE);
        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) continue;

        le_advertising_info *info = (le_advertising_info *)(meta->data + 1);
        char addr[MAC_STR_LEN];
        ba2str(&info->bdaddr, addr);
        mac_upper(addr);

        /* de-duplicate by address */
        bool dup = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(out[i].address, addr) == 0) { dup = true; break; }
        }
        if (dup) continue;

        /* RSSI is the last byte after the AD data */
        int8_t rssi_raw = (int8_t)*(info->data + info->length);

        /* extract local name from AD payload */
        char dev_name[NAME_LEN] = {0};
        int idx = 0;
        while (idx < (int)info->length) {
            int adlen = info->data[idx];
            /* adlen==0 is invalid; idx+1+adlen must stay within payload */
            if (adlen == 0 || idx + 1 + adlen > (int)info->length) break;
            uint8_t adtype = info->data[idx + 1];
            if (adtype == 0x08 || adtype == 0x09) {
                int nlen = adlen - 1; /* bytes after the type byte */
                if (nlen <= 0) break; /* no name bytes */
                if (nlen >= NAME_LEN) nlen = NAME_LEN - 1;
                memcpy(dev_name, &info->data[idx + 2], (size_t)nlen);
                dev_name[nlen] = '\0';
                break;
            }
            idx += adlen + 1;
        }

        Device *d = &out[n++];
        memset(d, 0, sizeof(*d));
        strncpy(d->address, addr, MAC_STR_LEN - 1);
        d->address[MAC_STR_LEN - 1] = '\0';
        strncpy(d->type,    "BLE", sizeof(d->type) - 1);
        d->type[sizeof(d->type) - 1] = '\0';
        strncpy(d->vendor,  lookup_vendor(addr), sizeof(d->vendor) - 1);
        d->vendor[sizeof(d->vendor) - 1] = '\0';
        d->rssi     = (int)rssi_raw;
        d->has_rssi = true;

        if (dev_name[0]) {
            strncpy(d->name, dev_name, NAME_LEN - 1);
        } else if (d->vendor[0]) {
            snprintf(d->name, NAME_LEN, "[%s]", d->vendor);
        } else {
            strncpy(d->name, "Unknown", NAME_LEN - 1);
        }
        d->name[NAME_LEN - 1] = '\0';
    }

    if (setsockopt(sock, SOL_HCI, HCI_FILTER, &of, sizeof(of)) < 0) {
        log_warn("ble_scan: setsockopt (restore filter) failed: %s", strerror(errno));
    }
    if (hci_le_set_scan_enable(sock, 0x00, 0x01, 1000) < 0)
        log_warn("ble_scan: disable scan failed: %s", strerror(errno));
    hci_close_dev(sock);

    log_info("BLE scan complete — %d device(s) found.", n);
    return n;
}

/* ============================================================
 * BR/EDR SCAN  (BlueZ HCI inquiry)
 * ============================================================ */
static int bredr_scan(Device *out, int max_out) {
    if (!out || max_out <= 0) { log_err("bredr_scan: invalid output buffer"); return -1; }
    int dev_id = hci_get_route(NULL);
    if (dev_id < 0) { log_err("No Bluetooth adapter found"); return -1; }

    log_info("Starting BR/EDR scan (may take ~10s)...");

    inquiry_info *ii   = NULL;
    int          n     = 0;
    int          flags = IREQ_CACHE_FLUSH;
    int num   = hci_inquiry(dev_id, 10, 256, NULL, &ii, flags);
    if (num < 0) {
        log_err("BR/EDR inquiry failed: %s", strerror(errno));
        free(ii);
        return -1;
    }
    if (num > max_out) num = max_out; /* clamp to output buffer */

    int sock = hci_open_dev(dev_id);
    if (sock < 0) {
        log_err("Cannot open HCI device for name lookup: %s", strerror(errno));
        free(ii);
        return -1;
    }

    for (int i = 0; i < num && n < max_out; i++) {
        char addr[MAC_STR_LEN] = {0};
        ba2str(&ii[i].bdaddr, addr);
        addr[MAC_STR_LEN - 1] = '\0';
        mac_upper(addr);

        char name[NAME_LEN] = {0};
        if (hci_read_remote_name(sock, &ii[i].bdaddr, NAME_LEN - 1, name, 0) < 0)
            strncpy(name, "Unknown", NAME_LEN - 1);
        name[NAME_LEN - 1] = '\0';

        Device *d = &out[n++];
        memset(d, 0, sizeof(*d));
        strncpy(d->address, addr,               MAC_STR_LEN - 1);
        d->address[MAC_STR_LEN - 1] = '\0';
        strncpy(d->name,    name[0] ? name : "Unknown", NAME_LEN - 1);
        d->name[NAME_LEN - 1] = '\0';
        strncpy(d->type,    "BR/EDR",            sizeof(d->type) - 1);
        d->type[sizeof(d->type) - 1] = '\0';
        strncpy(d->vendor,  lookup_vendor(addr), sizeof(d->vendor) - 1);
        d->vendor[sizeof(d->vendor) - 1] = '\0';
        d->has_rssi = false;
    }

    free(ii);
    hci_close_dev(sock);
    log_info("BR/EDR scan complete — %d device(s) found.", n);
    return n;
}

/* ============================================================
 * BR/EDR SERVICE ENUMERATION  (SDP)
 * ============================================================ */
static int bredr_enum_services(const char *mac, Service *out, int max_out) {
    if (!mac || !validate_mac(mac)) { log_err("bredr_enum_services: invalid MAC"); return -1; }
    if (!out || max_out <= 0) { log_err("bredr_enum_services: invalid output buffer"); return -1; }
    bdaddr_t addr;
    str2ba(mac, &addr);

    sdp_session_t *session = sdp_connect(BDADDR_ANY, &addr, SDP_RETRY_IF_BUSY);
    if (!session) {
        log_err("SDP connect to %s failed: %s", mac, strerror(errno));
        return -1;
    }

    uuid_t svc_uuid;
    sdp_uuid16_create(&svc_uuid, PUBLIC_BROWSE_GROUP);
    sdp_list_t *attrid_list, *search_list, *response_list = NULL;
    uint32_t range = 0x0000ffff;

    search_list = sdp_list_append(NULL, &svc_uuid);
    attrid_list = sdp_list_append(NULL, &range);

    int ret = sdp_service_search_attr_req(
        session, search_list,
        SDP_ATTR_REQ_RANGE, attrid_list,
        &response_list);

    int n = 0;
    if (ret == 0) {
        for (sdp_list_t *r = response_list; r && n < max_out; r = r->next) {
            sdp_record_t *rec = (sdp_record_t *)r->data;
            Service *svc = &out[n];
            memset(svc, 0, sizeof(*svc));

            /* Name */
            sdp_get_service_name(rec, svc->name, NAME_LEN);
            if (!svc->name[0]) strncpy(svc->name, "Unknown", NAME_LEN - 1);

            /* Protocol / port */
            sdp_list_t *proto = NULL;
            if (sdp_get_access_protos(rec, &proto) == 0) {
                int ch = sdp_get_proto_port(proto, RFCOMM_UUID);
                svc->port = (ch > 0) ? ch : 0;
                snprintf(svc->protocol, sizeof(svc->protocol),
                         ch > 0 ? "RFCOMM" : "L2CAP");
                sdp_list_foreach(proto, (sdp_list_func_t)sdp_list_free, NULL);
                sdp_list_free(proto, NULL);
            }

            strncpy(svc->provider,    "BR/EDR", sizeof(svc->provider) - 1);
            strncpy(svc->description, svc->name, NAME_LEN - 1);

            /* UUID */
            sdp_list_t *svclass = NULL;
            if (sdp_get_service_classes(rec, &svclass) == 0 && svclass) {
                uuid_t *u = (uuid_t *)svclass->data;
                sdp_uuid2strn(u, svc->uuid, UUID_LEN);
                sdp_list_free(svclass, free);
            } else {
                strncpy(svc->uuid, "N/A", UUID_LEN - 1);
            }
            n++;
            sdp_record_free(rec);
        }
    }

    sdp_list_free(response_list, NULL);
    sdp_list_free(search_list,   NULL);
    sdp_list_free(attrid_list,   NULL);
    sdp_close(session);
    return n;
}

/* ============================================================
 * KNOWN GATT CHARACTERISTIC NAMES
 * ============================================================ */
typedef struct { const char *short_uuid; const char *name; } GattInfo;
static const GattInfo GATT_CHARS[] = {
    {"2a00", "Device Name"},           {"2a01", "Appearance"},
    {"2a04", "Conn. Pref. Params"},    {"2a05", "Service Changed"},
    {"2a19", "Battery Level"},         {"2a24", "Model Number"},
    {"2a25", "Serial Number"},         {"2a26", "Firmware Revision"},
    {"2a27", "Hardware Revision"},     {"2a28", "Software Revision"},
    {"2a29", "Manufacturer Name"},     {"2a37", "Heart Rate Measurement"},
    {"2a38", "Body Sensor Location"},  {"2a3f", "Alert Status"},
    {"2a46", "New Alert"},             {"2a6d", "Pressure"},
    {"2a6e", "Temperature"},           {"2a6f", "Humidity"},
};
#define NUM_GATT_CHARS ((int)(sizeof(GATT_CHARS)/sizeof(GATT_CHARS[0])))

static const char *gatt_char_name(const char *uuid_lower) {
    if (!uuid_lower) return "Unknown Characteristic";
    /* uuid_lower is full 128-bit or short; check last 4 hex of "0000XXXX" prefix */
    for (int i = 0; i < NUM_GATT_CHARS; i++) {
        if (strstr(uuid_lower, GATT_CHARS[i].short_uuid)) return GATT_CHARS[i].name;
    }
    return "Unknown Characteristic";
}

/* ============================================================
 * BLE (GATT) SERVICE ENUMERATION
 * BlueZ GATT via D-Bus is complex; we use the simpler gatttool
 * approach via popen() for portability on Arch Linux.
 * ============================================================ */
static int ble_enum_services(const char *mac, Service *out, int max_out) {
    if (!mac || !validate_mac(mac)) { log_err("ble_enum_services: invalid MAC"); return -1; }
    if (!out || max_out <= 0) { log_err("ble_enum_services: invalid output buffer"); return -1; }
    log_info("Connecting to %s for GATT enumeration...", mac);

    char *cmd = NULL;
    if (asprintf(&cmd, "gatttool -b %s --primary 2>/dev/null", mac) < 0 || !cmd) {
        log_err("Failed to allocate command buffer");
        return -1;
    }

    FILE *fp = popen(cmd, "r");
    free(cmd);
    cmd = NULL;
    if (!fp) { log_err("gatttool not available"); return -1; }

    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), fp) && n < max_out) {
        /* Example: "attr handle = 0x0001, end grp handle = 0x0009 uuid: 00001800-..." */
        char uuid_str[UUID_LEN] = {0};
        if (sscanf(line, "%*[^u]uuid: %63s", uuid_str) != 1) continue;

        /* strip trailing newline/whitespace */
        for (int i = (int)strlen(uuid_str)-1; i >= 0 && isspace((unsigned char)uuid_str[i]); i--)
            uuid_str[i] = '\0';

        /* lowercase for lookup */
        char uuid_lower[UUID_LEN];
        int ul;
        for (ul = 0; ul < UUID_LEN - 1 && uuid_str[ul]; ul++)
            uuid_lower[ul] = (char)tolower((unsigned char)uuid_str[ul]);
        uuid_lower[ul] = '\0';

        Service *svc = &out[n];
        memset(svc, 0, sizeof(*svc));
        strncpy(svc->uuid,        uuid_str,                    UUID_LEN - 1);
        strncpy(svc->name,        gatt_char_name(uuid_lower),  NAME_LEN - 1);
        snprintf(svc->description, NAME_LEN, "UUID: %s",        uuid_str);
        strncpy(svc->protocol,    "GATT",                       sizeof(svc->protocol) - 1);
        strncpy(svc->provider,    "BLE",                        sizeof(svc->provider) - 1);

        /* Enumerate characteristics for this service */
        char *cmd2 = NULL;
        if (asprintf(&cmd2, "gatttool -b %s --characteristics 2>/dev/null", mac) < 0 || !cmd2) {
            log_err("Failed to allocate command buffer for characteristics");
            n++;
            continue;
        }
        FILE *fp2 = popen(cmd2, "r");
        free(cmd2);
        cmd2 = NULL;
        if (fp2) {
            char line2[512];
            while (fgets(line2, sizeof(line2), fp2)
                   && svc->num_chars < MAX_CHARS) {
                char cuuid[UUID_LEN] = {0};
                /* "handle = 0x0002, char properties = 0x02, char value handle = 0x0003, uuid = ..." */
                if (sscanf(line2, "%*[^u]uuid = %63s", cuuid) != 1) continue;
                for (int i = (int)strlen(cuuid)-1;
                     i >= 0 && isspace((unsigned char)cuuid[i]); i--) cuuid[i] = '\0';

                unsigned int prop_byte = 0;
                if (sscanf(line2, "%*[^p]properties = %x", &prop_byte) < 1)
                    prop_byte = 0; /* no properties field parsed — treat as none */
                /* decode property bits */
                char pbuf[128] = {0};
                if (prop_byte & 0x02) strncat(pbuf, "read,",    sizeof(pbuf)-strlen(pbuf)-1);
                if (prop_byte & 0x04) strncat(pbuf, "write-without-response,", sizeof(pbuf)-strlen(pbuf)-1);
                if (prop_byte & 0x08) strncat(pbuf, "write,",   sizeof(pbuf)-strlen(pbuf)-1);
                if (prop_byte & 0x10) strncat(pbuf, "notify,",  sizeof(pbuf)-strlen(pbuf)-1);
                if (prop_byte & 0x20) strncat(pbuf, "indicate,",sizeof(pbuf)-strlen(pbuf)-1);
                int plen = (int)strlen(pbuf);
                if (plen > 0 && pbuf[plen-1] == ',') pbuf[plen-1] = '\0';

                char cuuid_lower[UUID_LEN];
                int cl;
                for (cl = 0; cl < UUID_LEN - 1 && cuuid[cl]; cl++)
                    cuuid_lower[cl] = (char)tolower((unsigned char)cuuid[cl]);
                cuuid_lower[cl] = '\0';

                GattChar *gc = &svc->chars[svc->num_chars++];
                strncpy(gc->uuid,        cuuid,                       UUID_LEN - 1);
                gc->uuid[UUID_LEN - 1] = '\0';
                strncpy(gc->description, gatt_char_name(cuuid_lower), NAME_LEN - 1);
                gc->description[NAME_LEN - 1] = '\0';
                strncpy(gc->properties,  pbuf[0] ? pbuf : "none",     sizeof(gc->properties) - 1);
                gc->properties[sizeof(gc->properties) - 1] = '\0';
            }
            pclose(fp2);
        }
        n++;
    }
    pclose(fp);
    log_info("GATT enumeration complete — %d service(s).", n);
    return n < 0 ? 0 : n;
}

/* ============================================================
 * SECURITY SCAN
 * ============================================================ */
typedef struct { const char *uuid_short; const char *reason; } SuspiciousUUID;
static const SuspiciousUUID SUSPICIOUS[] = {
    {"1800", "Generic Access — device name/appearance exposed"},
    {"1801", "Generic Attribute — service change notifications"},
    {"180a", "Device Information — firmware/model/serial exposed"},
    {"180f", "Battery Service — battery level readable"},
    {"1812", "HID over GATT — keyboard/mouse emulation possible"},
    {"fe59", "Nordic DFU — firmware update possible (check auth)"},
};
#define NUM_SUSPICIOUS ((int)(sizeof(SUSPICIOUS)/sizeof(SUSPICIOUS[0])))

static void perform_security_scan(const char *mac) {
    if (!mac) { log_err("perform_security_scan: NULL MAC"); return; }
    if (!validate_mac(mac)) { log_err("Invalid MAC: %s", mac); return; }

    log_info("Security scan -> %s", mac);
    Service svcs[MAX_SERVICES];
    int n = ble_enum_services(mac, svcs, MAX_SERVICES);
    if (n < 0) {
        log_err("perform_security_scan: GATT enumeration failed for %s", mac);
        return;
    }
    if (n == 0) {
        log_warn("perform_security_scan: no services found on %s", mac);
        /* fall through — report will show 0 services / 0 findings */
    }

    Finding findings[MAX_SERVICES * 4];
    int nf = 0;

    for (int i = 0; i < n; i++) {
        char uuid_low[UUID_LEN];
        int ul2;
        for (ul2 = 0; ul2 < UUID_LEN - 1 && svcs[i].uuid[ul2]; ul2++)
            uuid_low[ul2] = (char)tolower((unsigned char)svcs[i].uuid[ul2]);
        uuid_low[ul2] = '\0';

        for (int s = 0; s < NUM_SUSPICIOUS; s++) {
            if (strstr(uuid_low, SUSPICIOUS[s].uuid_short)) {
                if (nf >= MAX_SERVICES * 4) { log_warn("Findings buffer full, skipping."); break; }
                Finding *f = &findings[nf++];
                memset(f, 0, sizeof(*f));
                strncpy(f->severity, "MEDIUM",              sizeof(f->severity)-1);
                strncpy(f->service,  svcs[i].name,          sizeof(f->service)-1);
                strncpy(f->uuid,     svcs[i].uuid,          sizeof(f->uuid)-1);
                strncpy(f->reason,   SUSPICIOUS[s].reason,  sizeof(f->reason)-1);
            }
        }

        for (int c = 0; c < svcs[i].num_chars; c++) {
            if (strstr(svcs[i].chars[c].properties, "write")) {
                if (nf >= MAX_SERVICES * 4) { log_warn("Findings buffer full, skipping."); break; }
                Finding *f = &findings[nf++];
                memset(f, 0, sizeof(*f));
                strncpy(f->severity, "HIGH",    sizeof(f->severity)-1);
                strncpy(f->service,  svcs[i].name, sizeof(f->service)-1);
                strncpy(f->uuid,     svcs[i].chars[c].uuid, sizeof(f->uuid)-1);
                strncpy(f->reason,   "Writable characteristic (no auth confirmed)",
                        sizeof(f->reason)-1);
            }
        }
    }

    bool has_high   = false, has_medium = false;
    for (int i = 0; i < nf; i++) {
        if (strcmp(findings[i].severity, "HIGH")   == 0) has_high   = true;
        if (strcmp(findings[i].severity, "MEDIUM") == 0) has_medium = true;
    }
    const char *risk = has_high ? "HIGH" : has_medium ? "MEDIUM" : "LOW";
    const char *risk_col = has_high   ? (g_headless?"":COL_RED)
                         : has_medium ? (g_headless?"":COL_YELLOW)
                         :              (g_headless?"":COL_GREEN);

    printf("\n  %sSecurity Scan Report%s  ->  %s\n",
           g_headless?"":COL_CYAN, g_headless?"":COL_RESET, mac);
    printf("  Risk level : %s%s%s\n", risk_col, risk, g_headless?"":COL_RESET);
    printf("  Services   : %d\n", n);
    printf("  Findings   : %d\n", nf);
    for (int i = 0; i < nf; i++) {
        const char *sc = (strcmp(findings[i].severity,"HIGH")==0)
                         ? (g_headless?"":COL_RED) : (g_headless?"":COL_YELLOW);
        printf("    %s[%s]%s %s - %s\n",
               sc, findings[i].severity, g_headless?"":COL_RESET,
               findings[i].service, findings[i].reason);
    }
    printf("\n");
}

/* ============================================================
 * CONTINUOUS MONITOR
 * ============================================================ */
static void monitor_continuous_scan(int duration, double interval) {
    if (duration <= 0) { log_warn("Invalid duration, using default 300s."); duration = 300; }
    /* Clamp duration to avoid integer overflow when casting to time_t.
     * 86400 * 365 = one year, a reasonable upper bound. */
    if (duration > 31536000) { log_warn("Duration too large, clamping to 1 year."); duration = 31536000; }
    if (interval <= 0.0) { log_warn("Invalid interval, using default 10s."); interval = 10.0; }
    if (interval > (double)duration) { log_warn("Interval exceeds duration, clamping."); interval = (double)duration; }
    Device  seen[MAX_DEVICES];
    int     seen_n = 0;

    Device  batch[MAX_DEVICES];
    time_t  start_time = time(NULL);
    time_t  end  = start_time + (time_t)duration;
    int     pass = 0;

    /* duration is already validated/clamped above; end = start_time + (time_t)duration
     * is safe because duration <= 31536000 which fits in any reasonable time_t.
     * We drive the loop via wall-clock comparison (time_t) to avoid any int overflow
     * in a hypothetical for(i=0; i<duration; i+=interval) counter. */
    log_info("Continuous monitor started — %ds total, %.0fs per pass.", duration, interval);
    log_info("Started at: %ld, ends at: %ld", (long)start_time, (long)end);

    while (time(NULL) < end && !g_interrupted) {
        pass++;
        time_t now = time(NULL);
        time_t remaining = end - now;
        int scan_t = (interval < (double)remaining) ? (int)interval : (int)remaining;
        if (scan_t <= 0) break;

        log_info("Pass %d — scanning %ds ...", pass, scan_t);
        int n = ble_scan(scan_t, batch, MAX_DEVICES);
        if (n < 0) {
            log_warn("Pass %d: ble_scan failed, skipping.", pass);
            n = 0;
        }

        char ts[TS_LEN]; iso_now(ts, sizeof(ts));

        for (int i = 0; i < n; i++) {
            bool found = false;
            for (int j = 0; j < seen_n; j++) {
                if (strcmp(seen[j].address, batch[i].address) == 0) {
                    seen[j].rssi = batch[i].rssi;
                    seen[j].has_rssi = batch[i].has_rssi;
                    strncpy(seen[j].last_seen, ts, TS_LEN-1);
                    seen[j].last_seen[TS_LEN-1] = '\0';
                    found = true; break;
                }
            }
            if (!found) {
                if (seen_n >= MAX_DEVICES) {
                    log_warn("Device cap (%d) reached — skipping new devices.", MAX_DEVICES);
                    continue;
                }
                batch[i].first_seen[0] = batch[i].last_seen[0] = '\0';
                strncpy(batch[i].first_seen, ts, TS_LEN-1);
                batch[i].first_seen[TS_LEN-1] = '\0';
                strncpy(batch[i].last_seen,  ts, TS_LEN-1);
                batch[i].last_seen[TS_LEN-1]  = '\0';
                /* ensure strings are null-terminated before copy/print */
                batch[i].address[MAC_STR_LEN - 1] = '\0';
                batch[i].name[NAME_LEN - 1]        = '\0';
                seen[seen_n++] = batch[i];
                log_info("  NEW  %s  %s", batch[i].address, batch[i].name);
                db_record_device(&batch[i]);
            }
        }
    }

    log_info("Monitor finished — %d unique device(s) observed.", seen_n);
    display_devices(seen, seen_n);
}

/* ============================================================
 * DEVICE HISTORY
 * ============================================================ */
static void show_device_history(const char *mac, int limit) {
    if (!mac) { log_err("show_device_history: NULL MAC"); return; }
    if (!validate_mac(mac)) { log_err("Invalid MAC: %s", mac); return; }
    /* limit validated at call site; guard here too */
    if (limit <= 0 || limit > 100000) { log_warn("limit out of range, clamping to 50."); limit = 50; }

    sqlite3 *db = db_open();
    if (!db) return;

    char mac_up[MAC_STR_LEN];
    strncpy(mac_up, mac, MAC_STR_LEN-1); mac_up[MAC_STR_LEN-1] = '\0'; mac_upper(mac_up);

    const char *sql =
        "SELECT seen_at, rssi, name FROM device_history"
        " WHERE mac_address = ? ORDER BY seen_at DESC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        log_err("DB prepare failed"); sqlite3_close(db); return;
    }
    sqlite3_bind_text(stmt, 1, mac_up, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt,  2, limit);

    printf("\n  History for %s%s%s\n",
           g_headless?"":COL_CYAN, mac_up, g_headless?"":COL_RESET);
    printf("  %-4s %-28s %-7s %s\n", "#","Seen At","RSSI","Name");
    printf("  %s\n", "------------------------------------------------------------");

    int row = 0;
    int step_rc;
    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        row++;
        const char *seen_at = (const char *)sqlite3_column_text(stmt, 0);
        int         rssi    = sqlite3_column_int(stmt, 1);
        const char *name    = (const char *)sqlite3_column_text(stmt, 2);
        int         null_r  = sqlite3_column_type(stmt, 1) == SQLITE_NULL;
        if (!seen_at) seen_at = "";
        if (!name)    name    = "";
        char rssi_str[16];
        if (null_r) snprintf(rssi_str, sizeof(rssi_str), "%s", "\xe2\x80\x94"); /* em-dash */
        else snprintf(rssi_str, sizeof(rssi_str), "%d", rssi);
        printf("  %-4d %-28s %-7s %s\n", row, seen_at, rssi_str, name);
    }
    if (step_rc != SQLITE_DONE)
        log_err("show_device_history: query error: %s", sqlite3_errmsg(db));
    if (row == 0 && step_rc == SQLITE_DONE)
        log_warn("No history found for %s.", mac);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("\n");
}

/* ============================================================
 * EXPORT (CSV)
 * ============================================================ */
static void export_csv(Device *devs, int n, const char *path) {
    if (!devs || !path || n <= 0) { log_err("export_csv: invalid arguments"); return; }
    /* Reject absolute paths, dot-dot traversals, and embedded path separators */
    if (path[0] == '/' || strstr(path, "..") || strchr(path, '/') || strchr(path, '\\')) {
        log_err("export_csv: unsafe path rejected: '%s'", path);
        return;
    }
    FILE *fp = fopen(path, "w");
    if (!fp) { log_err("Cannot open %s: %s", path, strerror(errno)); return; }
    fprintf(fp, "address,name,type,vendor,rssi\n");
    for (int i = 0; i < n; i++) {
        char rssi_str[16];
        if (devs[i].has_rssi) snprintf(rssi_str, sizeof(rssi_str), "%d", devs[i].rssi);
        else                   rssi_str[0] = '\0';
        /* Quote fields that may contain commas or newlines */
        fprintf(fp, "%s,\"%s\",%s,\"%s\",%s\n",
                devs[i].address,
                devs[i].name[0]   ? devs[i].name   : "",
                devs[i].type,
                devs[i].vendor[0] ? devs[i].vendor : "",
                rssi_str);
    }
    if (ferror(fp)) {
        log_err("Write error while exporting to %s", path);
        fclose(fp);
        return;
    }
    fclose(fp);
    log_info("Exported %d device(s) -> %s", n, path);
}

/* ============================================================
 * INTERACTIVE MODE
 * ============================================================ */
static void interactive_mode(bool use_ble) {
    print_bordered(use_ble ? "Interactive Mode (BLE)" : "Interactive Mode (BR/EDR)");
    printf("\n");

    Device devs[MAX_DEVICES];
    int n = use_ble ? ble_scan(5, devs, MAX_DEVICES)
                    : bredr_scan(devs, MAX_DEVICES);
    if (n <= 0) { log_warn("No devices found."); return; }
    display_devices(devs, n);

    printf("\n%sAvailable devices:%s\n", g_headless?"":COL_YELLOW, g_headless?"":COL_RESET);
    for (int i = 0; i < n; i++) {
        printf("  %s[%d]%s %s%s%s — %s%s%s\n",
               g_headless?"":COL_LGRAY, i+1, g_headless?"":COL_RESET,
               g_headless?"":COL_LGREEN, devs[i].address, g_headless?"":COL_RESET,
               g_headless?"":COL_CYAN,   devs[i].name,    g_headless?"":COL_RESET);
    }
    printf("  %s[0]%s %sExit%s\n",
           g_headless?"":COL_LGRAY, g_headless?"":COL_RESET,
           g_headless?"":COL_RED,   g_headless?"":COL_RESET);

    int choice = -1;
    int attempts = 0;
    while (choice < 0 || choice > n) {
        if (attempts++ > 10) { log_err("Too many invalid inputs. Exiting."); return; }
        printf("\n%sSelect device [0-%d]: %s", g_headless?"":COL_CYAN, n, g_headless?"":COL_RESET);
        fflush(stdout);
        if (scanf("%d", &choice) != 1) {
            /* clear bad input from stdin to avoid infinite loop */
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            choice = -1;
            log_warn("Invalid input. Please enter a number between 0 and %d.", n);
        } else if (choice < 0 || choice > n) {
            /* flush the rest of the line (e.g. trailing newline) */
            int c2;
            while ((c2 = getchar()) != '\n' && c2 != EOF);
            log_warn("Choice out of range. Enter 0 to exit or 1-%d for a device.", n);
        }
    }
    if (choice == 0) { log_info("Exiting."); return; }

    Device *sel = &devs[choice - 1];
    printf("\n%s✓ Selected:%s %s%s%s (%s%s%s)\n\n",
           g_headless?"":COL_GREEN,  g_headless?"":COL_RESET,
           g_headless?"":COL_LGREEN, sel->name,    g_headless?"":COL_RESET,
           g_headless?"":COL_CYAN,   sel->address, g_headless?"":COL_RESET);

    print_bordered("Enumerating services...");
    Service svcs[MAX_SERVICES];
    int ns = use_ble ? ble_enum_services(sel->address, svcs, MAX_SERVICES)
                     : bredr_enum_services(sel->address, svcs, MAX_SERVICES);
    if (ns < 0) ns = 0;
    display_services(svcs, ns);
}

/* ============================================================
 * VENDORS LIST
 * ============================================================ */
static void list_vendors(void) {
    printf("\n  %-12s %s\n", "Vendor", "OUI Prefix");
    printf("  %-12s %s\n",   "------------", "----------");
    for (int i = 0; i < NUM_VENDORS; i++) {
        printf("  %s%-12s%s %s%s%s\n",
               g_headless?"":COL_CYAN,   VENDORS[i].name, g_headless?"":COL_RESET,
               g_headless?"":COL_LGREEN, VENDORS[i].oui,  g_headless?"":COL_RESET);
    }
    printf("\n");
}

/* ============================================================
 * USAGE / HELP
 * ============================================================ */
static void usage(const char *prog) {
    printf("Usage: %s [--headless] <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  list   [-w SECS]          Quick BLE device list\n");
    printf("  scan   [-b] [-t SECS]     Scan for Bluetooth devices\n");
    printf("  enum   <MAC> [-b]         Enumerate services\n");
    printf("  interactive [-b]          Interactive scan -> enumerate\n");
    printf("  export [-b] [-t SECS] [-o FILE]  Scan and export CSV\n");
    printf("  monitor [-d SECS] [-i SECS]      Continuous BLE monitor\n");
    printf("  security <MAC>            BLE security scan\n");
    printf("  history  <MAC> [-n LIMIT] Show DB history\n");
    printf("  vendors                   List known OUI prefixes\n");
    printf("\nOptions:\n");
    printf("  --headless   Disable colours\n");
    printf("  -h, --help   Show this help\n\n");
    printf("Build deps (Arch): bluez bluez-libs sqlite\n");
    printf("  gcc bleeding.c -o bleeding $(pkg-config --cflags --libs bluez) -lsqlite3 -lm\n\n");
}

/* ============================================================
 * MAIN / CLI DISPATCH
 * ============================================================ */
int main(int argc, char *argv[]) {
    /* Use sigaction instead of signal() for well-defined, race-safe signal handling.
     * SA_RESTART automatically restarts interrupted system calls where possible.
     * g_interrupted is volatile sig_atomic_t — the only shared state written in the handler. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT,  &sa, NULL) < 0) { perror("sigaction SIGINT");  return 1; }
    if (sigaction(SIGTERM, &sa, NULL) < 0) { perror("sigaction SIGTERM"); return 1; }

    if (argc < 2) { print_banner(); usage(argv[0]); return 1; }

    int argi = 1;

    /* global flags before subcommand */
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "--headless") == 0) { g_headless = true; argi++; }
        else if (strcmp(argv[argi], "-h") == 0 ||
                 strcmp(argv[argi], "--help") == 0) {
            print_banner(); usage(argv[0]); return 0;
        } else break;
    }

    if (!g_headless) print_banner();
    if (argi >= argc) { usage(argv[0]); return 1; }

    const char *cmd = argv[argi++];

    /* ---- list ---- */
    if (strcmp(cmd, "list") == 0) {
        int wait = 5;
        for (int i = argi; i < argc; i++) {
            if ((strcmp(argv[i],"-w")==0||strcmp(argv[i],"--wait-time")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                long v = strtol(argv[++i], &end, 10);
                if (errno || end == argv[i] || *end != '\0' || v <= 0 || v > 3600) {
                    log_warn("Invalid wait time '%s', using default 5s.", argv[i]); wait = 5;
                } else { wait = (int)v; }
            }
        }
        Device devs[MAX_DEVICES];
        int n = ble_scan(wait, devs, MAX_DEVICES);
        if (n <= 0) { log_warn("No devices found."); return 0; }
        printf("\n%-20s %-8s %-12s %s\n", "Address","RSSI","Vendor","Name");
        printf("%s\n", "------------------------------------------------------------");
        for (int i = 0; i < n; i++) {
            char rssi_str[16];
            if (devs[i].has_rssi) snprintf(rssi_str,sizeof(rssi_str),"%d",devs[i].rssi);
            else { strncpy(rssi_str,"N/A",sizeof(rssi_str)-1); rssi_str[sizeof(rssi_str)-1] = '\0'; }
            printf("%-20s %-8s %-12s %s\n",
                   devs[i].address, rssi_str, devs[i].vendor, devs[i].name);
        }
        printf("\n[+] %d device(s) found.\n", n);

    /* ---- scan ---- */
    } else if (strcmp(cmd, "scan") == 0) {
        bool ble = false; int timeout = 5;
        for (int i = argi; i < argc; i++) {
            if (strcmp(argv[i],"-b")==0||strcmp(argv[i],"--ble")==0) ble = true;
            if ((strcmp(argv[i],"-t")==0||strcmp(argv[i],"--timeout")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                long v = strtol(argv[++i], &end, 10);
                if (errno || end == argv[i] || *end != '\0' || v <= 0 || v > 3600) {
                    log_warn("Invalid timeout '%s', using default 5s.", argv[i]); timeout = 5;
                } else { timeout = (int)v; }
            }
        }
        Device devs[MAX_DEVICES];
        int n = ble ? ble_scan(timeout, devs, MAX_DEVICES) : bredr_scan(devs, MAX_DEVICES);
        if (n < 0) n = 0;
        display_devices(devs, n);

    /* ---- enum ---- */
    } else if (strcmp(cmd, "enum") == 0) {
        if (argi >= argc) { log_err("enum requires a MAC address"); return 1; }
        const char *mac = argv[argi++];
        bool ble = false;
        for (int i = argi; i < argc; i++) {
            if (strcmp(argv[i],"-b")==0||strcmp(argv[i],"--ble")==0) ble = true;
        }
        if (!validate_mac(mac)) { log_err("Invalid MAC: %s", mac); return 1; }
        Service svcs[MAX_SERVICES];
        int n = ble ? ble_enum_services(mac, svcs, MAX_SERVICES)
                    : bredr_enum_services(mac, svcs, MAX_SERVICES);
        if (n < 0) n = 0;
        display_services(svcs, n);

    /* ---- interactive ---- */
    } else if (strcmp(cmd, "interactive") == 0) {
        bool ble = false;
        for (int i = argi; i < argc; i++) {
            if (strcmp(argv[i],"-b")==0||strcmp(argv[i],"--ble")==0) ble = true;
        }
        interactive_mode(ble);

    /* ---- export ---- */
    } else if (strcmp(cmd, "export") == 0) {
        bool ble = false; int timeout = 5; const char *outfile = NULL;
        for (int i = argi; i < argc; i++) {
            if (strcmp(argv[i],"-b")==0||strcmp(argv[i],"--ble")==0) ble = true;
            if ((strcmp(argv[i],"-t")==0||strcmp(argv[i],"--timeout")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                long v = strtol(argv[++i], &end, 10);
                if (errno || end == argv[i] || *end != '\0' || v <= 0 || v > 3600) {
                    log_warn("Invalid timeout '%s', using default 5s.", argv[i]); timeout = 5;
                } else { timeout = (int)v; }
            }
            if ((strcmp(argv[i],"-o")==0||strcmp(argv[i],"--output")==0) && i+1<argc) {
                const char *candidate = argv[++i];
                if (strlen(candidate) >= 127) {
                    log_err("Output filename too long (max 126 chars), ignoring -o.");
                } else {
                    outfile = candidate;
                }
            }
        }
        Device devs[MAX_DEVICES];
        int n = ble ? ble_scan(timeout, devs, MAX_DEVICES) : bredr_scan(devs, MAX_DEVICES);
        if (n <= 0) { log_warn("No devices found."); return 0; }
        char auto_path[128];
        if (!outfile) {
            time_t t = time(NULL);
            struct tm tmbuf;
            struct tm *ltm = localtime_r(&t, &tmbuf);
            if (ltm && strftime(auto_path, sizeof(auto_path), "ble_scan_%Y%m%d_%H%M%S.csv", ltm) > 0) {
                /* strftime succeeded — auto_path is valid */
            } else {
                snprintf(auto_path, sizeof(auto_path), "ble_scan_output.csv");
            }
            /* auto_path is always null-terminated: strftime writes '\0', snprintf guarantees it */
            outfile = auto_path;
        }
        export_csv(devs, n, outfile);
        printf("%s[+] Saved to:%s %s\n", g_headless?"":COL_GREEN, g_headless?"":COL_RESET, outfile);

    /* ---- monitor ---- */
    } else if (strcmp(cmd, "monitor") == 0) {
        int    duration = 300;
        double interval = 10.0;
        for (int i = argi; i < argc; i++) {
            if ((strcmp(argv[i],"-d")==0||strcmp(argv[i],"--duration")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                long v = strtol(argv[++i], &end, 10);
                if (errno || end == argv[i] || *end != '\0' || v <= 0 || v > 31536000) {
                    log_warn("Invalid duration '%s', using default 300s.", argv[i]); duration = 300;
                } else { duration = (int)v; }
            }
            if ((strcmp(argv[i],"-i")==0||strcmp(argv[i],"--interval")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                double v = strtod(argv[++i], &end);
                if (errno || end == argv[i] || *end != '\0' || v <= 0.0 || v > 86400.0) {
                    log_warn("Invalid interval '%s', using default 10s.", argv[i]); interval = 10.0;
                } else { interval = v; }
            }
        }
        monitor_continuous_scan(duration, interval);

    /* ---- security ---- */
    } else if (strcmp(cmd, "security") == 0) {
        if (argi >= argc) { log_err("security requires a MAC address"); return 1; }
        const char *mac = argv[argi];
        if (!validate_mac(mac)) { log_err("Invalid MAC address: %s", mac); return 1; }
        perform_security_scan(mac);

    /* ---- history ---- */
    } else if (strcmp(cmd, "history") == 0) {
        if (argi >= argc) { log_err("history requires a MAC address"); return 1; }
        const char *mac = argv[argi++];
        int limit = 50;
        for (int i = argi; i < argc; i++) {
            if ((strcmp(argv[i],"-n")==0||strcmp(argv[i],"--limit")==0) && i+1<argc) {
                char *end = NULL; errno = 0;
                long v = strtol(argv[++i], &end, 10);
                if (errno || end == argv[i] || *end != '\0' || v <= 0 || v > 100000) {
                    log_warn("Invalid limit '%s', using default 50.", argv[i]); limit = 50;
                } else { limit = (int)v; }
            }
        }
        show_device_history(mac, limit);

    /* ---- vendors ---- */
    } else if (strcmp(cmd, "vendors") == 0) {
        list_vendors();

    } else {
        log_err("Unknown command: %s", cmd);
        usage(argv[0]);
        return 1;
    }

    return 0;
}
