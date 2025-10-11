#include <ctime>
#include <cstring>
#include <vector>
#include <string>
#include <string_view>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <thread>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "../kernel/qassam_engine.hh"
#include "../kernel/qassam_config.hh"
#include "../kernel/qassam_support.hh"

#ifndef TARGET_OS_LINUX
#include <linux/ip.h>
#endif

#ifdef __linux__
    #include <linux/ip.h>
    #include <linux/tcp.h>
    #include <linux/udp.h>
#else
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
#endif




[[nodiscard]]
constexpr ipv4_t QASSAM_INET_ADDR_IPV4(std::uint8_t O1, std::uint8_t O2, std::uint8_t O3, std::uint8_t O4) noexcept
{
    return htonl((static_cast<std::uint32_t>(O1) << 24) | (static_cast<std::uint32_t>(O2) << 16) | (static_cast<std::uint32_t>(O3) << 8) | (static_cast<std::uint32_t>(O4) << 0));
}


/*[[nodiscard]]
constexpr  ipv4_t QASSAM_INET_ADDR_IPV6(std::uint8_t O1, std::uint8_t O2, std::uint8_t O3, std::uint8_t O4) noexcept
{
    return htonl((static_cast<std::uint32_t>(O1) << 24) | (static_cast<std::uint32_t>(O2) << 16) | (static_cast<std::uint32_t>(O3) << 8) | (static_cast<std::uint32_t>(O4) << 0));
}*/

[[nodiscard]]
constexpr ipv6_t QASSAM_INET_ADDR_IPV6(std::uint8_t a1, std::uint8_t a2, std::uint8_t a3, std::uint8_t a4,std::uint8_t b1, std::uint8_t b2, std::uint8_t b3, std::uint8_t b4,std::uint8_t c1, std::uint8_t c2, std::uint8_t c3, std::uint8_t c4,std::uint8_t d1, std::uint8_t d2, std::uint8_t d3, std::uint8_t d4) noexcept
{
    // return htonl((static_cast<std::uint32_t>(O1) << 24) | (static_cast<std::uint32_t>(O2) << 16) | (static_cast<std::uint32_t>(O3) << 8) | (static_cast<std::uint32_t>(O4) << 0));
    return { a1, a2, a3, a4, b1, b2, b3, b4, c1, c2, c3, c4, d1, d2, d3, d4 };
}

// Use Example QASSAM_INET_ADDR_IPV6
/*
constexpr auto addr6 = QASSAM_INET_ADDR_IPV6(
    0x20, 0x01, 0x0d, 0xb8,
    0x85, 0xa3, 0x00, 0x00,
    0x00, 0x00, 0x8a, 0x2e,
    0x03, 0x70, 0x73, 0x34
);
*/