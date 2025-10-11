#pragma once

#ifndef B0B38F43_F84B_4445_8B68_8B6A25D9B803
#define B0B38F43_F84B_4445_8B68_8B6A25D9B803


#include "qassam_config.hh"




[[nodiscard]]
int qassam_strlen(char *str) noexcept;

[[nodiscard]]
bool qassam_strncmp(char *str1, char *str2, int len) noexcept;

[[nodiscard]]
bool qassam_strcmp(char *str1, char *str2) noexcept;

[[nodiscard]]
int qassam_strcpy(char *dst, char *src) noexcept;

void qassam_strcat(char *dest, char *src) noexcept;
void qassam_memcpy(void *dst, void *src, int len) noexcept;
void qassam_zero(void *buf, int len) noexcept;

[[nodiscard]]
int qassam_atoi(char *str, int base) noexcept;

[[nodiscard]]
char *qassam_itoa(int value, int radix, char *string) noexcept;

[[nodiscard]]
int qassam_memsearch(char *buf, int buf_len, char *mem, int mem_len) noexcept;

[[nodiscard]]
int qassam_stristr(char *haystack, int haystack_len, char *str) noexcept;

[[nodiscard]]
ipv4_t qassam_local_addr(void) noexcept;

[[nodiscard]]
char *qassam_fdgets(char *buffer, int buffer_size, int fd) noexcept;


inline bool qassam_isupper(char c) noexcept;
inline bool qassam_isalpha(char c) noexcept;
inline bool qassam_isspace(char c) noexcept;
inline bool qassam_isdigit(char c) noexcept;

[[nodiscard]]
inline std::string qassam_to_string(const ipv4_t);

[[nodiscard]]
inline std::string qassam_to_string(const ipv6_t&);

[[nodiscard]]
inline std::string qassam_to_string(const ip_addr_t&);

inline uint16_t qassam_generic(const uint16_t*, uint32_t) noexcept;
// inline uint16_t qassam_tcpudp(struct iphdr*, void*, uint16_t, int) noexcept;
inline uint16_t qassam_tcpudp(void* ip_header, void* transport_header, uint16_t transport_len, uint8_t protocol) noexcept;
static uint32_t qassam_add_carry(uint32_t sum) noexcept;


































#endif /* B0B38F43_F84B_4445_8B68_8B6A25D9B803 */



