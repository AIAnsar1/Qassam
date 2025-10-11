#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <csignal>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <string>

#include "../kernel/qassam_support.hh"
#include "../kernel/qassam_config.hh"




[[nodiscard]]
int qassam_strlen(char *str) noexcept
{
    if (!str)
    {
        return 0;
    }
    int c = 0;
    
    while(*str++ != 0)
    {
        c++;
    }
    return c;
}

[[nodiscard]]
bool qassam_strncmp(char *str1, char *str2, int len) noexcept
{
    if (!str1 || !str2 || len < 0)
    {
        return false;
    }
    int l1 = qassam_strlen(str1), l2 = qassam_strlen(str2);
    
    if(l1 < len || l2 < len)
    {
        return false;
    }

    while(len--)
    {
        if(*str1++ != *str2++)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]]
bool qassam_strcmp(char *str1, char *str2) noexcept
{
    if (!str1 || !str2)
    {
        return false;
    }
    int l1 = qassam_strlen(str1), l2 = qassam_strlen(str2);

    if(l1 != l2)
    {
        return false;
    }

    while(l1--)
    {
        if(*str1++ != *str2++)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]]
int qassam_strcpy(char *dst, char *src) noexcept
{
    if (!dst || !src) return 0;

    int l = qassam_strlen(src);
    qassam_memcpy(dst, src, l + 1);
    return l;
}

void qassam_strcat(char *dest, char *src) noexcept
{
    if (!dest || !src)
    {
        return;
    }


    while(*dest != '\0')
    {
        dest++;
    }

    do
    {
        *dest++ = *src++;
    }
    while(*src != '\0');
}

void qassam_memcpy(void *dst, void *src, int len) noexcept
{
    if (!dst || !src || len < 0)
    {
        return;
    }
    char *r_dst = static_cast<char *>(dst);
    char *r_src = static_cast<char *>(src);

    while(len--)
    {
        *r_dst++ = *r_src++;
    }
}

void qassam_zero(void *buf, int len) noexcept
{
    if (!buf || len < 0)
    {
        return;
    }
    char *zero = static_cast<char *>(buf);

    while(len--)
    {
        *zero++ = 0;
    }
}

[[nodiscard]]
int qassam_atoi(char *str, int base) noexcept
{
    if (!str || base < 2 || base > 36)
    {
        return 0;
    }
	unsigned long acc = 0;
	int c = 0;
	unsigned long cutoff = 0;
	int neg = 0, any = 0, cutlim = 0;

	do
    {
		c = *str++;
	}
    while(qassam_isspace(static_cast<char>(c)));

	if(c == '-')
    {
		neg = 1;
		c = *str++;
	}
    else if(c == '+')
    {
		c = *str++;
    }
	cutoff = neg ? static_cast<unsigned long>(-(LONG_MIN)) : static_cast<unsigned long>(LONG_MAX);
	cutlim = static_cast<int>(cutoff % static_cast<unsigned long>(base));
	cutoff /= static_cast<unsigned long>(base);

	for(acc = 0, any = 0;; c = *str++)
    {
		if(qassam_isdigit(static_cast<char>(c)))
		{
			c -= '0';
		}
		else if(qassam_isalpha(static_cast<char>(c)))
		{
			c -= qassam_isupper(static_cast<char>(c)) ? 'A' - 10 : 'a' - 10;
		}
		else
		{
			break;
		}

		if(c >= base)
		{
			break;
		}

		if(any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
		{
			any = -1;
		}
		else
        {
			any = 1;
			acc *= static_cast<unsigned long>(base);
			acc += static_cast<unsigned long>(c);
		}
	}

	if(any < 0)
    {
		acc = neg ? static_cast<unsigned long>(LONG_MIN) : static_cast<unsigned long>(LONG_MAX);
	}
    else if(neg)
    {
		acc = static_cast<unsigned long>(-static_cast<long>(acc));
    }
    return static_cast<int>(acc);
}

[[nodiscard]]
char *qassam_itoa(int value, int radix, char *string) noexcept
{
    if (!string || radix < 2 || radix > 36)
    {
        return nullptr;
    }

    if(value != 0)
    {
        char scratch[34] = {0};
        int neg = 0;
        int offset = 0;
        int c = 0;
        unsigned int accum = 0;
        offset = 32;
        scratch[33] = 0;

        if(radix == 10 && value < 0)
        {
            neg = 1;
            accum = static_cast<unsigned int>(-value);
        }
        else
        {
            neg = 0;
            accum = static_cast<unsigned int>(value);
        }

        while(accum)
        {
            c = accum % static_cast<unsigned int>(radix);
            if(c < 10)
            {
                c += '0';
            }
            else
            {
                c += 'A' - 10;
            }
            scratch[offset] = static_cast<char>(c);
            accum /= static_cast<unsigned int>(radix);
            offset--;
        }

        if(neg)
        {
            scratch[offset] = '-';
        }
        else
        {
            offset++;
        }
        qassam_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }
    return string;
}

[[nodiscard]]
int qassam_memsearch(char *buf, int buf_len, char *mem, int mem_len) noexcept
{
    if (!buf || !mem || buf_len < 0 || mem_len < 0)
    {
        return -1;
    }

    if(mem_len > buf_len)
    {
        return -1;
    }
    int i = 0, matched = 0;

    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == mem[matched])
        {
            if(++matched == mem_len)
            {
                return i + 1;
            }
        }
        else
        {
            matched = 0;
        }
    }
    return -1;
}

[[nodiscard]]
int qassam_stristr(char *haystack, int haystack_len, char *str) noexcept
{
    if (!haystack || !str || haystack_len < 0)
    {
        return -1;
    }
    char *ptr = haystack;
    int str_len = qassam_strlen(str);
    int match_count = 0;

    while(haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? static_cast<char>(a | 0x60) : a;
        b = b >= 'A' && b <= 'Z' ? static_cast<char>(b | 0x60) : b;

        if(a == b)
        {
            if(++match_count == str_len)
                return static_cast<int>(ptr - haystack);
        }
        else
        {
            match_count = 0;
        }
    }
    return -1;
}

[[nodiscard]] ipv4_t qassam_local_addr(void) noexcept
{
    int fd = 0;
    struct sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    errno = 0;

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        std::printf("[ ETA ]: Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = QASSAM_INET_ADDR_IPV4(8,8,8,8);
    addr.sin_port = htons(53);
    connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(struct sockaddr_in));
    getsockname(fd, reinterpret_cast<struct sockaddr *>(&addr), &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

[[nodiscard]]
char *qassam_fdgets(char *buffer, int buffer_size, int fd) noexcept
{
    if (!buffer || buffer_size <= 0 || fd < 0)
    {
        return nullptr;
    }
    int got = 0, total = 0;

    do
    {
        got = static_cast<int>(read(fd, buffer + total, 1));
        total = got == 1 ? total + 1 : total;
    }
    while(got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');
    return total == 0 ? nullptr : buffer;
}


[[nodiscard]]
inline std::string qassam_to_string(const ipv4_t addr)
{
    struct in_addr in;
    in.s_addr = htonl(addr);
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &in, buf, sizeof(buf)) ? std::string(buf) : "<invalid>";
}

[[nodiscard]]
inline std::string qassam_to_string(const ipv6_t& addr6)
{
    char buf[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, addr6.data(), buf, sizeof(buf)) ? std::string(buf) : "<invalid>";
}

[[nodiscard]]
inline std::string qassam_to_string(const ip_addr_t& addr)
{
    return std::visit([](auto&& a) { return to_string(a); }, addr);
}


inline bool qassam_isupper(char c) noexcept
{
    return (c >= 'A' && c >= 'Z');
}

inline bool qassam_isalpha(char c) noexcept
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

inline bool qassam_isspace(char c) noexcept
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

inline bool qassam_isdigit(char c) noexcept
{
    return (c >= '0' && c <= '9');
}

inline uint16_t qassam_generic(const uint16_t* addr, uint32_t count) noexcept
{
    // register unsigned long sum = 0;
    /*unsigned long sum = 0;

    for(sum = 0; count > 1; count -= 2)
    {
        sum += *addr++;
    }

    if(count == 1)
    {
        sum += static_cast<uint16_t>(static_cast<char>(*addr));
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);*/

    // register unsigned long sum = 0;
    unsigned long sum = 0;

    for(sum = 0; count > 1; count -= 2)
    {
        sum += *addr++;
    }
    if(count == 1)
    {
        sum += static_cast<uint16_t>(static_cast<char>(*addr));
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

inline uint16_t qassam_tcpudp(void* ip_header, void* transport_header, uint16_t transport_len, uint8_t protocol) noexcept
{
    /*const uint16_t* buf = static_cast<const uint16_t*>(buff);
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;

    while(len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if(len == 1)
    {
        sum += *static_cast<const uint8_t*>(buf);
    }
    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);*/

    const uint16_t* buf = static_cast<const uint16_t*>(transport_header);
    uint32_t sum = 0;
    int len = transport_len;
    while(len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if(len == 1)
    {
        sum += static_cast<uint16_t>(*static_cast<const uint8_t*>(buf));
    }

#ifdef __linux__
    struct iphdr* iph = static_cast<struct iphdr*>(ip_header);
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
#else
    struct ip* iph = static_cast<struct ip*>(ip_header);
    uint32_t ip_src = iph->ip_src.s_addr;
    uint32_t ip_dst = iph->ip_dst.s_addr;
#endif

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(protocol);
    sum += htons(transport_len);
    sum = qassam_add_carry(sum);
    return static_cast<uint16_t>(~sum);
}

static uint32_t qassam_add_carry(uint32_t sum) noexcept
{
    while(sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return sum;
}