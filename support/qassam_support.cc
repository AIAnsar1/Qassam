#pragma once

#define _GNU_SOURCE
#include <algorithm>

#ifdef DEBUG
    #include <cstdio>  // для printf
#endif

#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <csignal>


#include "../kernel/qassam_support.hh"
#include "../kernel/qassam_engine.hh"


int QassamSupport::qassam_strlen(char *str)
{
    int c = 0;

    while (*str++ != 0) // or while(*str) { c++; str++; }
    {
        c++;
    }
    return c;
}

[[nodiscard]]
bool QassamSupport::qassam_strncmp(const char* str1, const char* str2, int len)
{
    int l1 = QassamSupport::qassam_strlen(str1), l2 = QassamSupport::qassam_strlen(str2);

    if (l1 < len || l2 < len)
    {
        return false;
    }

    for (int i = 0; i < len; ++i)
    {
        if (str1[i] != str2[i])
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]]
bool QassamSupport::qassam_strcmp(const char* str1, const char* str2)
{
    int l1 = QassamSupport::qassam_strlen(str1), l2 = QassamSupport::qassam_strlen(str2);

    if (l1 != l2)
    {
        return false;
    }

    for (int i = 0; i < l1; ++i)
    {
        if (str1[i] != str2[i])
        {
            return false;
        }
    }
    return true;

}



int QassamSupport::qassam_strcpy(char* dst, const char* src)
{
    int l = QassamSupport::qassam_strlen(src);

    for (int i = 0; i <= l; ++i)
    {
        dst[i] = src[i];
    }
    return l;
}


void QassamSupport::qassam_strcat(char* dest, const char* src)
{
    char* dest_end = dest;

    while (*dest_end != '\0')
    {
        dest_end++;
    }

    do
    {
        *dest_end++ = *src++;
    }while (*src != '\0');
    *dest_end = '\0';
}


void QassamSupport::qassam_memcpy(void* dst, const void* src, int len)
{
    char* r_dst = static_cast<char*>(dst);
    const char* r_src = static_cast<const char*>(src);

    for (int i = 0; i < len; ++i)
    {
        r_dst[i] = r_src[i];
        // or std::copy_n(static_cast<const char*>(src), len, static_cast<char*>(dst));
        // or std::memcpy(dst, src, len);
    }
}



void QassamSupport::qassam_zero(void* buf, int len)
{
    char* zero = static_cast<char*>(buf);

    for (int i = 0; i < len; ++i)
    {
        zero[i] = 0;
        // or std::fill_n(static_cast<char*>(buf), len, 0);
        // or std::memset(buf, 0, len);
    }
}

[[nodiscard]]
int QassamSupport::qassam_atoi(const char* str, int base)
{
    unsigned long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    do
    {
        c = *str++;
    }while (QassamSupport::qassam_isspace(c));

    if (c == '-')
    {
        neg = 1;
        c = *str++;
    }
    else if (c == '+')
    {
        c = *str++;
    }
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff * (unsigned long)base;
    cutoff /= (unsigned long)base;


    for (acc = 0, any = 0;; c = *str++)
    {
        if (QassamSupport::qassam_isdigit(c))
        {
            c -= '0';
        }
        else if (QassamSupport::qassam_isalpha(c))
        {
            c -= QassamSupport::qassam_isupper(c) ? 'A' - 10 : 'a' - 10;
        }
        else
        {
            break;
        }

        if (c >= base)
        {
            break;
        }

        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
        {
            any = -1;
        }
        else
        {
            any = 1;
            acc *= base;
            acc += c;
        }
    }


    if(any < 0)
    {
        acc = neg ? LONG_MIN : LONG_MAX;
    }
    else if(neg)
    {
        acc = -acc;
    }
    return static_cast<int>(acc);
}


char *QassamSupport::qassam_itoa(int value, int radix, char* string)
{
    if (string == nullptr)
    {
        return nullptr;
    }

    if (value != 0)
    {
        char scratch[34];
        int neg = 0;
        int offset = 32;
        int c = 0;
        unsigned int accum;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = static_cast<unsigned int>(value);
        }

        while (accum)
        {
            c = accum % radix;

            if (c < 10)
            {
                c += '0';
            }
            else
            {
                c += 'A' - 10;
            }
            scratch[offset--] = static_cast<char>(c);
        }

        if(neg)
        {
            scratch[offset--] = '-';
        }

        for(int i = offset + 1; scratch[i] != 0; ++i)
        {
            *string++ = scratch[i];
        }
        *string = 0;
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }
    return string;
}

[[nodiscard]]
int QassamSupport::qassam_memsearch(const char* buf, int buf_len, const char* mem, int mem_len)
{
    if (mem_len > buf_len)
    {
        return -1;
    }

    for (int i = 0; i <= buf_len - mem_len; i++)
    {
        if (buf[i] == mem[0])
        {
            bool match = true;

            for (int j = 1; j < mem_len; j++)
            {
                if (buf[i + j] != mem[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                return i + 1;
            }
        }
    }
    return -1;
}

[[nodiscard]]
int QassamSupport::qassam_stristr(const char* haystack, int haystack_len, const char* str)
{
    int str_len = QassamSupport::qassam_strlen(str);

    for (int i = 0; i <= haystack_len - str_len; i++)
    {
        bool match = true;

        for (int j = 0; j < str_len; j++)
        {
            char a = haystack[i + j];
            char b = str[j];
            a = (a >= 'A' && a <= 'Z') ? a | 0x60 : a;
            b = (b >= 'A' && b <= 'Z') ? b | 0x60 : b;

            if(a != b)
            {
                match = false;
                break;
            }
        }
        if(match)
        {
            return i + 1;
        }
    }
    return -1;
}

[[nodiscard]]
ipv4_t QassamSupport::qassam_local_addr(void)
{
    int fd = 0;
    struct sockaddr_in addr = {0};
    socklen_t addr_len = sizeof(addr);
    errno = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        std::printf("[ ETA ]: Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = QASSAM_INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);
    connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr_in));
    getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}


char *QassamSupport::qassam_fdgets(char* buffer, int buffer_size, int fd)
{
    if(buffer_size <= 0)
    {
        return nullptr;
    }
    int total = 0;
    char c;

    while(total < buffer_size - 1)
    {
        ssize_t got = read(fd, &c, 1);
        if(got <= 0) break;
        buffer[total++] = c;
        if(c == '\n') break;
    }

    if(total == 0)
    {
        return nullptr;
    }
    buffer[total] = 0;
    return buffer;
}


inline bool QassamSupport::qassam_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}


inline bool QassamSupport::qassam_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}


inline bool QassamSupport::qassam_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

inline bool QassamSupport::qassam_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}



























