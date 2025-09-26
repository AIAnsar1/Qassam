#pragma once

#ifndef QASSAM_QASSAM_qassam_HH
#define QASSAM_QASSAM_qassam_HH


#include "qassam_engine.hh"


class QassamSupport
{
    public:
        int qassam_strlen(char *);
        bool qassam_strncmp(const char*, const char*, int);
        bool qassam_strcmp(const char*, const char*);
        int qassam_strcpy(char*, const char*);
        void qassam_strcat(char*, const char*);
        void qassam_memcpy(void*, const void*, int);
        void qassam_zero(void *, int);
        int qassam_atoi(const char*, int);
        char *qassam_itoa(int, int, char *);
        int qassam_memsearch(const char*, int, const char*, int);
        int qassam_stristr(const char*, int, const char*);
        ipv4_t qassam_local_addr(void);
        char *qassam_fdgets(char *, int, int);
        static inline bool qassam_isupper(char);
        static inline bool qassam_isalpha(char);
        static inline bool qassam_isspace(char);
        static inline bool qassam_isdigit(char);
};







#endif //QASSAM_QASSAM_qassam_HH