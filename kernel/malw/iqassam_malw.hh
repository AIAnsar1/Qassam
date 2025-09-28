#pragma once

#ifndef QASSAM_IQASSAM_MALW_HH
#define QASSAM_IQASSAM_MALW_HH


#ifdef DEBUG
inline constexpr int QASSAM_MALW_SCANNER_MAX_CONNS = 3;
inline constexpr int QASSAM_MALW_SCANNER_RAW_PPS = 788;
#else
inline constexpr int QASSAM_MALW_SCANNER_MAX_CONNS = 256;
inline constexpr int QASSAM_MALW_SCANNER_RAW_PPS = 788;
#endif

#define GPON443_SCANNER_RDBUF_SIZE  1080
#define GPON443_SCANNER_HACK_DRAIN  64


class IQassamMalw
{
    public:

};









































#endif //QASSAM_IQASSAM_MALW_HH


