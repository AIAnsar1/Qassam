#pragma once

#ifndef QASSAM_QASSAM_GPON80_HH
#define QASSAM_QASSAM_GPON80_HH

#include "../qassam_engine.hh"
#include "../qassam_support.hh"
#include "../scanner/qassam_scanner.hh"
#include "iqassam_malw.hh"




class QassamGpon80 : public IQassamMalw, public QassamEngine, public QassamSupport, public QassamScanner, public QassamScannerConnection, public QassamScannerAuth
{
    
};

























#endif //QASSAM_QASSAM_GPON80_HH


