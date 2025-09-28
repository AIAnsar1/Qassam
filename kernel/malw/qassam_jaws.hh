#pragma once

#ifndef QASSAM_QASSAM_JAWS_HH
#define QASSAM_QASSAM_JAWS_HH


#include "../qassam_engine.hh"
#include "../qassam_support.hh"
#include "../scanner/qassam_scanner.hh"
#include "iqassam_malw.hh"

class QassamJaws : public IQassamMalw, public QassamEngine, public QassamSupport, public QassamScanner, public QassamScannerConnection, public QassamScannerAuth
{

};

























#endif //QASSAM_QASSAM_JAWS_HH


