#ifndef STOPCAPTURE_H
#define STOPCAPTURE_H

#include <QElapsedTimer>

class StopCapture
{
public:
    StopCapture();
    static bool stopTable;
    static void startTimer();
    static qint64 elapsed();
    static QElapsedTimer timer;
};


#endif // STOPCAPTURE_H
