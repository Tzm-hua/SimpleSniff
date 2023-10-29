#include "stopcapture.h"

StopCapture::StopCapture()
{

}


void StopCapture::startTimer() {
    timer.start();
}

qint64 StopCapture::elapsed() {
    return timer.elapsed();
}


bool StopCapture::stopTable=false;
QElapsedTimer StopCapture::timer;
