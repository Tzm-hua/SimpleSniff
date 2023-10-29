#ifndef PACKETCAPTURETHREAD_H
#define PACKETCAPTURETHREAD_H

#include <QThread>
#include <QString>
#include <pcap.h>
#include "structureHeader.h"
#include "stopcapture.h"

class PacketCaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit PacketCaptureThread(const QString &deviceName, QObject *parent = nullptr);
    void run() override;
    void handlePacket(const u_char *packet, int len, QString subTime) {
        emit packetCaptured(packet, len, subTime);
    }
    static pcap_t *handleShare;

signals:
    void packetCaptured(const u_char *, const unsigned int, QString);

private:
    QString deviceName;
};


#endif // PACKETCAPTURETHREAD_H
