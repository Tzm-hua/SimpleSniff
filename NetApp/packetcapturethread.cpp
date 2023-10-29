#include "packetcapturethread.h"
#include "structureHeader.h"
using namespace std;

const int ETHER_HEADER_SIZE = 14;
static int countData = 0;

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    PacketCaptureThread* threadInstance = reinterpret_cast<PacketCaptureThread*>(userData);
    if (StopCapture::stopTable) {
        pcap_breakloop(PacketCaptureThread::handleShare);  // 使用类的句柄成员变量
        return;
    }

    double elapsedSeconds = (StopCapture::timer).nsecsElapsed() / 1e9; // 1e9 纳秒是1秒
    QString subTime = QString::number(elapsedSeconds, 'f', 6) + "s";
    threadInstance->handlePacket(packet, pkthdr->caplen, subTime);
}


PacketCaptureThread::PacketCaptureThread(const QString &deviceName, QObject *parent)
    : QThread(parent), deviceName(deviceName) {}

void PacketCaptureThread::run()
{
    /* deviceName是接口名称 */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle=pcap_open(deviceName.toStdString().c_str(),
                             65536,
                             PCAP_OPENFLAG_PROMISCUOUS,
                             1000,
                             NULL,
                             errbuf);
    if (handle == nullptr)  return;
    if(pcap_datalink(handle) != DLT_EN10MB) return;
    struct bpf_program fp; // The compiled filter
    char filter_exp[] = "ip and (tcp or udp) and (port 53 or port 80 or port 443)";

    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1)  return;
    if (pcap_setfilter(handle, &fp) == -1)  return;

    //共享变量
    handleShare = handle;
    (StopCapture::timer).start();

    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this)); // 0 means loop forever
    pcap_close(handle);
}

pcap_t* PacketCaptureThread::handleShare = NULL;
