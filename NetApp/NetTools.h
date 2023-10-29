#ifndef NETTOOLS_H
#define NETTOOLS_H

#include <iostream>
#include <ctime>
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#include "windows.h"
#include <QString>
#include <QStringList>


using namespace std;



//get the Net device interface
QStringList getNetDevices(){
    QStringList QSList;

    pcap_if_t* alldevs;
    pcap_if_t* device;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /*获取本地机器设备列表*/
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        return QSList;
    }

    /*打印列表*/
    for (device = alldevs; device != NULL; device = device->next)
    {
        string tempStr = to_string(++i);
        tempStr += ". ";
        if (device->description){
            string ss = "" + string(device->description);
            tempStr = tempStr + ss;
        }
        else
            tempStr = tempStr + "No description available";
        QSList << QString::fromStdString(tempStr);
    }

    if (i == 0)
    {
        QSList << "No interfaces found!Make sure WinPcap is installed.";
        pcap_freealldevs(alldevs);
        return QSList;
    }
    pcap_freealldevs(alldevs);
    return QSList;
}


// Function to print data in hex format
void printDataInHex(const u_char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 32 == 0) // Print new line every 16 bytes
            printf("\n");
    }
    printf("\n");
}

#endif // NETTOOLS_H

