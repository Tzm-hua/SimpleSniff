#ifndef STRUCTUREHEADER_H
#define STRUCTUREHEADER_H

#include <winsock2.h>
#include <QString>

// IP address structure
struct IPAddress {
    u_char b1, b2, b3, b4;
};

// MAC address structure
struct MACAddress {
    u_char b1, b2, b3, b4, b5, b6;
    MACAddress(){}
    MACAddress(const u_char B1, const u_char B2, const u_char B3, const u_char B4, const u_char B5, const u_char B6){
        b1 = B1;
        b2 = B2;
        b3 = B3;
        b4 = B4;
        b5 = B5;
        b6 = B6;
    }
};

// Ethernet header structure
struct EthernetHeader {
    MACAddress destAddress;
    MACAddress srcAddress;
    u_short type;
};

// IP header structure
struct IPHeader {
    u_char ver_ihl, tos;
    u_short len, id, flags_offset;
    u_char ttl, proto;
    u_short checksum;
    IPAddress srcAddress, destAddress;
};

// UDP header structure
struct UDPHeader {
    u_short srcPort, destPort, len, checksum;
};

// TCP header structure
struct TCPHeader {
    u_short srcPort, destPort;
    u_int sequenceNum, ackNum;
    u_short flags, window, checksum, urgentPointer;
};

// DNS header structure
struct DNSHeader {
    u_short id, flags, questCount, ansCount, authRecordCount, addRecordCount;
};



#endif // STRUCTUREHEADER_H
