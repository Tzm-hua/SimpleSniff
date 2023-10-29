#ifndef MYTABLEMODEL_H
#define MYTABLEMODEL_H

#include <QAbstractTableModel>
#include "structureHeader.h"
#include <winsock2.h>

const u_int ETHER_HEADER_SIZE=14;

struct AllData {
    EthernetHeader *ethernetHeader;
    unsigned int dataLen;
    u_char * packet;
    QString subTime;
};
Q_DECLARE_METATYPE(AllData)



class MyTableModel : public QAbstractTableModel {
    Q_OBJECT

private:
    QList<AllData> dataList;

public:
    // ... 构造函数、析构函数等 ...

    QList<AllData> getDataList(){
        return dataList;
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override {
        Q_UNUSED(parent);
        return dataList.count();
    }

    int columnCount(const QModelIndex &parent = QModelIndex()) const override {
        Q_UNUSED(parent);
        return 10;
    }

    AllData getDataItem(int pos){
        if(pos>=0 && pos <dataList.count()){
            return dataList[pos];
        }
        AllData da;
        da.packet=nullptr;
        da.ethernetHeader=nullptr;
        return da;
    }

    void addData(const AllData &dataItem) {
        // 通知视图我们将在最后添加一行
        beginInsertRows(QModelIndex(), dataList.count(), dataList.count());
        AllData data;
        data.dataLen = dataItem.dataLen;
        data.packet = new u_char[data.dataLen];
        for(u_int pos=0; pos<data.dataLen; ++pos){
            data.packet[pos] = dataItem.packet[pos];
        }
        data.ethernetHeader = (EthernetHeader*)(dataItem.packet);
        data.subTime = dataItem.subTime;
        dataList.append(data);
        // 通知视图插入完成
        endInsertRows();
    }

    void clearData(){
        if (!dataList.isEmpty()) {
            beginRemoveRows(QModelIndex(), 0, dataList.count() - 1);
            dataList.clear();
            endRemoveRows();
        }
    }

    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override {
        if (!index.isValid())
            return QVariant();

        if (role == Qt::DisplayRole) {
            const AllData &allPacketData = dataList.at(index.row());
            EthernetHeader *ethernetHeader = allPacketData.ethernetHeader;
            u_int dataLen = allPacketData.dataLen;

            //处理IP数据包
            IPHeader *ipHeader = (IPHeader*)((u_char*)ethernetHeader + ETHER_HEADER_SIZE);
            u_int ipHeaderLen = (ipHeader->ver_ihl & 0xf) * 4;      //ip头部长度
            unsigned short ipLength = ipHeader->len;                //ip数据包总长度
            u_char Protocol = ipHeader->proto;                      //协议
            //源IP地址
            QString srcIp = QString::number(ipHeader->srcAddress.b1) + "." +
                            QString::number(ipHeader->srcAddress.b2) + "." +
                            QString::number(ipHeader->srcAddress.b3) + "." +
                            QString::number(ipHeader->srcAddress.b4);
            //目的IP地址
            QString destIp = QString::number(ipHeader->destAddress.b1) + "." +
                             QString::number(ipHeader->destAddress.b2) + "." +
                             QString::number(ipHeader->destAddress.b3) + "." +
                             QString::number(ipHeader->destAddress.b4);

            QString Info = "";
            QString protocol;

            QString SrcPort="",DestPort="";

            int tcp_or_udp=0;

            /* 处理传输层数据包 */
            if(ipHeader->proto==IPPROTO_TCP){   //处理TCP数据报文
                const TCPHeader* tcpHeader = (TCPHeader*)((u_char*)ipHeader + ipHeaderLen);     //获得tcp头部指针
                u_short srcPort = ntohs(tcpHeader->srcPort);               //源端口
                u_short destPort = ntohs(tcpHeader->destPort);             //目的端口
                u_int sequenceNum = ntohl(tcpHeader->sequenceNum);         //序号
                u_int ackNum = ntohl(tcpHeader->ackNum);                   //确认号
                u_char tcpFlags = u_char(ntohs(tcpHeader->flags) & 0x003F);        //6位标志位(ACK、SYN……)
                u_short tcpWindows = ntohs(tcpHeader->window);                     //窗口大小
                u_short tcpHeaderLen = ((ntohs(tcpHeader->flags) & 0xF000)>>12) * 4;        //tcp头部长度
                SrcPort = QString::number(srcPort); DestPort = QString::number(destPort);
                tcp_or_udp=0;

                protocol = "TCP";
                Info = QString("%1 → %2 ").arg(srcPort).arg(destPort);
                QString tempTcp="";
                if(((tcpFlags>>5)&1)!=0)
                    tempTcp += "URG, ";
                if(((tcpFlags>>4)&1)!=0)
                    tempTcp += "ACK, ";
                if(((tcpFlags>>3)&1)!=0)
                    tempTcp += "PSH, ";
                if(((tcpFlags>>2)&1)!=0)
                    tempTcp += "RST, ";
                if(((tcpFlags>>1)&1)!=0)
                    tempTcp += "SYN, ";
                if((tcpFlags&1)!=0)
                    tempTcp += "FIN, ";
                if(tempTcp.length()!=0)
                    tempTcp = "("+tempTcp.mid(0,tempTcp.length()-2)+")";
                else
                    tempTcp = "(None)";
                tempTcp[0]='['; tempTcp[tempTcp.length()-1]=']';
                Info = Info + tempTcp + QString(" Seq=%1 ").arg(sequenceNum);
                if(((tcpFlags>>4)&1) == 1)
                    Info += QString("Ack=%1 ").arg(ackNum);
                Info += QString("Win=%1").arg(tcpWindows);
                if(srcPort==53 || destPort==53){
                    DNSHeader *dnsHeader = (DNSHeader*)((u_char*)tcpHeader + tcpHeaderLen);
                    protocol = "DNS";
                    Info = "[协议：DNS]  " + Info;
                } else if(srcPort==80 || destPort==80){
                    protocol = "Http";
                    Info = "[协议：Http]  " + Info;
                } else if(srcPort==443 || destPort==443){
                    protocol = "Https";
                    Info = "[协议：Https]  " + Info;
                } else if(ipLength-ipHeaderLen == tcpHeaderLen){
                    protocol = "TCP";
                }
            }
            else if(ipHeader->proto==IPPROTO_UDP){  //处理UDP数据报文
                const UDPHeader* udpHeader = (UDPHeader*)((u_char*)ipHeader + ipHeaderLen);     //获得udp头部指针
                u_short srcPort = ntohs(udpHeader->srcPort);       //源端口
                u_short destPort = ntohs(udpHeader->destPort);     //目的端口
                u_short udpLength = ntohs(udpHeader->len);     //udp数据报长度
                tcp_or_udp=1;
                SrcPort = QString::number(srcPort); DestPort = QString::number(destPort);
                protocol = "UDP";
                Info = QString("%1 → %2 ").arg(srcPort).arg(destPort);

                if(srcPort==53 || destPort==53){
                    protocol = "DNS";
                    Info = "[协议：DNS]  " + Info;
                }
            }
            else{
                protocol = "Unknown";
                tcp_or_udp=2;
            }

            QString subTime = allPacketData.subTime;

            switch (index.column()) {
                case 0: return index.row()+1;
                case 1: return subTime;
                case 2: return srcIp;
                case 3: return destIp;
                case 4: return protocol;
                case 5: return dataLen;
                case 6: return Info;
                case 7: return SrcPort;
                case 8: return DestPort;
                case 9: return tcp_or_udp;
                default: return QVariant();
            }
        }
        return QVariant();
    }
\
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (role != Qt::DisplayRole)
            return QVariant();

        if (orientation == Qt::Horizontal) {
            switch (section) {
                case 0: return QString("No.");
                case 1: return QString("Time");
                case 2: return QString("Source");
                case 3: return QString("Destination");
                case 4: return QString("Protocol");
                case 5: return QString("Length");
                case 6: return QString("Info");
                case 7: return "Hidden Data Of SrcPort";
                case 8: return "Hidden Data Of DstPort";
                case 9: return "Hidden Data Of TCP_or_UDP";
            }
        } else if (orientation == Qt::Vertical) {
            // 如果你也想自定义行标题，可以在这里添加代码
        }
        return QVariant();
    }

    // ... 其他必要的实现，如headerData, setData, flags等 ...
};


#endif // MYTABLEMODEL_H
