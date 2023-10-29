#ifndef CUSTOMFILTERPROXYMODEL_H
#define CUSTOMFILTERPROXYMODEL_H

#include<QSortFilterProxyModel>
#include<winsock2.h>
#include"structureHeader.h"
#include"mytablemodel.h"

class CustomFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    CustomFilterProxyModel(QObject *parent = nullptr) : QSortFilterProxyModel(parent) {}

    void setDataF(QString addr="",QString por="",bool http=false, bool dns=false, bool tcp=false, bool udp=false){
        this->address = addr;
        this->port = por;
        this->http = http;
        this->dns = dns;
        this->tcp = tcp;
        this->udp = udp;
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override {

        QModelIndex index2 = sourceModel()->index(sourceRow, 2, sourceParent);  // 获取第3列的索引
        QModelIndex index3 = sourceModel()->index(sourceRow, 3, sourceParent);  // 获取第4列的索引
        QModelIndex index4 = sourceModel()->index(sourceRow, 4, sourceParent);  // 获取第5列的索引
        QModelIndex index7 = sourceModel()->index(sourceRow, 7, sourceParent);  // 获取第8列的索引
        QModelIndex index8 = sourceModel()->index(sourceRow, 8, sourceParent);  // 获取第9列的索引
        QModelIndex index9 = sourceModel()->index(sourceRow, 9, sourceParent);  // 获取第10列的索引

        // 获取数据
        QString srcIp = sourceModel()->data(index2).toString();     //源IP
        QString destIp = sourceModel()->data(index3).toString();    //目的IP
        QString protocol = sourceModel()->data(index4).toString();  //协议
        QString srcPort = sourceModel()->data(index7).toString();   //源端口
        QString destPort = sourceModel()->data(index8).toString();  //目的端口
        int tcp_or_udp = sourceModel()->data(index9).toInt();       //传输层协议 tcp|udp|其他

        bool addr=false,por=false,proto=false;
        if(address=="")    addr=true;
        else if(address==srcIp||address==destIp) addr=true;
        else    addr=false;
        if(port=="") por=true;
        else if(port==srcPort||port==destPort)   por=true;
        else    por=false;
        if(!tcp && !udp && !http && !dns)   proto=true;
        if(protocol=="Http" && http)    proto=true;
        if(protocol=="DNS" && dns)    proto=true;
        if((tcp_or_udp==0) && tcp)    proto=true;
        if((tcp_or_udp==1) && udp)    proto=true;
        if (addr && por && proto) {
            return true;
        } else {
            return false;
        }
    }

    QString address;
    QString port;
    bool http,dns,tcp,udp;
};


#endif // CUSTOMFILTERPROXYMODEL_H
