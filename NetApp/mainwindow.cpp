#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>
#include "structureHeader.h"
#include <cstring>
#include <QTreeWidgetItem>
#include <QSortFilterProxyModel>


using namespace std;

bool showData(int index);
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    deviceNameC = "";
    actionGroup = new QActionGroup(this);

    initInterfacesMenu();
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::initInterfacesMenu()
{
    //UI初始化
    ui->plainTextEdit->setReadOnly(true);
    ui->plainTextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    ui->plainTextEdit->setWordWrapMode(QTextOption::NoWrap);
    ui->plainText_Device->setReadOnly(true);
    ui->treeWidget->setHeaderHidden(true);
    ui->treeWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    ui->plainText_Device->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    menuInterfaces = menuBar()->addMenu("选择网络设备接口");
    stopMenu = menuBar()->addMenu("停止");    stopTable=false;

    //获取设备接口列表
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return;
    }
    int pos = 0;
    for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next) {
        QString device = QString::number(++pos) + ". " + QString::fromStdString(dev->name)
                         + "(" + QString::fromStdString(dev->description) + ")";
        QAction *action = menuInterfaces->addAction(device);
        action->setCheckable(true);
        action->setData(QVariant::fromValue(MenuItemDevice(dev->name,dev->description)));
        actionGroup->addAction(action);
    }
    //设置触发器
    connect(actionGroup, &QActionGroup::triggered, this, &MainWindow::onInterfaceSelected);
    connect(stopMenu, &QMenu::aboutToShow, this, &MainWindow::onClickedStopMenu);
    //释放接口权柄
    pcap_freealldevs(alldevs);

    // 创建一个正则表达式，用于验证IPv4地址
    QRegularExpression ipRegex("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    QValidator *ipValidator = new QRegularExpressionValidator(ipRegex, ui->lineEdit_Address);
    QValidator *portValidator = new QIntValidator(0, 65535, ui->lineEdit_Port);

    // 将验证器设置到QLineEdit控件
    ui->lineEdit_Address->setValidator(ipValidator);
    ui->lineEdit_Port->setValidator(portValidator);

    model = new MyTableModel();
    proxyModel = new CustomFilterProxyModel();
    proxyModel->setSourceModel(model);

    //设置tableView初始化界面参数
    ui->tableView->setModel(proxyModel);
    ui->tableView->setShowGrid(false);
    ui->tableView->verticalHeader()->setVisible(false);
    ui->tableView->setColumnHidden(7,true);
    ui->tableView->setColumnHidden(8,true);
    ui->tableView->setColumnHidden(9,true);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    //设置触发器
    connect(ui->tableView, &QTableView::clicked, this, &MainWindow::handleTableRowClicked);
}

void MainWindow::onInterfaceSelected(QAction *action)
{
    if (action) {
        StopCapture::stopTable = false;
        model->clearData();
        MenuItemDevice selectedDevice = action->data().value<MenuItemDevice>();
        QString deviceName = selectedDevice.deviceName;
        deviceNameC = deviceName;       //接口名称
        ui->plainText_Device->setPlainText(selectedDevice.deviceName + "(" + selectedDevice.deviceDescription + ")");

        PacketCaptureThread *captureThread = new PacketCaptureThread(deviceName, this);
        connect(captureThread, &PacketCaptureThread::packetCaptured, this, &MainWindow::addPacketData);
        captureThread->start();
    }
}

void MainWindow::onClickedStopMenu(){
    StopCapture::stopTable = true;
}

void MainWindow::addPacketData(const u_char *packet, const u_int dataLen,QString subTime)
{

    AllData allPacketData;
    allPacketData.packet = new u_char[dataLen];
    for(u_int pos=0; pos<dataLen; ++pos){
        allPacketData.packet[pos] = packet[pos];
    }
    allPacketData.ethernetHeader = (EthernetHeader*)(allPacketData.packet);
    EthernetHeader *ethernetHeader = allPacketData.ethernetHeader;
    allPacketData.dataLen = dataLen;
    allPacketData.subTime = subTime;
    model->addData(allPacketData);

}


QString MainWindow::protocolNameFromNumber(u_char proto){
//    struct protoent *pe = getprotobynumber(proto);
//    if (pe) {
//        return QString::fromLatin1(pe->p_name);
//    } else {
//        return QStringLiteral("Unknown");
//    }


    static QMap<int, QString> protocolMap = {
                {0,"HOPOPT (IPv6 Hop-by-Hop Option（IPv6 逐跳选项）)"},
                {1, "ICMP (Internet Control Message Protocol（Internet 消息控制协议）)"},
                {2, "GGP (Gateway to Gateway Protocol（网关对网关）)"},
                {3, "IGMP (Internet Group Management Protocol（Internet 组管理协议）)"},
                {4, "IP (IP in IP(encapsulation)（被IP协议封装的IP）)"},
                {5, "ST (Stream)"},
                {6, "TCP (Transmission Control Protocol（传输控制协议）)"},
                {7, "CBT (CBT)"},
                {8, "EGP (Exterior Gateway Protocol（外部网关协议）)"},
                {9, "IGP (any private interior gateway(used by Cisco for their IGRP) （任何专用内部网关，思科将其用于IGRP）)"},
                {17, "UDP (User Datagram Protocol（用户数据报协议）)"},
                {20, "HMP (Host Monitoring（主机监视）)"},
                {41, "IPV6 (IPV6)"},
                {43, "IPV6-Route (Routing Header for IPv6（IPv6 的路由标头）)"},
                {44, "IPV6-Frag (Fragment Header for IPv6（IPv6 的片断标头）)"},
                {46, "RSVP (Resource Reservation Protocol（资源预留协议）)"},
                {47, "GRE (Generic Routing Encapsulation（通用路由封装）)"},
                {50, "ESP (Encap Security Payload（IPv6 的封装安全负载）)"},
                {51, "AH (Authentication Header（IPv6 的身份验证标头）)"},
                {54, "NARP (Protocol（NARP，NBMA 地址解析协议）、NBMA Next Hop Resolution Protocol（NHRP，NBMA下一跳解析协议）)"},
                {58, "IPV6-ICMP (ICMP for IPv6（用于 IPv6 的 ICMP）)"},
                {59, "IPV6-NoNxt (No Next Header for IPv6（用于 IPv6 的无下一个标头）	)"},
                {60, "IPV6-Opts (Destination Options for IPv6（IPv6 的目标选项）)"},
                {88, "IGRP (Cisco Internet Gateway Routing Protocol（思科Internet网关路由选择协议）)"},
                {89, "OSPF (Open Shortest Path First（开放式最短路径优先）)"},
                {103, "PIM (Protocol Independent Multicast（独立于协议的多播）)"},
                {112, "VRRP (Virtual Router Redundancy Protocol（虚拟路由器冗余协议）	)"},
                {115, "L2TP (Layer Two Tunneling Protocol（第二层隧道协议）)"},
                {132, "STCP (Stream Control Transmission Protocol（流控制传输协议）	)"}
            };

    return protocolMap.value(proto, "Unknown");
}

QString MainWindow::IpToQStr(IPAddress ipAddress){
    QString Ip = "";
    Ip = Ip + QString::number(ipAddress.b1) + "." +
              QString::number(ipAddress.b2) + "." +
              QString::number(ipAddress.b3) + "." +
              QString::number(ipAddress.b4);
    return Ip;
}

QString MainWindow::MacToQStr(MACAddress macAddress){
    QString B1 = QString::number(macAddress.b1>>4,16).toUpper() + QString::number(macAddress.b1 & 0x0f,16).toUpper();
    QString B2 = QString::number(macAddress.b2>>4,16).toUpper() + QString::number(macAddress.b2 & 0x0f,16).toUpper();
    QString B3 = QString::number(macAddress.b3>>4,16).toUpper() + QString::number(macAddress.b3 & 0x0f,16).toUpper();
    QString B4 = QString::number(macAddress.b4>>4,16).toUpper() + QString::number(macAddress.b4 & 0x0f,16).toUpper();
    QString B5 = QString::number(macAddress.b5>>4,16).toUpper() + QString::number(macAddress.b5 & 0x0f,16).toUpper();
    QString B6 = QString::number(macAddress.b6>>4,16).toUpper() + QString::number(macAddress.b6 & 0x0f,16).toUpper();
    QString mac = "";
    mac = mac + B1 + ":" +  B2 + ":" + B3 + ":" + B4 + ":" + B5 + ":" + B6;
    return mac;
}

QString MainWindow::formatPacketData(const QByteArray& data) {
    QString formatted;
    const int bytesPerRow = 16;

    for(int i = 0; i < data.size(); i += bytesPerRow) {
        QString hexPart;
        QString asciiPart;

        for(int j = 0; j < bytesPerRow; ++j) {
            if(i + j < data.size()) {
                unsigned char byte = static_cast<unsigned char>(data[i + j]);
                hexPart.append(QString::number(byte, 16).rightJustified(2, '0').toUpper() + " ");

                if(byte >= 32 && byte < 127) {
                    asciiPart.append(static_cast<char>(byte));
                } else {
                    asciiPart.append('.');
                }
            } else {
                hexPart.append("   ");
            }
        }

        formatted.append(QString::number(i, 16).rightJustified(4, '0').toUpper());
        formatted.append("  " + hexPart + "  " + asciiPart);
        formatted.append("\n");
    }

    return formatted;
}

QString MainWindow::TCPFlags(u_char flags){
    QString temp="";
    if(((flags>>5)&1)!=0)
        temp += "URG, ";
    if(((flags>>4)&1)!=0)
        temp += "ACK, ";
    if(((flags>>3)&1)!=0)
        temp += "PSH, ";
    if(((flags>>2)&1)!=0)
        temp += "RST, ";
    if(((flags>>1)&1)!=0)
        temp += "SYN, ";
    if((flags&1)!=0)
        temp += "FIN, ";
    if(temp.length()!=0)
        temp = "("+temp.mid(0,temp.length()-2)+")";
    else
        temp = "(None)";
    return temp;
}


void MainWindow::processTcp(const TCPHeader *tcpHeader){
    //解析tcp数据包
    u_short srcPort = ntohs(tcpHeader->srcPort);               //源端口
    u_short destPort = ntohs(tcpHeader->destPort);             //目的端口
    u_int sequenceNum = ntohl(tcpHeader->sequenceNum);         //序号
    u_int ackNum = ntohl(tcpHeader->ackNum);                   //确认号
    u_short tcpHeaderLen = ((ntohs(tcpHeader->flags) & 0xF000)>>12) * 4;        //tcp头部长度
    u_char tcpRemain = (ntohs(tcpHeader->flags) & 0x0FC0);             //6位保留
    u_char tcpFlags = u_char(ntohs(tcpHeader->flags) & 0x003F);        //6位标志位(ACK、SYN……)
    u_short tcpWindows = ntohs(tcpHeader->window);                     //窗口大小
    QString tcpChecksum = QString::number(ntohs(tcpHeader->checksum),16).toUpper();       //校验和
    u_short tcpUrgentPoint = ntohs(tcpHeader->urgentPointer);          //紧急指针
    //添加到TreeWidget中
    QString TcpStr = QString("Tranmission Control Protocol, Src Port: %1, Dst Port: %2, Seq:  %3").arg(srcPort).arg(destPort).arg(sequenceNum);
    if(((tcpFlags>>4)&1) != 0)
        TcpStr = TcpStr + QString(", Ack: %1").arg(ackNum);
    QString srcportTcpStr = QString("Source Port:  %1").arg(srcPort);
    QString destportTcpStr = QString("Destination Port:  %1").arg(destPort);
    QString seqTcpStr = QString("Sequence Number:  %1").arg(sequenceNum);
    QString lenTcpStr = QString::number(tcpHeaderLen>>2, 2).rightJustified(4, '0')+QString("  . . . .   = Header Length:  %1 bytes (%2)").arg(tcpHeaderLen).arg(tcpHeaderLen>>2);
    QString flagsTcpStr = QString("Flags:  0x%1").arg((QString::number(tcpFlags, 16).rightJustified(3, '0').toUpper()))+"  ";
    flagsTcpStr += TCPFlags(tcpFlags);
    QString windowsTcpStr = QString("Window Size:  %1").arg(tcpWindows);
    QString checksumTcpStr = QString("Checksum:  0x%1").arg((QString::number(tcpFlags, 16).rightJustified(4, '0').toUpper()));
    QString urgentpointTcpStr = QString("Urgent Pointer:  %1").arg(tcpUrgentPoint);
    QTreeWidgetItem *tcpItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << TcpStr);
    QTreeWidgetItem *tcpItem_1 = new QTreeWidgetItem(tcpItem, QStringList() << srcportTcpStr);
    QTreeWidgetItem *tcpItem_2 = new QTreeWidgetItem(tcpItem, QStringList() << destportTcpStr);
    QTreeWidgetItem *tcpItem_3 = new QTreeWidgetItem(tcpItem, QStringList() << seqTcpStr);
    QTreeWidgetItem *tcpItem_4 = new QTreeWidgetItem(tcpItem, QStringList() << lenTcpStr);
    if(((tcpFlags>>4)&1)!=0){
        QString ackTcpStr = QString("Acknowledgment Number:  %1").arg(ackNum);
        QTreeWidgetItem *tcpItem_5 = new QTreeWidgetItem(tcpItem, QStringList() << ackTcpStr);
    } else{
         QTreeWidgetItem *tcpItem_5 = new QTreeWidgetItem(tcpItem, QStringList() << "Acknowledgment Number:  None");
    }
    QTreeWidgetItem *tcpItem_6 = new QTreeWidgetItem(tcpItem, QStringList() << flagsTcpStr);
    QTreeWidgetItem *tcpItem_7 = new QTreeWidgetItem(tcpItem, QStringList() << windowsTcpStr);
    QTreeWidgetItem *tcpItem_8 = new QTreeWidgetItem(tcpItem, QStringList() << checksumTcpStr);
    if(((tcpFlags>>5)&1)!=0)
        QTreeWidgetItem *tcpItem_9 = new QTreeWidgetItem(tcpItem, QStringList() << urgentpointTcpStr);
}

void MainWindow::processUdp(const UDPHeader *udpHeader){
    //解析UDP数据包
    u_short srcPort = ntohs(udpHeader->srcPort);       //源端口
    u_short destPort = ntohs(udpHeader->destPort);     //目的端口
    u_short udpLength = ntohs(udpHeader->len);         //udp数据包总长度
    u_short udpChecksum = ntohs(udpHeader->checksum);      //校验和

    //添加到TreeWidget中
    QString UdpStr = QString("User Datagram Protocol, Src Port: %1, Dst Port: %2").arg(srcPort).arg(destPort);
    QTreeWidgetItem *udpItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << UdpStr);
    QString srcPortUdpStr = QString("Source Port:  %1").arg(srcPort);
    QString destPortUdpStr = QString("Destination Port:  %1").arg(destPort);
    QString lengthUdpStr = QString("Length:  %1").arg(udpLength);
    QString checksumUdpStr = QString("Checksum:  0x%1").arg((QString::number(udpChecksum, 16).rightJustified(4, '0').toUpper()));
    QString payloadUdpStr = QString("UDP payload:  (%1 bytes)").arg(udpLength-8);

    QTreeWidgetItem *udpItem_1 = new QTreeWidgetItem(udpItem, QStringList() << srcPortUdpStr);
    QTreeWidgetItem *udpItem_2 = new QTreeWidgetItem(udpItem, QStringList() << destPortUdpStr);
    QTreeWidgetItem *udpItem_3 = new QTreeWidgetItem(udpItem, QStringList() << lengthUdpStr);
    QTreeWidgetItem *udpItem_4 = new QTreeWidgetItem(udpItem, QStringList() << checksumUdpStr);
    QTreeWidgetItem *udpItem_5 = new QTreeWidgetItem(udpItem, QStringList() << payloadUdpStr);
}

void MainWindow::processIp(const IPHeader *ipHeader){
    /* 处理IP数据包 */
    u_int ipHeaderLen = (ipHeader->ver_ihl & 0xf) * 4;      //ip头部长度
    u_char ipVersion = (ipHeader->ver_ihl & 0xf0)>>4;          //ip版本号
    u_char ipServiceType = ipHeader->tos;                       //ip服务类型
    unsigned short ipLength = ntohs(ipHeader->len);                //ip数据包总长度
    u_short ipIdentify = ntohs(ipHeader->id);                      //标识
    u_short ipFragments = (ntohs(ipHeader->flags_offset))>>13;    //切片标志位
    u_short ipOffset = (ntohs(ipHeader->flags_offset) & 0x1FFF);       //片偏移
    u_char TTL = ipHeader->ttl;                             //生存时间
    QString Protocol = protocolNameFromNumber(ipHeader->proto);                      //协议
    u_short ipChecksum = ntohs(ipHeader->checksum);                //校验和
    //源IP地址
    QString srcIp = IpToQStr(ipHeader->srcAddress);
    //目的IP地址
    QString destIp = IpToQStr(ipHeader->destAddress);
    //添加到TreeWidget中
    QString IpStr = QString("Internet Protocol Version 4, Src: %1, Dst: %2").arg(srcIp).arg(destIp);
    QTreeWidgetItem *ipItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << IpStr);
    QString versionIpStr = QString("%1").arg(ipVersion, 4, 2, QChar('0'))+"  . . . . = Version:  " + QString::number(ipVersion);
    QTreeWidgetItem *ipItem_1 = new QTreeWidgetItem(ipItem, QStringList() << versionIpStr);
    QString headerLenIpStr = ". . . .   "+QString("%1").arg(ipHeaderLen>>2, 4, 2, QChar('0'))+" = Header Length:  " + QString::number(ipHeaderLen)+" bytes ("+QString::number(ipHeaderLen>>2)+")";
    QTreeWidgetItem *ipItem_2 = new QTreeWidgetItem(ipItem, QStringList() << headerLenIpStr);
    QString serviceTypeIpStr = QString("IP Service Type:  %1").arg(ipServiceType);
    QTreeWidgetItem *ipItem_3 = new QTreeWidgetItem(ipItem, QStringList() << serviceTypeIpStr);
    QString totalLengthIpStr = QString("Total Length:  %1").arg(ipLength);
    QTreeWidgetItem *ipItem_4 = new QTreeWidgetItem(ipItem, QStringList() << totalLengthIpStr);
    QString identifyIpStr = "Identification: 0x"+QString::number(ipIdentify, 16).rightJustified(4, '0').toUpper()+QString(" (%1)").arg(ipIdentify);
    QTreeWidgetItem *ipItem_5 = new QTreeWidgetItem(ipItem, QStringList() << identifyIpStr);
    QString flagsIpStr = QString("%1").arg(ipFragments, 3, 2, QChar('0'))+".   . . . .  = Flags: 0x"+QString::number(ipFragments,16);
    QTreeWidgetItem *ipItem_6 = new QTreeWidgetItem(ipItem, QStringList() << flagsIpStr);
    QString offsetIpStr_pre = QString::number(ipOffset, 2).rightJustified(13, '0').toUpper();
    QString offsetIpStr = ". . . "+offsetIpStr_pre[0]+"  "+offsetIpStr_pre.mid(1,4)+"  "+offsetIpStr_pre.mid(5,4)+"  "+offsetIpStr_pre.mid(9,4)+" = Fragment Offset:  "+QString::number(ipOffset);
    QTreeWidgetItem *ipItem_7 = new QTreeWidgetItem(ipItem, QStringList() << offsetIpStr);
    QString ttlIpStr = QString("Time to Live:  %1").arg(TTL);
    QTreeWidgetItem *ipItem_8 = new QTreeWidgetItem(ipItem, QStringList() << ttlIpStr);
    QString protocolIpStr = QString("Protocol:  %1 (%2)").arg(Protocol).arg(ipHeader->proto);
    QTreeWidgetItem *ipItem_9 = new QTreeWidgetItem(ipItem, QStringList() << protocolIpStr);
    QString checksumIpStr = QString("Header Checksum:  0x%1").arg((QString::number(ipChecksum, 16).rightJustified(4, '0').toUpper()));
    QTreeWidgetItem *ipItem_10 = new QTreeWidgetItem(ipItem, QStringList() << checksumIpStr);
    QString srcaddIpStr = QString("Source Address:  %1").arg(srcIp);
    QTreeWidgetItem *ipItem_11 = new QTreeWidgetItem(ipItem, QStringList() << srcaddIpStr);
    QString destaddIpStr = QString("Destination Address:  %1").arg(destIp);
    QTreeWidgetItem *ipItem_12 = new QTreeWidgetItem(ipItem, QStringList() << destaddIpStr);
}

void MainWindow::processEthernet(const EthernetHeader *ethernetHeader){
    //目的MAC地址
    QString destMac = MacToQStr(ethernetHeader->destAddress);
    //源MAC地址
    QString srcMac = MacToQStr(ethernetHeader->srcAddress);
    //帧类型
    unsigned short macType = ntohs(ethernetHeader->type);
    //添加到TreeWidget中
    QString EthernetStr = QString("Ethernet II,  SRC: (%1), DST:  (%2)").arg(srcMac).arg(destMac);
    QTreeWidgetItem *ethernetItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << EthernetStr);
    QTreeWidgetItem *ethernetItem_1 = new QTreeWidgetItem(ethernetItem, QStringList() << QString("Destination:    %1").arg(destMac));
    QTreeWidgetItem *ethernetItem_2 = new QTreeWidgetItem(ethernetItem, QStringList() << QString("Source:    %1").arg(srcMac));
    QTreeWidgetItem *ethernetItem_3 = new QTreeWidgetItem(ethernetItem, QStringList() << QString("Type:    0x%1").arg(QString::number(macType,16).rightJustified(4,'0').toUpper()));
}

void MainWindow::processDNS(const DNSHeader *dnsHeader){
    u_short dnsIdentifier = ntohs(dnsHeader->id);
    u_short dnsFlags = ntohs(dnsHeader->flags);
    u_short dnsQuestCount = ntohs(dnsHeader->questCount);
    u_short dnsAnsCount = ntohs(dnsHeader->ansCount);
    u_short dnsAuthCount = ntohs(dnsHeader->authRecordCount);
    u_short dnsAddCount = ntohs(dnsHeader->addRecordCount);
    QString dnsStr = "Domain Name System";
    QString dnsIDStr = QString("Transaction ID: 0x%1").arg((QString::number(dnsIdentifier,16).rightJustified(4,'0').toUpper()));
    QString dnsFlagsStr = QString("Flags:  0x%1").arg((QString::number(dnsFlags,16).rightJustified(4,'0').toUpper()));
    QString dnsQuestStr = QString("Question:  %1").arg(dnsQuestCount);
    QString dnsAnsRRs = QString("Answer RRs:  %1").arg(dnsAnsCount);
    QString dnsAuthRRs = QString("Authority RRs:  %1").arg(dnsAuthCount);
    QString dnsAddRrs = QString("Additional RRs:  %1").arg(dnsAddCount);

    QTreeWidgetItem *dnsItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << dnsStr);
    QTreeWidgetItem *dnsItem_1 = new QTreeWidgetItem(dnsItem, QStringList() << dnsIDStr);
    QTreeWidgetItem *dnsItem_2 = new QTreeWidgetItem(dnsItem, QStringList() << dnsFlagsStr);
    QTreeWidgetItem *dnsItem_3 = new QTreeWidgetItem(dnsItem, QStringList() << dnsQuestStr);
    QTreeWidgetItem *dnsItem_4 = new QTreeWidgetItem(dnsItem, QStringList() << dnsAnsRRs);
    QTreeWidgetItem *dnsItem_5 = new QTreeWidgetItem(dnsItem, QStringList() << dnsAuthRRs);
    QTreeWidgetItem *dnsItem_6 = new QTreeWidgetItem(dnsItem, QStringList() << dnsAddRrs);
}

void MainWindow::processHTTP(const u_char *httpHeaderOffset, u_int httpLength){
    const char* httpOffset = reinterpret_cast<const char*>(httpHeaderOffset);
    QByteArray httpData(httpOffset, httpLength);
    QString httpString(httpData);
    QString httpStr = QString("Hypertext Transfer Protocol");
    QString detailsHttpStr = httpString;

    QTreeWidgetItem *httpItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << httpStr);
    QTreeWidgetItem *httpItem_1 = new QTreeWidgetItem(httpItem, QStringList() << detailsHttpStr);
}

void MainWindow::printDataBinaryInHex(const u_char *packet, unsigned int packetLength){
    //以十六进制打印数据包的二进制流
    QByteArray plainText;
    plainText.append(reinterpret_cast<const char*>(packet), packetLength);
    QString formattedData = formatPacketData(plainText);
    ui->plainTextEdit->setPlainText(formattedData);
}

int MainWindow::cCount = 0; // 初始化为0

void MainWindow::on_pushButton_Assure_clicked()
{

}

void MainWindow::on_pushButton_Filter_clicked()
{
    QString ipAddress = ui->lineEdit_Address->text();
    QString port = ui->lineEdit_Port->text();
    bool http = ui->checkBox_http->isChecked();
    bool dns = ui->checkBox_dns->isChecked();
    bool tcp = ui->checkBox_tcp->isChecked();
    bool udp = ui->checkBox_udp->isChecked();
    proxyModel->setDataF(ipAddress,port,http,dns,tcp,udp);
    proxyModel->invalidate();


}

void MainWindow::adjustTableColumnWidth(){
    int quarterWidth_Info = ui->tableView->width() / 3;
    int quarterWidth_others = ui->tableView->width() / 9;
    ui->tableView->setColumnWidth(6, quarterWidth_Info);
    for(int pos=0; pos<6; pos++)
        ui->tableView->setColumnWidth(pos, quarterWidth_others);
}

void MainWindow::resizeEvent(QResizeEvent* event) {
    QMainWindow::resizeEvent(event); // 调用基类的处理函数
    adjustTableColumnWidth();
}

void MainWindow::handleTableRowClicked(const QModelIndex &index){
    QColor selectedColor(29, 122, 243);

    ui->treeWidget->clear();
    QModelIndex sourceIndex = proxyModel->mapToSource(index);
    int selectedRow = sourceIndex.row();
    AllData data = model->getDataItem(selectedRow);
    // 现在你可以访问 data 结构体中的所有成员
    const EthernetHeader *ethernetHeader = data.ethernetHeader;
    unsigned int packetLength = data.dataLen;
    const u_char *packet = data.packet;
    ui->treeWidget->setColumnCount(1); // 设置为两列或者你需要的列数
    printDataBinaryInHex(packet,packetLength);

    /* 处理Frame */
    QString FrameStr = QString("Frame %1: %2 bytes captured (%3 bits) on interface %4").arg(selectedRow+1).arg(packetLength).arg(packetLength*8).arg(deviceNameC);
    QTreeWidgetItem *frameItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << FrameStr);

     /* 处理以太网帧 */
    processEthernet(ethernetHeader);
    if( ntohs(ethernetHeader->type) != 2048){
        QString netStr = QString("The type of the Net Layer is not IPV4");
        QTreeWidgetItem *netItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << netStr);
        return;
    }

    /* 处理IP数据包 */
    IPHeader *ipHeader = (IPHeader*)((u_char*)ethernetHeader + ETHER_HEADER_SIZE);
    u_int ipHeaderLen = (ipHeader->ver_ihl & 0xf) * 4;      //ip头部长度
    unsigned short ipLength = ipHeader->len;                //ip数据包总长度
    QString Protocol = protocolNameFromNumber(ipHeader->proto);                      //协议
    processIp(ipHeader);

    /* 处理传输层数据包 */
    if(ipHeader->proto == IPPROTO_TCP){      //处理TCP数据报
        //解析tcp数据包
        const TCPHeader* tcpHeader = (TCPHeader*)((u_char*)ipHeader + ipHeaderLen);     //获得tcp头部指针
        processTcp(tcpHeader);
        u_short tcpSrcPort = ntohs(tcpHeader->srcPort);
        u_short tcpDstPort = ntohs(tcpHeader->destPort);
        u_short tcpHeaderLen = ((ntohs(tcpHeader->flags) & 0xF000)>>12) * 4;
        if(tcpSrcPort==53 || tcpDstPort==53){
            DNSHeader *dnsHeader = (DNSHeader*)((u_char*)tcpHeader + tcpHeaderLen);
            processDNS(dnsHeader);
        } else if(tcpSrcPort==80 || tcpDstPort==80){
            const u_char *httpOffset = packet + ETHER_HEADER_SIZE + ipHeaderLen +tcpHeaderLen;
            u_int httpLength = ipLength - ipHeaderLen - tcpHeaderLen;
            processHTTP(httpOffset,httpLength);
        } else if(tcpSrcPort==443 || tcpDstPort==443){
            QTreeWidgetItem *httpsItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << "Hypertext Transfer Protocol Secure(Https)");
        }
    } else if(ipHeader->proto == IPPROTO_UDP){     //数理UDP数据报
        const UDPHeader* udpHeader = (UDPHeader*)((u_char*)ipHeader + ipHeaderLen);
        processUdp(udpHeader);
        u_short udpSrcPort = ntohs(udpHeader->srcPort);
        u_short udpDstPort = ntohs(udpHeader->destPort);
        if(udpSrcPort==53 || udpDstPort==53){
            DNSHeader *dnsHeader = (DNSHeader*)((u_char*)udpHeader + 8);
            processDNS(dnsHeader);
        }
    } else
        QTreeWidgetItem *otherTranItem = new QTreeWidgetItem(ui->treeWidget, QStringList() << "Tranmisson Layer Protocol:  "+Protocol);

}


