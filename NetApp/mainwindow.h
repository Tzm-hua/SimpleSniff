#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QActionGroup>
#include <winsock2.h>
#include <QListWidget>
#include "packetcapturethread.h"
#include <QTableWidget>
#include "structureHeader.h"
#include <QTreeWidgetItem>
#include "stopcapture.h"
#include "mytablemodel.h"
#include <QSortFilterProxyModel>
#include "customfilterproxymodel.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE


struct MenuItemDevice {
    QString deviceName;
    QString deviceDescription;

    // 默认构造函数
    MenuItemDevice() {}

    // 带参数的构造函数
    MenuItemDevice(const QString &name, const QString &desc)
        : deviceName(name), deviceDescription(desc) {}

};
Q_DECLARE_METATYPE(MenuItemDevice)


struct orderItem{

};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
//    void populateMenuFile(const QStringList &items);
//    void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet);
//    bool showData(int index);
    ~MainWindow();
    static int cCount;
    bool stopTable;


private slots:
//    void onDynamicActionTriggered(QAction* action);
    void onInterfaceSelected(QAction *action);
    void addPacketData(const u_char *, const unsigned int, QString subTime);
    QString protocolNameFromNumber(u_char proto);
    void onClickedStopMenu();
    void handleTableRowClicked(const QModelIndex &index);
    void on_pushButton_Assure_clicked();
    
    void on_pushButton_Filter_clicked();

private:
    Ui::MainWindow *ui;
    QActionGroup *actionGroup;
//    QListWidget *listWidget;
//    QTableWidget *table;
    QMenu *menuInterfaces;
    QMenu *stopMenu;
    MyTableModel *model;
    CustomFilterProxyModel *proxyModel;
    void initInterfacesMenu();
    QString MacToQStr(MACAddress);
    QString IpToQStr(IPAddress);
    QString formatPacketData(const QByteArray& data);
    QString deviceNameC;
    QString TCPFlags(u_char);
    void processTcp(const TCPHeader *);
    void processUdp(const UDPHeader *);
    void tcpSeqAndAck(u_char);
    void processIp(const IPHeader*);
    void processEthernet(const EthernetHeader*);
    void processDNS(const DNSHeader*);
    void processHTTP(const u_char *, u_int);
    void printDataBinaryInHex(const u_char *, unsigned int);
    void adjustTableColumnWidth();


protected:
    void resizeEvent(QResizeEvent* event) override;
};
#endif // MAINWINDOW_H
