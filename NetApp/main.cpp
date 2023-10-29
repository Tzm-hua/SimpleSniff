#include "mainwindow.h"
#include <QListWidget>
#include "NetTools.h"

#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

//    QStringList items = getNetDevices();
//    w.populateMenuFile(items);

    w.show();
    return a.exec();
}

