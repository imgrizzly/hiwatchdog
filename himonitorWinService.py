# encoding: utf-8
import win32serviceutil
import win32service
import win32event
import winerror
import servicemanager
import time
import sys
import os
import himonitor


class WinPollManager(win32serviceutil.ServiceFramework):
    """
    #1.安装服务
    python WinPollManager.py install

    #2.让服务自动启动
    python WinPollManager.py --startup auto install

    #3.启动服务
    python WinPollManager.py start

    #4.重启服务
    python WinPollManager.py restart

    #5.停止服务
    python WinPollManager.py stop

    #6.删除/卸载服务
    python WinPollManager.py remove
    """

    _svc_name_ = "hiway_manager"  # 服务名
    _svc_display_name_ = "hiway_manager"  # 服务在windows系统中显示的名称
    _svc_description_ = "hiway_manager"  # 服务的描述

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True
        self._poll_intvl = 30

        print "init: " + os.getcwd()

    def SvcDoRun(self):
        print "run: " + os.getcwd()
        himonitor.main()


    def SvcStop(self):

        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.isAlive = False
        himonitor.all_exit()

if __name__ == '__main__':

    if len(sys.argv) == 1:
        try:
            evtsrc_dll = os.path.abspath(servicemanager.__file__)
            servicemanager.PrepareToHostSingle(WinPollManager)
            servicemanager.Initialize('WinPollManager', evtsrc_dll)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error, details:
            if details[0] == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                win32serviceutil.usage()
    else:
        print "main: " + os.getcwd()
        win32serviceutil.HandleCommandLine(WinPollManager)  # 括号里参数可以改成其他名字，但是必须与class类名一致；