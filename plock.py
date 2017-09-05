# encoding: utf-8
import sys
import time
import os
import platform

try:
    import fcntl

    LOCK_EX = fcntl.LOCK_EX
    LOCK_NB = fcntl.LOCK_NB
except ImportError:
    # Windows平台下没有fcntl模块
    fcntl = None
    import win32con
    import win32file
    import pywintypes

    LOCK_EX = win32con.LOCKFILE_EXCLUSIVE_LOCK
    overlapped = pywintypes.OVERLAPPED()


class Lock:
    """进程互斥锁
    """

    def __init__(self, filename):
        # type: (object) -> object
        self.filename = filename
        # 如果文件不存在则创建
        self.handle = open(filename, 'w')

    def check_lock(self):
        if fcntl:
            try:
                print "fcntl"
                fcntl.flock(self.handle, LOCK_EX | LOCK_NB)
                return True
            except:
                return False

        else:
            try:
                print self.filename
                cfile = win32file._get_osfhandle(self.handle.fileno())
                win32file.LockFileEx(cfile, LOCK_EX, 0, -0x10000, overlapped)
                self.handle.write("test")
                return True
            except Exception as e:
                print e
                return False

    def acquire(self):
        # 给文件上锁
        if fcntl:
            fcntl.flock(self.handle, LOCK_EX | LOCK_NB)
        else:
            hfile = win32file._get_osfhandle(self.handle.fileno())
            win32file.LockFileEx(hfile, LOCK_EX, 0, -0x10000, overlapped)

    def release(self):
        # 文件解锁
        if fcntl:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
        else:
            hfile = win32file._get_osfhandle(self.handle.fileno())
            win32file.UnlockFileEx(hfile, 0, -0x10000, overlapped)

    def __del__(self):
        try:
            self.release()
            self.handle.close()
            os.remove(self.filename)
        except:
            pass


def chk_lock(lockname):
    if platform.system() == "Windows":
        try:
            if os.remove(lockname):
                print "not be locked!!"
                lock = Lock(lockname)
                lock.acquire()
        except WindowsError as e:
            print "be locked!"
            sys.exit(0)
    elif platform.system() == "Linux":
        lock = Lock(lockname)
        try:
            print " linux opt"
            lock.acquire()
        except IOError:
            print "linux be locked!"
            sys.exit(0)
if __name__ == '__main__':
    lockname = "watchdog.lock"
    if os.path.exists(lockname):
        chk_lock(lockname)
    else:
        lock = Lock(lockname)
        lock.acquire()

    while True:
        time.sleep(2)
        print "fff"
    print "release"
    lock.release()
