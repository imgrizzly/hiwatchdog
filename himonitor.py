# encoding: utf-8

import os
import sys
import json
import psutil
import logging
import logging.handlers
import time
import threading
import platform
import subprocess
import signal
import plock
import errno
from threading import Thread
from collections import OrderedDict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import fcntl
except:
    pass

MONITOR_MAIN_EXIT = False
thread_terminate = threading.Event()
thread_terminate.clear()

PID_CMDLINE = {}
C2P_DICT = {}
thread_conf_edited = threading.Event()
thread_conf_edited.clear()

logger = logging.getLogger('')
logger.setLevel(logging.DEBUG)
curr_path = os.path.dirname(os.path.realpath(__file__)) + os.sep

if os.path.exists(curr_path + "log") is False:
    os.mkdir(curr_path + "log")
LOG_FILE = curr_path + "log" + os.sep + os.path.basename(sys.argv[0]).split(".")[0] + "_DEBUG_.log"
Rthandler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 512, backupCount=9)

formatter = logging.Formatter('%(asctime)s - %(process)d - %(thread)d - %(levelname)s - %(message)s - [%('
                              'filename)s:%(lineno)s]')
Rthandler.setFormatter(formatter)
logger.addHandler(Rthandler)


# kwargs = {}
# if 'Windows' in platform.system():
#     CREATE_NEW_PROCESS_GROUP = 0x00000200  # note: could get it from subprocess
#     DETACHED_PROCESS = 0x00000008  # 0x8 | 0x200 == 0x208
#     kwargs.update(creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
# elif sys.version_info < (3, 2):  # assume posix
#     kwargs.update(preexec_fn=os.setsid)
# else:  # Python 3.2+ and Unix
#     kwargs.update(start_new_session=True)
# print kwargs

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == curr_path + "logging.conf":
            with open(curr_path + 'logging.conf', 'r') as log_conf:
                logger.setLevel(int(json.loads(log_conf.read())["log_level"]))
                logger.critical("logger level modify!")
        if event.src_path == curr_path + 'himonitor.json':
            thread_conf_edited.set()  # notify  monitor thread.


def switch_monitor_item(configkey, progname, parameter, switch):
    # type: (object, object, object, object) -> object
    # TODO edit config . edit every item status
    if switch == "start":
        opt_value = 1
    elif switch == "stop":
        opt_value = 0
    filename = curr_path + 'himonitor.json'
    with open(filename, 'r') as configfile:
        config_json = json.loads(configfile.read().strip(), object_pairs_hook=OrderedDict)
    for inx, val in enumerate(config_json[configkey]):
        if progname in os.path.split(val["progname"])[1] and parameter == val["parameter"]:
            if val["status"] == int(not opt_value):
                config_json[configkey][inx]["status"] = opt_value
                with open(filename, 'w') as f:
                    json.dump(config_json, f, indent=4)
                logger.debug("modify monitor status %s config item %s %s switch %s" % (
                    configkey, progname, parameter, opt_value))
                return 0
            elif val["status"] == opt_value:
                logger.critical('[ %s %s ]state value is always %s' % (progname, parameter, opt_value))
                return 1
    else:
        logger.debug(" parameter matching configuration file error" )
        return 2


def add_or_del_item(configkey, opt, *args):
    # TODO add or del  item of config.
    filename = curr_path + 'himonitor.json'
    with open(filename, 'r') as configfile:
        config_json = json.loads(configfile.read().strip(), object_pairs_hook=OrderedDict)
    if opt == "add":
        item_keys = config_json[configkey][0].keys()
        if len(args) < len(item_keys):
            new_itme = args.__add__(('',) * (len(item_keys) - len(args)))
        elif len(args) > len(item_keys):
            logger.critical("Error : The number of incoming parameters is greater than the configuration")
            logger.critical("Error args: %s" % str(args))
            return False
        else:
            new_itme = args
        config_json[configkey].append(OrderedDict(zip(item_keys, new_itme)))
        with open(filename, 'w') as f:
            json.dump(config_json, f, indent=4)
        logger.debug('add %s config  item:%s %s ' % (configkey, str(args)))
    elif opt == "del":
        progname = args[0]
        parameter = args[1]
        for inx, val in enumerate(config_json[configkey]):
            if progname in os.path.split(val["progname"])[1] and parameter == val["parameter"]:
                config_json[configkey].pop(inx)
        with open(filename, 'w') as f:
            json.dump(config_json, f, indent=4)
        logger.debug('del %s config  item:%s %s ' % (configkey, progname, parameter))


def query_status():
    # TDDO query monitor running statue and The state of the monitored process
    monitored_process_conf, _ = read_config("main")
    state_monitored_process, no_running_process = return_running(monitored_process_conf)
    print "{:<8} {:<50} {:<8}".format('PID', 'COMMAND-LINE', 'STATUE')
    for k, v in state_monitored_process.iteritems():
        print "{:<8} {:<50} {:<8}".format(k, v, psutil.Process(k).status())
    if no_running_process:
        for _ in no_running_process:
            print "{:<8} {:<20} {:<8}".format("", _, "")
    logger.debug('call query status')
    return state_monitored_process


def all_exit():
    # TODO Monitor Thread exit and Main Monitor Process Exit.
    global MONITOR_MAIN_EXIT
    thread_terminate.set()  # notify all monitor thread and subprocess exit.
    config_monitor_process, _ = read_config("main")
    exit_time = time.time()
    while True:
        time.sleep(4)
        _, running_process = check_run(config_monitor_process)
        if len(running_process) == 0:
            break
        if time.time() - exit_time > 12:
            logger.critical("Exit timeout: " + str(running_process))
            break
    logger.critical(" Receive exit command is about to stop Main Process")
    MONITOR_MAIN_EXIT = True


def return_running(config):
    # TODO  return running  monitored process dict. and no running process list
    running_process_dict = {}
    for _ in psutil.process_iter():
        try:
            if " ".join(_.cmdline()):  # Filter the system proc
                if " ".join(_.cmdline()) in config:
                    logger.debug("return monitored running PID:%s cmdline :%s " % (str(_.pid), " ".join(_.cmdline())))
                    running_process_dict[_.pid] = " ".join(_.cmdline())
        except:
            pass
    return (running_process_dict,  set(config) - set(running_process_dict.values()))


def pkill_all(config):
    # TODO exit monitor or exit monitor and monitored process
    pkill_list, _ = return_running(config)
    logger.debug("Read config monitor process  :" + str(config))
    pl = []
    for _ in os.listdir(curr_path):
        if ".lock" in _:
            pl.append(_)
            psutil.Process(int(_.split('.')[0])).terminate()
            logger.critical('PID %s Main Process Terminate success: ' % (_.split('.')[0]))

    for k, v in pkill_list.items():
        try:
            psutil.Process(k).kill()
            logger.critical('PID: %s pkill Process succees: %s ' % (str(k), v))
        except Exception as e:
            logging.exception(e)

    for times in range(10):
        try:
            for _ in pl:
                if os.remove(_):
                    logger.debug("Remove lock file Success:" + _)
            break
        except Exception as e:
            logging.exception(e)
            logger.debug("Remove lock file failed:" + _)
        time.sleep(1)


def monitor_process(process_list, exit_flag, edit_flag):
    global PID_CMDLINE

    while True:
        time.sleep(2)
        try:
            if exit_flag.isSet():
                logger.critical("Monitoring thread is about to exit: ")
                for _ in PID_CMDLINE.keys():
                    psutil.Process(_).terminate()
                    logger.critical("PID :%s Being monitored Process exit: %s" % (_, PID_CMDLINE[_]))
                break
        except Exception as e:
            logger.critical("Exiting monitor thread Error: ", exc_info=True)
        try:
            if edit_flag.isSet():
                cmdlist, cmd_all_list = read_config("main")
                if set(cmdlist) == set(PID_CMDLINE.values()):
                    logger.debug("The configuration is modified, but the monitoring item has not changed")
                    pass
                elif len(set(cmdlist)) - len(set(PID_CMDLINE.values())) > 0:
                    for _ in set(cmdlist) - set(PID_CMDLINE.values()):
                        if _ not in return_running(cmdlist)[0].values():
                            sp = [i for i in cmd_all_list if i[1] == _]
                            pid = start_process(sp)
                            logger.critical("added monitoring PID :%s cmdline: %s" % (pid, _))
                        else:
                            added_monitoring_item = return_running(_)[0]
                            PID_CMDLINE = dict(PID_CMDLINE, **added_monitoring_item)
                            logger.critical("added monitoring PID :%s cmdline: %s" % (added_monitoring_item.keys(), _))
                            del added_monitoring_item
                elif len(set(cmdlist)) - len(set(PID_CMDLINE.values())) < 0:
                    remove_items = {k: v for k, v in PID_CMDLINE.items() if v not in cmdlist}
                    PID_CMDLINE = {k: v for k, v in PID_CMDLINE.items() if v in cmdlist}
                    for pk, cv in remove_items.items():
                        logger.critical("removed monitoring PID :%s cmdline: %s" % (pk, cv))
                    pass
                thread_conf_edited.clear()
        except Exception as e:
            logger.critical("Edit monitor thread Error: ")
            logging.exception(e)
        logger.debug("Runing :" + str(PID_CMDLINE.values()))
        if len(set(PID_CMDLINE.keys()) - set(psutil.pids())) > 0:
            for _ in (set(PID_CMDLINE.keys()) - set(psutil.pids())):
                logger.debug("monitoring Process PID :%s executing: %s" % (_, PID_CMDLINE[_]))
                logger.critical('Ready to restart: ' + PID_CMDLINE[_].encode('utf-8'))
                cmdlist, cmd_all_list = read_config("main")
                if PID_CMDLINE[_] not in return_running(cmdlist)[0].values():
                    sp = [i for i in cmd_all_list if i[1] == PID_CMDLINE[_]]
                    pid = start_process(sp)
                    logger.critical("added monitoring PID :%s cmdline: %s" % (pid, PID_CMDLINE[_]))
                    logger.critical("removed monitoring PID :%s cmdline: %s" % (_, PID_CMDLINE[_]))
                    PID_CMDLINE.pop(_)
                else:
                    added_monitoring_item = return_running(PID_CMDLINE[_])[0]
                    PID_CMDLINE = dict(PID_CMDLINE, **added_monitoring_item)
                    logger.critical("added monitoring PID :%s cmdline: %s" % (added_monitoring_item.keys(), added_monitoring_item.values()))
                    logger.critical("removed monitoring PID :%s cmdline: %s" % (_, PID_CMDLINE[_]))
                    PID_CMDLINE.pop(_)


def run_once(runcmd):
    # TODO only start once program
    runcmd = "".join(runcmd)  # remove empty string entry
    logger.debug('run_once cmd is :' + runcmd)
    assert isinstance(runcmd, object)
    begin_time = time.time()
    p = subprocess.Popen(runcmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE,
                         shell=True)
    while True:
        p.wait()
        time.sleep(1)
        if p.returncode == 0:
            time_consuming = time.time() - begin_time
            logger.critical("Once Prceoss normal finsh:%s return code:%s time_consumings %s sec" % (runcmd,
                                                                                                    p.returncode,
                                                                                                    time_consuming))
            return p.returncode
        elif p.returncode and p.returncode != 0:
            time_consuming = time.time() - begin_time
            logger.critical("Once Prceoss faid :%s return code:%s time_consumings %s sec" % (runcmd, p.returncode,
                                                                                             time_consuming))
            run_once(runcmd)
            # elif time.time() - begin_time > 5:  # time out is 5
            #     logger.critical("Once Prceoss time out: " + runcmd)
            #     p.terminate()
            #     logger.critical("Once Prceoss is terminate: " + runcmd)
            #     break


def check_run(config):
    # TODO Before starting the monitor, check whether there is a controlled program that has been started,
    # and return to the list of unsuccessized controlled programs and launchers
    run_list = []
    for _ in psutil.process_iter():
        try:
            run_list.append(" ".join(_.cmdline()))
        except Exception as e:
            pass
            # logger.error(_.name() + "check_process_iter")
    # if platform=="Windows":
    #     running_list = set(_.lower() for _ in config) & set(_.lower() for _ in run_list)
    running_list = set(config) & set(run_list)
    return set(config) - running_list, running_list


def init_config(configkey):
    # TODO restartup restore monitoring status
    filename = curr_path + 'himonitor.json'
    configfile = open(filename, 'r+')
    config_json = json.loads(configfile.read().strip())
    configfile.close()
    for inx, _ in enumerate(config_json[configkey]):
        config_json[configkey][inx]["status"] = 1
    with open(filename, 'w') as f:
        json.dump(config_json, f, indent=4)

        # configfile.write(config_json.strip().encode('utf-8'))


def c2p(str):
    # TODO cmdline to progname
    global C2P_DICT
    for _ in C2P_DICT.keys():
        if str == _:
            return C2P_DICT(_)
    else:
        return False

# def return_args():
#     # TODO return args, if args is Nne then return None
#     import collections
#     arg_names = [chr(_) for _ in range(65,86)]
#     args = dict(zip(arg_names, sys.argv))
#     Arg_list = collections.namedtuple('Arg_list', arg_names)
#     args = Arg_list(*(args.get(arg, None) for arg in arg_names))
#     return args


def read_config(configkey):
    # TODO return configfile commandlist, cmd_all_list include "prepare","progname" and "windup",
    # cmd_list only include "progname"
    global C2P_DICT
    logger.debug("read config key is: " + configkey)
    cmd_all_list = []
    cmd_list = []
    configfile = open(curr_path + 'himonitor.json', 'r')
    config_json = json.loads(configfile.read().strip())
    configfile.close()

    for _ in config_json[configkey]:
        if _["status"] == 1:
            sub_business_list = []
            sub_business_list.append(_["prepare"])# if _["prepare"] else sub_business_list.append("")

            if _["type"] == 1:
                sub_business_list.append(_['cmdline'] + " " + _["parameter"] if _["parameter"] else _['cmdline'])
                C2P_DICT[_['progname']] = _['cmdline']
            else:
                sub_business_list.append(_['progname'] + " " + _["parameter"] if _["parameter"] else _['progname'])

            sub_business_list.append(_["windup"])


            cmd_all_list.append(sub_business_list)

            cmd_list.append(sub_business_list[1])
    return cmd_list, cmd_all_list


def chking_it(runcmd, exit_flag):
    # TODO  Monitor the main program has started before the business process has been started,
    # If these programs exit will start monitoring them
    while True:
        time.sleep(2)
        if exit_flag.isSet():
            for _ in psutil.process_iter():
                try:
                    if " ".join(_.cmdline()) == runcmd:
                        _.kill
                        logger.critical("Receive exit command: " + runcmd)
                except Exception as e:
                    logger.critical("An error occurred while receiving the exit command exit: " + runcmd, exc_info=True)
            break
        logger.critical("No monitor prcoess running: " + runcmd)

        pp = []
        for _ in psutil.process_iter():
            try:
                pp.append(" ".join(_.cmdline()))
            except:
                pass
        if runcmd.encode("utf-8") not in pp:
            logger.critical("Not monitored stopped: " + runcmd)
            logger.critical('Ready to restart: ' + runcmd.encode('utf-8'))
            Thread(target=start_process, args=(runcmd, thread_terminate,)).start()
            break


def start_process(runcmd):
    # TODO start business process and return pid and cmdline. include  config key word is :prepare ,progname, windup
    global PID_CMDLINE
    main_prepare = runcmd[0]
    main_main = runcmd[1]
    main_windup = runcmd[2]

    if main_prepare:
        logger.debug("Run_it main_prepare :" + main_prepare.encode("utf-8"))
        run_once(main_prepare)
    try:
        logger.debug("Run_it main_main :" + main_main.encode("utf-8"))
        if c2p(main_main):
            pid = start_type_one(c2p(main_main))
        else:
            p = subprocess.Popen(main_main, stdout=None, stderr=None, stdin=None,
                             shell=True, close_fds=True)
            pid = p.pid
        # stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE
    except Exception as e:
        logger.critical("run_it Error :" + main_main, exc_info=True)
        return 0
    logger.debug("PID: %s Run_it Success :%s" % (pid, main_main.encode("utf-8")))
    PID_CMDLINE[pid] = main_main

    if main_windup:
        logger.debug("Run_it main_windup :" + main_windup.encode("utf-8"))
        run_once(main_windup)

    return pid

def start_type_one(var):
    # TODO return (type 1)'s pid. type1 : progname and cmdline is diff
    global C2P_DICT
    p = subprocess.Popen(var, stdout=None, stderr=None, stdin=None,
                     shell=True, close_fds=True)
    return return_running(C2P_DICT[var])[0].keys()


def check_lck(lockname):
    if platform.system() == "Linux":
        for _ in lockname:
            f = open(_, 'r')
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                logger.critical("can't immediately lock the file: " + _)
                return os.path.basename(_).split(".")[0]
            else:
                os.remove(_)
                logger.critical("%s is not locked." % _)
            return False

    elif platform.system() == "Windows":
        try:
            for _ in lockname:
                if os.remove(_):
                    logger.critical("%s is not locked." % lockname)
                return False
        except WindowsError as e:
            logger.critical("Windows Error ", exc_info=True)
            return os.path.basename(_).split(".")[0]

def opt_argv(main_pid):
    length_argv = len(sys.argv)
    if main_pid:
        if length_argv == 1:
            logger.critical("The same process PID:%s is running!" % main_pid)
            sys.exit(0)
        elif length_argv == 2:
            if sys.argv[1] == "stop":
                config, _ = read_config("main")
                pkill_all(config)
                sys.exit(0)
            elif sys.argv[1] == "status":
                print "The PID: %s Main Process running " % main_pid
                query_status()
                sys.exit(0)
            else:
                print "Please input correct parameters!"
                sys.exit(0)
        elif length_argv == 3 or length_argv == 4:
            if sys.argv[1] == "stop" or sys.argv[1] == "start":
                if length_argv == 4:
                    tmp = sys.argv[3]
                else:
                    tmp = ""
                switch_monitor_item("main", sys.argv[2], tmp, sys.argv[1])
            else:
                print "usage:start|stop  [PrceossName] [parameter]"
            sys.exit(0)
        else:
            print "Please input correct parameters!"
            sys.exit(0)
    else:
        if length_argv == 2 and sys.argv[1] == "status":
            print "Please start the monitoring program first."
            sys.exit(0)
        elif length_argv > 1:
            print "Please input correct parameters!"
            sys.exit(0)

def wait_child(signum, frame):
    logger.info('receive SIGCHLD')
    try:
        while True:
            time.sleep(1)
            # -1 表示任意子进程
            # os.WNOHANG 表示如果没有可用的需要 wait 退出状态的子进程，立即返回不阻塞
            cpid, status = os.waitpid(-1, os.WNOHANG)
            if cpid == 0:
                logger.info('no child process was immediately available')
                break
            exitcode = status >> 8
            logger.info('child process %s exit with exitcode %s', cpid, exitcode)
    except OSError as e:
        if e.errno == errno.ECHILD:
            logger.warning('current process has no existing unwaited-for child processes.')
        else:
            raise
        logger.info('handle SIGCHLD end')



def main():
    global MONITOR_MAIN_EXIT
    global PID_CMDLINE
    lockname = []
    for _ in os.listdir(curr_path):
        if '.lock' in _:
            lockname.append(curr_path + _)
    if lockname:
        opt_argv(check_lck(lockname))
    else:
        opt_argv(False)

    init_config("main")
    plock_lock = plock.Lock(curr_path + os.sep + str(psutil.Process().pid) + '.lock')
    plock_lock.acquire()

    event_handler1 = MyHandler()
    observer = Observer()
    watch = observer.schedule(event_handler1, path=curr_path, recursive=False)
    observer.start()

    readopt, _ = read_config("ready")
    for _ in readopt:
        run_once(_)

    list_main_process, list_all_main_process = read_config("main")
    list_main_process, has_been_up_monitoring_process = check_run(list_main_process)
    PID_CMDLINE, _ = return_running(has_been_up_monitoring_process)
    for _ in list_all_main_process[:]: #  loop through copy, opt oop through.
        if len(set(_) & set(list_main_process)) == 0:  # Remove the process has been started
            list_all_main_process.remove(_)

    for cmd in list_all_main_process:
        start_process(cmd)

    signal.signal(signal.SIGCHLD, wait_child)
    Thread(target=monitor_process, args=(PID_CMDLINE, thread_terminate, thread_conf_edited,)).start()

    # for chk in list_except_process:
    #     s = Thread(target=chking_it, args=(chk, thread_terminate,))
    #     s.start()
    while True:
        time.sleep(6)
        logger.debug("Main Process is running loop 6 sec")
        if MONITOR_MAIN_EXIT:
            plock_lock.release()
            del plock_lock
            logger.critical(" Main Process is Exit!")
            sys.exit(0)


if __name__ == '__main__':
    main()
