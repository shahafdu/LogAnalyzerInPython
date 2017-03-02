#!/usr/bin/env python


""" log analyzer """
import sys
import getopt
import os.path
import time

#Filters:
from mulpi_log_analyzer_filters import AttachSlotFilter
from mulpi_log_analyzer_filters import MacDomainSMFilter
from mulpi_log_analyzer_filters import PromoteMacDomainFilter
from mulpi_log_analyzer_filters import DemoteMacDomainFilter
from mulpi_log_analyzer_filters import DetachSlotFilter
from mulpi_log_analyzer_filters import ApplySMFilter
from mulpi_log_analyzer_filters import RemoveSMFilter
from mulpi_log_analyzer_filters import LightsonFilter
from mulpi_log_analyzer_filters import LightsoffFilter
from mulpi_log_analyzer_filters import ConfigurationFilter
from mulpi_log_analyzer_filters import ConfigurationChangeCountFilter

PROMOTE_STR = '^ Promote ^'
DEMOTE_STR = 'V Demote V'
STARTUP_STR = '!-- STARTUP --!'
SHOTDOWN_STR = '!-- SHOTDOWN --!'
CONFIGURATION_STR = '-- Configuration --'
WARM_ATTACH_STR = '-- Warm Attach --'
ATTACH_SLOT_STR = '-- Attach Slot --'
DETACH_SLOT_STR = '-- Detach Slot --'
CONFIG_START = 'Start config ID:'
CONFIG_END = 'End config ID:'

# TODO: move this to docstring and on help print __doc__
EXEUTION_HELP_STR = """print_sm.py
 -i <inputfile> (by default this value is /var/log/ulcmulpid.log)
 -t <test_mode [MDID-Get MD ids / SM-Get sata machines]>
 -f <filter mdid [0xdddddd]> (optional)
 -l [if to take the last run only] (optional)

 Example: print_sm.py -i ~/Downloads/ulcmulpid.log -t SM -f 0x10a7000 -l
 """

DEFAULT_LOG_NAME = '/var/log/ulcmulpid.log'
DEFAULT_IN_FILE = '/no/file/in/the/arguments'
# Colors for terminal


# Why not use dictionary ?
class TerminalColors(Exception):
    """    Colors for terminal    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Why do you inherit from Exception ?! you should inherit from object
# This is just two parameters and no methods - why use a class ?
class MacdomainParams(Exception):
    """    Store MD params    """

    def __init__(self, md_num, md_port):
        # what is the meaning of super here ?! this class is no Exception !
        super(MacdomainParams, self).__init__()
        self.md_num = md_num
        self.md_port = md_port

# This is a pseudo class - it can be a list of records, or multi list if you want to distinguish between record types.
class LogRecord(Exception):
    """    Store one log/state record    """

    # You do not need to use different names - you can do self.record = record
    def __init__(self, str_rec, type_rec, order):
        # what is the meaning of super here ?! this class is no Exception !
        super(LogRecord, self).__init__()
        self.rec_order = order # why do you need the number of the record inside the record ?
        self.rec_str = str_rec
        # 0=state , 1=lights , 2=config , 3=Demote ,4=attach/detach, 5= Apply
        # 6=remove , 7=config start / end
        self.rec_type = type_rec

        
    # Instead of using all these single line prints - return the string you want to print and apply it to the print you would like to print out
    @staticmethod
    def print_arrow(identation_numer):
        """ print arrows in SM """
        tab = "\t" * identation_numer
        print tab + '    |   '
        print tab + '    V   '
        
    # Instead of using all these single line prints - return the string you want to print and apply it to the print you would like to print out
    def print_state(self):
        """        Print Mac domains content        """
        if self.rec_type == 0:
            print TerminalColors.BOLD + "\t{MD} " + self.rec_str + TerminalColors.ENDC
            self.print_arrow(3)
        elif self.rec_type == 5:
            print "\t\t{Apply} " + self.rec_str
            self.print_arrow(4)
        elif self.rec_type == 6:
            print "\t\t{Remove} " + self.rec_str
            self.print_arrow(3)
        elif self.rec_type == 7:
            print TerminalColors.HEADER + "\t{Configuration} " + self.rec_str + TerminalColors.ENDC
            self.print_arrow(3)
        else:
            print TerminalColors.OKBLUE + self.rec_str + TerminalColors.ENDC
            print ' '
            print ' '


class MacDomainRecords(object):
    """    Store log/state records for spesific MD    """

    # _ in the beginning of a variable is a convension for private variables, here it is out of convension
    def __init__(self, mdid):
        self.mdid = mdid
        self.rec_count = 0 # redundant - you can get len(self.records)
        self.records = []

    def add_rec(self, str_rec, type_rec):
        """        Add single state/log rec to the MD        """
        self.rec_count += 1
        # why does a record need to know its numbering in the list ?
        self.records.append(LogRecord(str_rec, type_rec, self.rec_count))

    def keep_last_run(self):
        """        keep only the last run since the last startup        """
        last_idx = get_last_index(STARTUP_STR, self.records)
        self.records = self.records[last_idx:]

    # what's that ? if you want to create an empty method to implement it later - use 'pass'
    def filter_list(self):
        """        place to filter log records        """
        pass
        #self.records = self.records

    def print_state(self):
        """        Print Mac domains content        """
        for record in self.records:
            record.print_state()


class MacDomainsHandler(object):
    """    manage all the MD records    """

    # always put __init__ on top for visability
    def __init__(self, md_list):
        self.mds = {}
        self.md_list = md_list
        for mdid in self.md_list:
            if mdid not in self.mds:
                self.mds[mdid] = MacDomainRecords(mdid)
  
    def add_log_record(self, mdid, msg, type_rec, date):
        """         add log rec per Mdid        """
        msg = '%s \t(%s)' % (msg, date)
        self.mds[mdid].add_rec(msg, type_rec)

    def broadcast_message(self, msg, type_rec, date):
        """        add same message to all MDs        """
        for key in self.mds:
            self.add_log_record(key, msg, type_rec, date)

    def keep_last_run(self):
        """        keep only the last run since the last startup        """
        for key in self.mds:
            self.mds[key].keep_last_run()

    def filter_lists(self):
        """        place to filter log records        """
        for key in self.mds:
            self.mds[key].filter_list()

    def print_report(self, filter_md):
        """ print records for MDs except filter_md """
        for mdid, item in self.mds.items():
            if mdid == filter_md or not filter_md:
                # if you print all of this in one line - it will be faster - only one print to the monitor
                # print '\n\nMdId=%s\n-----------------%s\t\t ----- ' % (mdid, item.get_print_state())
                print '\n'
                print 'MdId=' + mdid
                print '-----------------'
                item.print_state()
                print "\t\t ----- "
               

def filter_line(filters, line, mds):
    """ filter line """
    for filter_handle in filters:
        filter_handle.check(line, mds)

def filter_lines(input_file_path, mds):
    """ read file and filter """
    filters = [AttachSlotFilter(), MacDomainSMFilter(), DemoteMacDomainFilter(),
               PromoteMacDomainFilter(), DetachSlotFilter(), ApplySMFilter(),
               RemoveSMFilter(), LightsonFilter(), LightsoffFilter(),
               ConfigurationFilter(), ConfigurationChangeCountFilter()]

    # if you want this to work super fast - you need to do some research to understand how to optimze string filtering, might be that you would prefer to do it with 'grep' in subprocess
    with open(input_file_path, 'r') as log_file:
        for line in log_file:
            filter_line(filters, line, mds)

def sm_test_new(input_file_path, filter_mdid="", last=False):
    """    Start log parsing for SM    """
    md_list = get_md_list(input_file_path, True)
    mds = MacDomainsHandler(md_list)

    start = time.time()
    filter_lines(input_file_path, mds)
    end = time.time()
    print "time:" + str(end - start)
    if last:
        mds.keep_last_run()

    mds.filter_lists()
    mds.print_report(filter_mdid)

    print 'done'





def get_md_list(input_file_path, silent=False):
    """    get full list of MDs and the md numbers    """
    md_list = {}
    with open(input_file_path, 'r') as log_file:
        prev_line = ''
        for line in log_file:
            if 'AddMacDomain' in line and 'MdController' in line:
                mdid = line.split('mdId')[1].strip()
                if mdid not in md_list:
                    md_list[mdid] = MacdomainParams(-1, '')
            elif 'MacDomain:0x' in line:
                mdid = line.split('MacDomain:')[
                    1].strip().split('-')[0].strip().split(' ')[0].strip()
                if mdid not in md_list:
                    md_list[mdid] = MacdomainParams(-1, '')
            elif 'RefreshConfigData' in prev_line:
                for mdid in md_list:
                    if mdid in prev_line:
                        md_num = line.split('(')[1].strip().split(')')[
                            0].strip()
                        md_port = line.split('=')[1].strip()
                        md_list[mdid] = MacdomainParams(md_num, md_port)
            prev_line = line

    if not silent:
        print '\nMac domains list:'
        print '------------------'
        for mdid, item in md_list.items():
            print 'MdId=' + mdid + " : {} ({})".format(item.md_num, item.md_port)
        print '-----------------'
        print TerminalColors.BOLD + 'Total MD in found=' + str(len(md_list)) + TerminalColors.ENDC
    return md_list


def check_input(argv):
    """
    parse execution arguments
    """
    inputfile = DEFAULT_IN_FILE
    test = ''
    filter_str = ''
    last = False
    return_args = {}
    try:
        opts, _ = getopt.getopt(
            argv, "hi:t:f:l", ["ifile=", "tTest=", "fFilter="])
    except getopt.GetoptError:
        print EXEUTION_HELP_STR
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print EXEUTION_HELP_STR
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-t", "--tTest"):
            test = arg
        elif opt in ("-f", "--fFilter"):
            filter_str = arg
        elif opt in "-l":
            last = True

    print 'PATH   :', inputfile
    print 'TEST   :', test
    print 'FILTER   :', filter_str
    print 'LAST   :', str(last)
    return_args['inputfile'] = inputfile.strip()
    return_args['test'] = test.strip()
    return_args['filter'] = filter_str.strip()
    return_args['last'] = last
    return 0, return_args


def get_last_index(val, list_items):
    """
    get the last index of val
    """
    if all(val not in x.rec_str for x in list_items):
        return 0
    last_index = 0
    for index, item in enumerate(list_items[::-1]):
        if val in item.rec_str:
            last_index = len(list_items) - 1 - index
            break
    return last_index

def main(argv):
    """ Main """
    input_check_status, args = check_input(argv)
    if input_check_status != 0:
        sys.exit(2)
    test = args['test']
    in_file = args['inputfile']
    if in_file == DEFAULT_IN_FILE:
        print 'input file hasnt entered. using default:' + DEFAULT_LOG_NAME
        in_file = DEFAULT_LOG_NAME
    if not os.path.exists(in_file):
        print "************\n{}ERROR:\nfile: {} doesnt exist!{}\n************".format(TerminalColors.FAIL, in_file,TerminalColors.ENDC)
        print EXEUTION_HELP_STR
        sys.exit(2)
    if test == 'MDID':
        get_md_list(in_file)
    elif test == 'SM':
        sm_test_new(in_file, args['filter'], args['last'])
    else:
        print "************\n" + TerminalColors.FAIL + "ERROR:\nUnknown Test!\n" + TerminalColors.ENDC + "************"
        print EXEUTION_HELP_STR
        sys.exit(2)

main(sys.argv[1:])
