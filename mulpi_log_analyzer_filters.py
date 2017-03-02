
""" Filters for log analyzer """

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


class AbstractFilter(Exception):
    """ base class for filter objects """
    def __init__(self):
        super(AbstractFilter, self).__init__()

    def handle(self, line, mds):
        """ generate record from log line """
        raise NotImplementedError('subclasses must override handle()!')
    def check(self, line, mds):
        """ check if filter """
        for filter_word in self.get_words_to_search():
            if filter_word not in line:
                return
        self.handle(line, mds)

    def get_words_to_search(self):
        """ get filter words """
        raise NotImplementedError('subclasses must override get_words_to_search()!')

class DemoteMacDomainFilter(AbstractFilter):
    """ Mac domain demotation """
    def __init__(self):
        super(DemoteMacDomainFilter, self).__init__()
    def get_words_to_search(self):
        return (' Demote', 'MacDomain')
    def handle(self, line, mds):
        mdid = (line.split('MacDomain:')[1].strip()).split('-')[0].strip()
        mds.add_log_record(mdid, DEMOTE_STR, 3, parse_time_and_date(line))

class PromoteMacDomainFilter(AbstractFilter):
    """ Mac domain promotion """
    def __init__(self):
        super(PromoteMacDomainFilter, self).__init__()
    def get_words_to_search(self):
        return ('Promote', 'MacDomain')
    def handle(self, line, mds):
        mdid = (line.split('MacDomain:')[1].strip()).split('-')[0].strip()
        mds.add_log_record(mdid, PROMOTE_STR, 3, parse_time_and_date(line))

class MacDomainSMFilter(AbstractFilter):
    """ Mac domain state machine """
    def __init__(self):
        super(MacDomainSMFilter, self).__init__()
    def get_words_to_search(self):
        return ('MacDomain', '::on')
    def handle(self, line, mds):
        mdid = (line.split('MacDomain:')[1].strip()).split('-')[0].strip()
        state = line.split(mdid)[1].replace(" -", " ").strip()
        mds.add_log_record(mdid, state, 0, parse_time_and_date(line))

class ConfigurationChangeCountFilter(AbstractFilter):
    """ Configuration change count value """
    def __init__(self):
        super(ConfigurationChangeCountFilter, self).__init__()
    def get_words_to_search(self):
        return ['Writing update MD']
    def handle(self, line, mds):
        mdid = (line.split('MacDomain:')[1].strip()).split('-')[0].strip()
        config_id = line.split('DB:')[1].strip()
        mds.add_log_record(mdid, "{}{}".format(CONFIG_START, config_id),
                           7, parse_time_and_date(line))


class ConfigurationFilter(AbstractFilter):
    """ Configuration has come """
    def __init__(self):
        super(ConfigurationFilter, self).__init__()
    def get_words_to_search(self):
        return ['come!!!']
    def handle(self, line, mds):
        mds.broadcast_message(CONFIGURATION_STR, 2, parse_time_and_date(line))

class LightsonFilter(AbstractFilter):
    """ Startup """
    def __init__(self):
        super(LightsonFilter, self).__init__()
    def get_words_to_search(self):
        return ('lights', 'on')
    def handle(self, line, mds):
        mds.broadcast_message(STARTUP_STR, 1, parse_time_and_date(line))

class LightsoffFilter(AbstractFilter):
    """ Shotdown """
    def __init__(self):
        super(LightsoffFilter, self).__init__()
    def get_words_to_search(self):
        return ('lights', 'off')
    def handle(self, line, mds):
        mds.broadcast_message(SHOTDOWN_STR, 1, parse_time_and_date(line))

class RemoveSMFilter(AbstractFilter):
    """ Remove config state machine """
    def __init__(self):
        super(RemoveSMFilter, self).__init__()
    def get_words_to_search(self):
        return ('RemoveState', '::on')
    def handle(self, line, mds):
        mdid = (line.split('RemoveState:')[1]
                .strip()).split('-')[0].strip()
        state = line.split(mdid)[1].replace(" -", " ").strip()
        mds.add_log_record(mdid, state, 6, parse_time_and_date(line))

class ApplySMFilter(AbstractFilter):
    """ Apply config state machine """
    def __init__(self):
        super(ApplySMFilter, self).__init__()
    def get_words_to_search(self):
        return ('ApplyState', '::on')
    def handle(self, line, mds):
        mdid = (line.split('ApplyState:')[1]
                .strip()).split(' ')[0].strip()
        state = line.split(mdid)[1].replace(" -", " ").strip()
        mds.add_log_record(mdid, state, 5, parse_time_and_date(line))

class DetachSlotFilter(AbstractFilter):
    """ Detach slot """
    def __init__(self):
        super(DetachSlotFilter, self).__init__()
    def get_words_to_search(self):
        return ('DetachSlot', 'MdController')
    def handle(self, line, mds):
        rpd_ip = line.split('rpdIp:')[1].strip()
        rpd_slot = line.split('slotId:')[1].strip().split(' ')[0].strip()
        rpd_chassis = line.split('chassisId:')[1].strip().split(' ')[0].strip()
        msg = format_attach_msg(DETACH_SLOT_STR, rpd_ip, rpd_chassis, rpd_slot)
        mds.broadcast_message(msg, 4, parse_time_and_date(line))

class AttachSlotFilter(AbstractFilter):
    """ Attach slot """
    def __init__(self):
        super(AttachSlotFilter, self).__init__()
    def get_words_to_search(self):
        return ('AttachSlot', 'MdController', 'warm:')
    def handle(self, line, mds):
        warm = line.split('warm:')[1].strip() == str(1)
        rpd_ip = line.split('rpdIp:')[1].strip().split(' ')[0].strip()
        rpd_slot = line.split('slotId:')[1].strip().split(' ')[0].strip()
        rpd_chassis = line.split('chassisId:')[1].strip().split(' ')[0].strip()
        if warm:
            msg = format_attach_msg(WARM_ATTACH_STR, rpd_ip, rpd_chassis, rpd_slot)
            mds.broadcast_message(msg, 4, parse_time_and_date(line))
        else:
            msg = format_attach_msg(ATTACH_SLOT_STR, rpd_ip, rpd_chassis, rpd_slot)
            mds.broadcast_message(msg, 4, parse_time_and_date(line))



def parse_time_and_date(line):
    """ parse date from log line """
    line_arr = line.split(' ')
    date_str = line_arr[0] + ' ' + line_arr[1]
    return date_str


def format_attach_msg(msg, rpd_ip, chassis, slot):
    """ format attach slot """
    msg = '{} (ip={} : {}/{})'.format(msg, rpd_ip, chassis, slot)
    return msg
