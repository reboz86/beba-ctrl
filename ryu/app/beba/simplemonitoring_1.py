import logging
import selectivemonitoring_1
import math
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.simplemonitoring')

class SimpleMonitoring(selectivemonitoring_1.BebaSelectiveMonitoring_1):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitoring, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.IPsrc = {} # Dictionary: IP src <->  #states
        self.IPdst = {} # Dictionary: IP dst <->  #states
        self.Portsrc = {} # Dictionary: Port src <->  #states
        self.Portdst = {} # Dictionary: Port dst <->  #states


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)
            # Remove all entries in the dictionary
            self.IPsrc.clear() 
            self.Portsrc.clear() 
            self.Portdst.clear() 
            self.IPdst.clear() 

    def _request_stats(self, datapath):
        for table in range(4):
            req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(datapath, table_id=table)
            datapath.send_msg(req)

    def convertPort2Int(self, keys):
        Portint = 0
        for index in range(len(keys)):
            Portint += keys[index] * math.pow(256,index)
        return Portint

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        if (msg.body.experimenter == 0XBEBABEBA):
          if(msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
            data = msg.body.data
            state_stats_list = bebaparser.OFPStateStats.parser(data,0)
            if (state_stats_list!=0):
                for index in range(len(state_stats_list)):
                    if (int(state_stats_list[index].table_id) == 0):
                        if (state_stats_list[index].entry.state != 0):
                            self.IPsrc[str(state_stats_list[index].entry.key)] = state_stats_list[index].entry.state
                    if (int(state_stats_list[index].table_id) == 1):
                        if (state_stats_list[index].entry.state != 0):
                            self.IPdst[str(state_stats_list[index].entry.key)] = state_stats_list[index].entry.state
                    if (int(state_stats_list[index].table_id) == 2):
                        if (state_stats_list[index].entry.state != 0):
                            portsrc = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.Portsrc[portsrc] = state_stats_list[index].entry.state
                    if (int(state_stats_list[index].table_id) == 3):
                        if (state_stats_list[index].entry.state != 0):
                            portdst = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.Portdst[portdst] = state_stats_list[index].entry.state
            else:
              LOG.info("No data")
        # Print the state stats of the dictionary
        if ((len(self.IPsrc)!= 0) and (len(self.IPdst)!= 0) and (len(self.Portsrc)!= 0) and (len(self.Portdst)!= 0)):
            LOG.info('****************************')
            for index in self.IPsrc:
                LOG.info('IPsrc= %s State= %s', index, self.IPsrc[index])
            LOG.info('---')
            for index in self.IPdst:    
                LOG.info('IPdst= %s State= %s', index, self.IPdst[index])
            LOG.info('---')
            for index in self.Portsrc:    
                LOG.info('Portsrc= %d State= %s', index, self.Portsrc[index])
            LOG.info('---')
            for index in self.Portdst:    
                LOG.info('Portdst= %d State= %s', index, self.Portdst[index])

# State Stats General Parser:
""" LOG.info('Length=%s Table ID=%s Duration_sec=%s Duration_nsec=%s Field_count=%s\n'
    'Keys:%s State=%s\n'
    'Hard_rollback=%s Idle_rollback=%s Hard_timeout=%s Idle_timeout=%s',
    str(state_stats_list[index].length), str(state_stats_list[index].table_id), str(state_stats_list[index].dur_sec), str(state_stats_list[index].dur_nsec), str(state_stats_list[index].field_count),
    bebaparser.state_entry_key_to_str(state_stats_list[index].fields, state_stats_list[index].entry.key, state_stats_list[index].entry.key_count), str(state_stats_list[index].entry.state),
    str(state_stats_list[index].hard_rb), str(state_stats_list[index].idle_rb), str(state_stats_list[index].hard_to), str(state_stats_list[index].idle_to))
    LOG.info('*************************************************************') """