import logging
import sys
sys.path.append('/home/beba/ryu/ryu/app/openstate')
import selectivemonitoring
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.openstate.simplemonitoring')

class SimpleMonitoring(selectivemonitoring.OpenStateSelectiveMonitoring):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitoring, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.IPdst = {} # Dictionary: IP dst <->  #states

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

    def del_flow_state_handler(self, datapath):
        # Converting str keys into int list
        for key in self.IPdst.keys():
            key = key[1:-1]
            key_list = []
            last =0
            for i,c in enumerate(key):
                if ","==c:
                    key_list.append(int(key[last:i]))
                    last = i+1
                if i== len(key)-1:
                    key_list.append(int(key[last:i+1]))
            state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=key_list, table_id=0) # Delete the flow of each IP_addr
            datapath.send_msg(state)
        self.IPdst.clear() # Remove all entries in the dictionary
        LOG.info("Flow States Deleted")

    def _request_stats(self, datapath):
        req = bebaparser.OFPExpStateStatsMultipartRequest(datapath, table_id=0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        if (msg.body.experimenter == 0XBEBABEBA):
          if(msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS):
            data = msg.body.data
            state_stats_list = bebaparser.OFPStateStats.parser(data,0)
            if (state_stats_list!=0):
                for index in range(len(state_stats_list)):
                    if (state_stats_list[index].entry.state != 0):
                        self.IPdst[str(state_stats_list[index].entry.key)] = state_stats_list[index].entry.state
                        #self.del_flow_state_handler(datapath)
            else:
              LOG.info("No data")
        # Print the state stats of the dictionary
        if (len(self.IPdst)!= 0):
            LOG.info('****************************')
        for index in self.IPdst:
            LOG.info('IP_DST=%s State=%s', index, self.IPdst[index])