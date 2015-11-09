import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser
from scapy.all import *

LOG = logging.getLogger('app.openstate.pkttmp')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

class OSMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSMacLearning, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofp.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)
		
	def add_pktgen_flow(self, datapath, table_id, priority, match, pkttmp_id, actions):
		if len(actions) > 0:
			inst = [osparser.OFPInstructionInSwitchPktGen(pkttmp_id, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switch sent his features, check if OpenState supported """
		msg = event.msg
		datapath = msg.datapath
		pkt_data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5')/ARP(
						hwsrc='00:01:02:03:04:05',hwdst='46:9c:96:30:ff:d5',psrc="172.16.0.2",pdst='172.16.0.1',op=2))
# 		pkt_data = b'\x01\x02\x03\x04\x05\x06'

		LOG.info("Configuring switch %d..." % datapath.id)

		LOG.info("Creating PKTTMP entries...")
		""" Create PKTTMP entries """
		req = osparser.OFPExpMsgAddPktTmp(datapath=datapath, pkttmp_id=0, pkt_data=pkt_data)
 		datapath.send_msg(req)
		
		LOG.info("Creating PKTTMP triggers...")
		""" Create PKTTMP trigger (install flow entry) """
		match = ofparser.OFPMatch(in_port=1)
		actions = [ofparser.OFPActionOutput(1)]
		self.add_pktgen_flow(datapath=datapath, table_id=0, priority=0,
							 match=match, pkttmp_id=0, actions=actions)
