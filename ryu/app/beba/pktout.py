import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser
from scapy.all import Ether, ARP
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

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

		
		LOG.info("Creating ARP triggers...")
		match = ofparser.OFPMatch(in_port=1)
		actions = [ofparser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
		self.add_flow(datapath=datapath, table_id=0, priority=0,
							 match=match, actions=actions)
		
		
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		
		if eth.ethertype != ether_types.ETH_TYPE_ARP:
			# ignore not arp packet
			LOG.info("unexpected packet...")
			return
		
		data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5') / ARP(
						hwsrc='00:01:02:03:04:05', hwdst='46:9c:96:30:ff:d5', psrc="172.16.0.2", pdst='172.16.0.1', op=2))

		actions = [parser.OFPActionOutput(1)]
		out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
		datapath.send_msg(out)

