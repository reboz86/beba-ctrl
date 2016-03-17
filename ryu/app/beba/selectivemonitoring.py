import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.openstate.selectivemonitoring')
# Number of switch ports
N = 4
LOG.info("Feature monitored: ipv4_dst")
LOG.info("Support max %d ports per switch" % N)

class OpenStateSelectiveMonitoring(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OpenStateSelectiveMonitoring, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)
					
		""" Set table as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, 
				table_id=0, 
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {ip_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, 									
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, 
				fields=[ofproto.OXM_OF_IPV4_DST], 
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {ip_dst} (same as lookup) """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, 
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, 
				fields=[ofproto.OXM_OF_IPV4_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Table 0 """
		""" ARP packets forwarding """
		match = ofparser.OFPMatch(eth_type=0x0806)
		inst = [ofparser.OFPInstructionGotoTable(table_id=1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)
		
		""" Drop IP-dst Broadcast for DEMO only """
		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="255.255.255.255")
		actions = []
		self.add_flow(datapath=datapath, table_id=0, priority=10,
						match=match, actions=actions)
		
		""" Increment State + forwarding to Table 1 """
		match = ofparser.OFPMatch(eth_type=0x0800)
		actions = [bebaparser.OFPExpActionIncState(table_id=0)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), ofparser.OFPInstructionGotoTable(table_id=1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
							priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

#########################################################################
#						MAC LEARNING IMPLEMENTATION						#
#########################################################################
		""" Set table 1 as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=1)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofproto.OFPP_FLOOD
				else:
					out_port = s
				actions = [bebaparser.OFPExpActionSetState(state=i, table_id=1, hard_timeout=10),
							ofparser.OFPActionOutput(out_port)]
				self.add_flow(datapath=datapath, table_id=1, priority=0,
								match=match, actions=actions)
#########################################################################


	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)