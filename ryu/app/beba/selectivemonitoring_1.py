import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.selectivemonitoring')
LOG.info("Features monitored: IP SRC/DST, PORT SRC/DST")

# Number of switch ports
N = 5
LOG.info("Support max %d ports per switch" % N)

class BebaSelectiveMonitoring_1(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(BebaSelectiveMonitoring_1, self).__init__(*args, **kwargs)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Configuration of the State Tables """
		for table in range(5):
			""" Set tables as stateful """
			req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
				table_id=table,
				stateful=1)
			datapath.send_msg(req)

			if table == 0:
				""" Set lookup extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
					fields=[ofproto.OXM_OF_IPV4_SRC],
					table_id=table)
				datapath.send_msg(req)

				""" Set update extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
					fields=[ofproto.OXM_OF_IPV4_SRC],
					table_id=table)
				datapath.send_msg(req)

			elif table == 1:
				""" Set lookup extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
					fields=[ofproto.OXM_OF_IPV4_DST],
					table_id=table)
				datapath.send_msg(req)

				""" Set update extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
					fields=[ofproto.OXM_OF_IPV4_DST],
					table_id=table)
				datapath.send_msg(req)

			elif table == 2: # Usually udp port: OXM_OF_UDP_SRC or tcp port: OXM_OF_TCP_SRC
				""" Set lookup extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
					fields=[ofproto.OXM_OF_UDP_SRC],
					table_id=table)
				datapath.send_msg(req)

				""" Set update extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
					fields=[ofproto.OXM_OF_UDP_SRC],
					table_id=table)
				datapath.send_msg(req)

			elif table == 3: # Usually udp port: OXM_OF_UDP_DST or tcp port: OXM_OF_TCP_DST
				""" Set lookup extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
					fields=[ofproto.OXM_OF_UDP_DST],
					table_id=table)
				datapath.send_msg(req)

				""" Set update extractor """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
					command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
					fields=[ofproto.OXM_OF_UDP_DST],
					table_id=table)
				datapath.send_msg(req)

			else:
				#########################################################################
				#						MAC LEARNING IMPLEMENTATION						#
				#########################################################################
				""" Set table 4 as stateful """
				req = bebaparser.OFPExpMsgConfigureStatefulTable(
						datapath=datapath,
						table_id=4,
						stateful=1)
				datapath.send_msg(req)

				""" Set lookup extractor = {eth_dst} """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
						command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
						fields=[ofproto.OXM_OF_ETH_DST],
						table_id=4)
				datapath.send_msg(req)

				""" Set update extractor = {eth_src}  """
				req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
						command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
						fields=[ofproto.OXM_OF_ETH_SRC],
						table_id=4)
				datapath.send_msg(req)
				# for each input port, for each state
				for i in range(1, N+1):
					for s in range(N+1):
						match = ofparser.OFPMatch(in_port=i, state=s)
						if s == 0:
							out_port = ofproto.OFPP_FLOOD
						else:
							out_port = s
						actions = [bebaparser.OFPExpActionSetState(state=i, table_id=table, hard_timeout=10),
									ofparser.OFPActionOutput(out_port)]
						self.add_flow(datapath=datapath, table_id=table, priority=0,
										match=match, actions=actions)
				#########################################################################

				""" Increment State + forwarding to the next Table """
			if table != 4:
				match = ofparser.OFPMatch(eth_type=0x0800)
				actions = [bebaparser.OFPExpActionIncState(table_id=table)]
				inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), ofparser.OFPInstructionGotoTable(table_id=table+1)]
				mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
								priority=10, match=match, instructions=inst)
				datapath.send_msg(mod)

		""" Table 0 """
		""" ARP packets forwarding """
		match = ofparser.OFPMatch(eth_type=0x0806)
		inst = [ofparser.OFPInstructionGotoTable(table_id=4)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)
			
		""" Drop IP-dst Broadcast for DEMO only """
		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="255.255.255.255")
		actions = []
		self.add_flow(datapath=datapath, table_id=0, priority=100,
						match=match, actions=actions)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)