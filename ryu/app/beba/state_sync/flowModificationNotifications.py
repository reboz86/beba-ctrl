import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as osp
import ryu.ofproto.beba_v1_0_parser as osparser
import array
from xdiagnose.pci_devices import RADEON
import struct
import binascii


LOG = logging.getLogger('app.beba.maclearning')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

devices=[]

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

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if Beba supported """
		msg = event.msg
		datapath = msg.datapath
		devices.append(datapath)
	

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = osparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_dst} """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osp.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = osparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=osp.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofp.OFPP_FLOOD
				else:
					out_port = s
				actions = [osparser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
							ofparser.OFPActionOutput(out_port)
							#,ofparser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                        # ofp.OFPCML_NO_BUFFER)
					  ]
				self.add_flow(datapath=datapath, table_id=0, priority=0,
								match=match, actions=actions)
				
				
        # State Sync: parse flow mod notification message	
	@set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
	def packet_in_handler(self, event):
		msg = event.msg
		if(msg.body.experimenter==0xBEBABEBA and msg.body.exp_type==osp.OFPT_EXP_FLOW_NOTIFICATION) :
			(table_id, ntf_type)= struct.unpack('!II', msg.body.data[:struct.calcsize("!II")])
			if ofp.OFPT_FLOW_MOD == ntf_type :
				print "**********************"
				print ("Notification FLOW_MOD")
				print ("Table id "+ str(table_id))
				match = ofparser.OFPMatch.parser(msg.body.data, struct.calcsize("!II"))	
				print ("Match "+ str(match))
				data = msg.body.data[struct.calcsize('!II')+match.length:]
				form = '!'+str(len(data)/struct.calcsize('!I'))+'I'
				instructions = struct.unpack_from(form, data, 0)
				print "Number of instructions " + str(instructions[0])
				print "Instructions " + str(instructions[1:])
					
				
