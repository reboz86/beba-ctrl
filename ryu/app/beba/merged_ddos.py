import logging
import csv
import math

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib.packet import ether_types, in_proto
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

# Time stamps for output messages
import time
import datetime

LOG = logging.getLogger('app.beba.merged_ddos')

MONITORING_SLEEP_TIME = 5
# 1->small precision 68%; 2->medium precision 95%; 3->high precision 99,7%
Precision = 3
single_features = {0: [ofproto.OXM_OF_IPV4_SRC],
                   1: [ofproto.OXM_OF_IPV4_DST],
                   2: [ofproto.OXM_OF_TCP_SRC],
                   3: [ofproto.OXM_OF_TCP_DST],
                   4: [ofproto.OXM_OF_UDP_SRC],
                   5: [ofproto.OXM_OF_UDP_DST]};
"""
TCP flag values
"""
# Special value for ignoring packet's flags.
F_DONT_CARE = 0xfff
F_SYN = 0x02
F_SYN_ACK = 0x12
F_ACK = 0x10

class FSM_T6_Normal:
    """
    Table 6 FSM for normal mode of operation
    FSM state definitions.
    """
    INIT = 0
    OPEN = 14 # TODO: Put all constanst to one class or package
    def load_fsm(self, dp):

        LOG.info("Loading Table 6 normal FSM on datapath %d...", dp.id)
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state INIT - ANY
        """
        Match a first packet of a new TCP flow (regardless of TCP flags)
        """
        match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                  ip_proto=in_proto.IPPROTO_TCP,
                                  state = self.INIT)

        """
        Forward the packet to the corresponding output interface and create
        entries for both directions of given flow in the OPEN state (forward
        all consecutive packets).
        ( TODO - hard-coded output)
        """
        actions = [# Create entry for direction of incoming packet
            bebaparser.OFPExpActionSetState(state = self.OPEN,
                                            table_id = 6, # TODO - TIMEOUTS
                                            idle_timeout = 10,
                                            bit = 0),
            # Create entry for opposite direction since response is expected
            bebaparser.OFPExpActionSetState(state = self.OPEN,
                                            table_id = 6, # TODO - TIMEOUTS
                                            idle_timeout = 10,
                                            bit = 1)]
        """
        Apply forward actions and the creation of entries, pass the first packet
        to the table 8 for the new TCP connections statistics computation.
        """
        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions),
                ofparser.OFPInstructionGotoTable(table_id = 7)]

        mod = ofparser.OFPFlowMod(datapath = dp,
                                  table_id = 6,
                                  priority=100,
                                  match = match,
                                  instructions = inst)
        dp.send_msg(mod)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state OPEN - ANY
        """
        Forward all consecutive packets of already seen flow by matching on
        previously created entries.
        """
        match = ofparser.OFPMatch(eth_type = 0x0800,
                                  ip_proto = 6,
                                  state = self.OPEN)
        """
        Just output packet to the corresponding output interface.
        ( TODO - hard-coded output)
        """
        actions = [bebaparser.OFPExpActionSetState(state = self.OPEN,
                                                   table_id = 6,# TODO-TIMEOUTS
                                                   idle_timeout = 10,
                                                   bit = 0),
                   # Refresh timeouts only
                   bebaparser.OFPExpActionSetState(state = self.OPEN,
                                                   table_id = 6, # TODO-TIMEOUTS
                                                   idle_timeout = 10,
                                                   bit = 1)]

        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions),
                ofparser.OFPInstructionGotoTable(table_id = 8)]
        mod = ofparser.OFPFlowMod(datapath = dp,
                                  table_id = 6,
                                  priority = 100,
                                  match = match,
                                  instructions = inst)
        dp.send_msg(mod)
        LOG.info("Done.")
################################################################################

class FSM_T6_Mtg:
    """ Table 6 FSM for DDoS mitigation mode of operation."""
    """ FSM state definitions. """
    # Special value, used when state of given entry will not be set.
    CH_STATE_NONE = -1

    INIT = 0
    SYN = 11
    SYN_ACK = 12
    ACK = 13
    OPEN = 14
    ERROR = 16
    """TODO limit retransmission count by parameter"""
    SYN_R = 111
    SYN_ACK_R = 121

    # Special value for dropping a packet.
    NO_OUTPUT = []
    # Values for packet counting determination..
    COUNT_PKT = True
    DO_NOT_COUNT_PKT = False

    """
    Template for packet handling rules.
    An incoming packet has to be an ethernet, TCP packet. The packet is matched
    to an entry in state "act_state" and optionally has to have "flags" set.
    Set "flags" to "self.F_DONT_CARE" to skip packet's flags matching.
    ( TODO - add masks?)
    Actions could be set to:
    - Output the packet to "output_ports" - list of output port
    numbers. Set parameter "output_ports" to "self.NO_OUTPUT" for dropping the
    packet.
    - Set a state and timeouts for the source (actual direction) and the
    destination (opposite direction) entries. Set "ch_state_src" /
    "ch_state_dst" to "self.CH_STATE_NONE" for skipping given direction entry.
    Instructions consists of an application of actions and an optional passage
    of the packet to the table1 for counting of first packets of new TCP
    connections. Set "count_in" to "self.COUNT_PKT" to pass the packet for
    counting, set to "self.DO_NOT_COUNT_PKT" otherwise.
    Finally a modification message with the "priority" from the parameter is
    composed and sent to the "datapath".
    """

    def process_packet(self, datapath,
                       act_state, flags,
                       output_ports,
                       ch_state_src, idle_to_src, hard_to_src,
                       ch_state_dst, idle_to_dst, hard_to_dst,
                       priority,
                       count_in):
        """
        Match packet - ethernet, TCP protocol, state (parameter), optional
        flags (parameter).
        """
        if flags == F_DONT_CARE:
            match = ofparser.OFPMatch(eth_type = 0x0800,
                                      ip_proto = 6,
                                      state = act_state)
        else:
            match = ofparser.OFPMatch(eth_type = 0x0800,
                                      ip_proto = 6,
                                      state = act_state,
                                      tcp_flags = flags)
        """
        Set actions:
        - Output ports (parameter - list).
        - SetState for both directions (parameters).
        """
        actions = []
        for port in output_ports:
            actions.append(ofparser.OFPActionOutput(port))

        if ch_state_src != self.CH_STATE_NONE:
            actions.append(bebaparser.OFPExpActionSetState(state = ch_state_src,
                                                    table_id = 6,#TODO-TIMEOUTS
                                                    idle_timeout = idle_to_src,
                                                    hard_timeout = hard_to_src,
                                                    bit = 0))

        if ch_state_dst != self.CH_STATE_NONE:
            actions.append(bebaparser.OFPExpActionSetState(state = ch_state_dst,
                                                    table_id = 6,#TODO-TIMEOUTS
                                                    idle_timeout = idle_to_dst,
                                                    hard_timeout = hard_to_dst,
                                                    bit=1))
        """
        Set instructions:
        - Apply previously defined actions.
        - Optionally pass packet to table1 for counting.
        """
        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions)]
        if count_in:
                inst.append(ofparser.OFPInstructionGotoTable(table_id=7))
        """
        Prepare and send message.
        """

        mod = ofparser.OFPFlowMod(datapath = datapath,
                                  table_id = 6,
                                  priority = priority,
                                  match = match,
                                  instructions = inst)
        datapath.send_msg(mod)
    def load_fsm(self, dp):
        LOG.info("Loading Table 6 DDoS detection and mitigation"\
        " FSM for datapath %d...", dp.id)
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state ERROR - ANY
        """
        Any TCP packet received in ERROR state is dropped.
        """
        self.process_packet(dp,
                            self.ERROR, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
                            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)
        # TODO - count erroneous packets as they can be part of active DDoS?

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state INIT - OK (SYN)
        """
        - Match first packet of new TCP flow - only SYN packet is allowed.
        - Drop first SYN packet (force a SYN packet retransmission).
        - Create an entry for the first SYN packet retransmission.
        - Pass this first packet to the table 8 for a new TCP connections
        statistics computation.
        """
        self.process_packet(dp,
                            self.INIT, F_SYN,
                            self.NO_OUTPUT,
                            self.SYN, 10, 0, # TODO - adjust timeouts
                            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
                            100,
                            self.COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state INIT - BAD (not SYN)
        """
        Every first TCP packet of new TCP connection, with flags different thn
        SYN is considered as malicious.
        - Drop the packet.
        - Create new entry for this flow in erroneous state with hard-timeout
        ( TODO set hard or inactive timeout: blocking of active malicious flows
          vs. blocking valid attempts after initial failure if these attempts
          occurs more often then inactive timeout.)
        """
        self.process_packet(dp,
                            self.INIT, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
                            90,
                            self.COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state SYN - OK (SYN - "forced" retransmission)
        """
        - Match a retransmitted SYN packet (which was intentionally dropped
          in the INIT state).
        - Forward the packet to the corresponding output interface.
        - Update an entry in source direction to the SYN_R state (for normal S
          retransmissions)
        - Create an entry for opposite direction in the SYN_ACK state (as th
          SYN+ACK packet is expected as a response to the SYN packet).
        ( TODO - hard-coded output)
        """
        self.process_packet(dp,
                            self.SYN, F_SYN,
                            [2],
                            self.SYN_R, 10, 0, # TODO - adjust timeouts
                            self.SYN_ACK, 10, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state SYN - BAD (not SYN)
        """
        Did not received retransmitted SYN packet (which was intentionally
        dropped in INIT state).
        - Drop the packet.
        - Transfer state of given entry into the ERROR state.
        """
        self.process_packet(dp,
                            self.SYN, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
                            90,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state SYN_R - OK (SYN - "normal" retransmission)
        """
        - Match retransmitted SYN packet (normal retransmissions).
        - Forward a packet to the corresponding output interface.
        - Keep entry in the SYN_R state (source direction).
        - TODO Keep entry in the SYN_ACK state (opposite direction).
        ( TODO - limit retransmissions)
        ( TODO - hard-coded output)
        """
        self.process_packet(dp,
                            self.SYN, F_SYN,
                            [2],
                            self.SYN_R, 10, 0, # TODO - adjust timeouts
                            self.SYN_ACK, 10, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK - OK (SYN+ACK)
        """
        - Match a SYN+ACK packet (as a response to the SYN packet).
        -Forward the packet to the corresponding output interface.
        - Transfer a state to the SYN_ACK_R state for this direction (accept
        only SYN_ACK retransmissions).
        - Transfer a state to the ACK state for the opposite direction entry
        (a continuation of TCP handshake).
        ( TODO - hard-coded output)
        """
        self.process_packet(dp,
                            self.SYN_ACK, F_SYN_ACK,
                            [1],
                            self.SYN_ACK_R, 10, 0, # TODO - adjust timeout
                            self.ACK, 10, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK - BAD (not SYN+ACK)
        """
        Received an unexpected TCP packet (expected only SYN+ACK).
        - Drop the packet.
        - Transfer state of given entries (both directions) into the ERROR
        state.
        """
        self.process_packet(dp,
                            self.SYN_ACK, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            90,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK_R - OK (SYN+ACK - "normal" retransmission)
        """
        - Match retransmitted SYN+ACK packet(s).
        - Forward the packet to the corresponding output interface.
        - Transfer a state to the SYN_ACK_R state for this direction (accept
          only SYN_ACK retransmissions.
        - Transfer a state to the ACK state for an opposite direction entry
          (continuation of TCP handshake).
        ( TODO - hard-coded output)
        ( TODO - limit retransmissions)
        """
        self.process_packet(dp,
                            self.SYN_ACK_R, F_SYN_ACK,
                            [1],
                            self.SYN_ACK_R, 10, 0, # TODO - adjust timeouts
                            # TODO - need to set this? refresh timeout?
                            self.ACK, 10, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK_R - BAD (not SYN_ACK)
        """
        Received an unexpected TCP packet (expected only SYN+ACK
        retransmissions).
        - Drop the packet.
        - Transfer a state of given entries (both directions) into the ERROR
          state.
        """
        self.process_packet(dp,
                            self.SYN_ACK_R, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            90,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## ACK - OK (ACK)
        """
        - Match an ACK packet (as a response to the SYN+ACK packet).
        - Forward the packet to the corresponding output interface.
        - Transfer states to the OPEN state for both directions.
        ( TODO - hard-coded output)
        """
        self.process_packet(dp,
                            self.ACK, F_ACK,
                            [2],
                            self.OPEN, 0, 0, # TODO - adjust timeouts
                            self.OPEN, 0, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## ACK - BAD (not ACK)
        """
        Received an unexpected TCP packet (expected only an ACK packet).
        - Drop the packet.
        - Transfer state of given entries (both directions) into the ERROR
        state.
        """
        self.process_packet(dp,
                            self.SYN_ACK, F_DONT_CARE,
                            self.NO_OUTPUT,
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            self.ERROR, 0, 10, # TODO - adjust timeouts
                            90,
                            self.DO_NOT_COUNT_PKT)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## OPEN - OK (ANY)
        """
        - Match any TCP packet.
        - Forward the packet to the corresponding output interface.
        - Keep entries for both directions in the OPEN state.
        ( TODO - hard-coded output)
        """
        self.process_packet(dp,
                            self.OPEN, F_DONT_CARE,
                            [1,2],
                            self.OPEN, 300, 0, # TODO - adjust timeouts
                            self.OPEN, 300, 0, # TODO - adjust timeouts
                            100,
                            self.DO_NOT_COUNT_PKT)

        LOG.info("Done.")
        """
        TODO - keep track of FIN packets in the OPEN state, clear the record
        after a valid TCP connection termination.
        """

################################################################################
class Table_Cntr:
    """
    Table for counting of TCP connection with SYN flag.
    """
    # Define states. First one is for unknown states and the second one
    # for known states.
    UNKNOWN_SYN = 0
    KNOWN_SYN = 1

    def load_fsm(self, dp):
        LOG.info("Loading Table 8 (SYN counter) for datapath %d...", dp.id)
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        """
        Create two records for implementation of SYN counter.The first one
        is used for counting of unkwnotn packets with SYN flag.
        After that, we use the second  record for counting of already known SYN
        flows.
        """
        # Setup the record for matching of unknown SYN
        actions = [bebaparser.OFPExpActionSetState(state = self.KNOWN_SYN,
                                                   table_id = 7,# TODO-TIMEOUTS
                                                   idle_timeout = 1)]

        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions),
                ofparser.OFPInstructionGotoTable(table_id=8)]

        match = ofparser.OFPMatch(eth_type = 0x0800,
                                  ip_proto = 6,
                                  state = self.UNKNOWN_SYN,
                                  tcp_flags = F_SYN)


        mod = ofparser.OFPFlowMod(datapath = dp,
                                  table_id = 7,
                                  priority = 1,
                                  match = match,
                                  instructions = inst)
        dp.send_msg(mod)

        actions = []
        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                               actions),
                ofparser.OFPInstructionGotoTable(table_id=8)]

        match = ofparser.OFPMatch(eth_type = 0x0800,
                                  ip_proto = 6,
                                  state = self.KNOWN_SYN,
                                  tcp_flags = F_SYN)

        mod = ofparser.OFPFlowMod(datapath = dp,
                                  table_id = 7,
                                  priority = 1,
                                  match = match,
                                  instructions = inst)
        dp.send_msg(mod)
################################################################################

class MergedDdosMitigation(app_manager.RyuApp):
    DDOS_ACTIVE_TRESHOLD = 200
    DDOS_INACTIVE_TRESHOLD = 140
    FIXED_TIMEOUT_TIME = 10 # 10 seconds of timeout duration

    timeout_time = 0

    def __init__(self, *args, **kwargs):
        super(MergedDdosMitigation, self).__init__(*args, **kwargs)
        # Entropy List
        self.Entropy_IPsrc, self.Entropy_IPdst, self.Entropy_Portsrc,\
            self.Entropy_Portdst, self.Abscisse_time = ({} for i in range(5))
        # Candidate address and ports that are not outside the entropy
        self.candidate_victim_address, self.candidate_victim_port,\
            self.candidate_attacker_address, self.candidate_attacker_port = \
            ({} for i in range(4))
        # Datapath +SYN DDoS_detected + Features dictionaries
        self.datapaths, self.syn_ddos_detected,  self.IPsrc, self.IPdst,\
            self.Portsrc, self.Portdst, self.TCPPortsrc, self.TCPPortdst,\
            self.UDPPortsrc, self.UDPPortdst = ({} for i in range(10))
        self.replies = {}

        self.normal_FSM=FSM_T6_Normal()
        self.ddos_mtg_FSM=FSM_T6_Mtg()
        self.counter_engine=Table_Cntr()
        # Setup default values of helping flags
        self.mitig_on = False
        self.old_unknown_syn = 0
        # External files to store calculated values
        with open('entropy.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["Time (s)"," IP Src Entropy"," IP Dst Entropy",
                             " Port Src Entropy"," Port Dst Entropy"])
            csvfile.close()

        with open('counters.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["Time (s)"," IPsrc"," State"," IPdst"," State",
                             " Portsrc"," State"," Portdst"," State"])
            csvfile.close()
        open('counter_ip_src.csv', 'wb').close()
        open('counter_ip_dst.csv', 'wb').close()
        open('counter_port_src.csv', 'wb').close()
        open('counter_port_dst.csv', 'wb').close()

        self.timer = 1

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):

        """ Parse the datapath and remember it as class variable dection and
        mitigation will be tested in the virtual environment """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.replies[datapath.id] = 0
                self.syn_ddos_detected[datapath.id] = False

                self.Entropy_IPsrc[datapath.id],\
                    self.Entropy_IPdst[datapath.id],\
                    self.Entropy_Portsrc[datapath.id],\
                    self.Entropy_Portdst[datapath.id],\
                    self.Abscisse_time[datapath.id] =\
                    ([] for i in range(5)) # Entropy List

                LOG.info("Configuring switch %d..." % datapath.id)
                self.configureSwitch(self.datapaths[datapath.id])
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                del self.replies[datapath.id]
                del self.syn_ddos_detected[datapath.id]
                del self.Entropy_IPsrc[datapath.id],\
                    self.Entropy_IPdst[datapath.id],\
                    self.Entropy_Portsrc[datapath.id],\
                    self.Entropy_Portdst[datapath.id],\
                    self.Abscisse_time[datapath.id]

    def configureSwitch(self, datapath):

        """ Configuration of the State Tables """
        for table in range(len(single_features) + 3):
            """Add 3 for the SYN-Ack mitigation and the MAC learning table

            Remove all entries from table """
            self.clear_table(datapath,table)
            LOG.info("Setting up Table %d ...", table)
            """ Set tables as stateful (all)"""
            req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
                                                             table_id=table,
                                                             stateful=1)
            datapath.send_msg(req)

            if table < 6:
                """ Set lookup extractor """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                    command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                    fields=single_features[table],
                                    table_id=table)
                datapath.send_msg(req)

                """ Set update extractor """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                    command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                    fields=single_features[table],
                                    table_id=table)
                datapath.send_msg(req)

                if table == 0:
                    """ Increment State + forward to the TCP / UDP Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_TCP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table+1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_UDP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table+1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_ICMP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table+1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                elif table == 1:
                    """ Increment State + forward to the TCP / UDP Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_TCP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table+1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_UDP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id= table+3)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ip_proto=in_proto.IPPROTO_ICMP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=8)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                elif table == 3:
                    """ Increment State + forward to the last Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=6)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=0, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                elif table == 5:
                    """ Increment State + forward to the last Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=8)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=0, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

                else:
                    """ Increment State + forward to the next Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions
                            (ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table+1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=0, match=match,
                                              instructions=inst)
                    datapath.send_msg(mod)

            elif table == 6:

                """ Tables 6 and 7 only extractors because
                FSM is loaded at runtime"""
                """ Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst}
                TODO - proto=TCP??   """
                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command = bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_TCP_SRC,
                                        ofproto.OXM_OF_TCP_DST],
                                        table_id = table)
                datapath.send_msg(req)

                """ Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst}"""
                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command = bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_TCP_SRC,
                                        ofproto.OXM_OF_TCP_DST],
                                        table_id = table,
                                        bit = 0)
                datapath.send_msg(req)

                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command = bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_TCP_DST,
                                        ofproto.OXM_OF_TCP_SRC],
                                        table_id = table,
                                        bit = 1)
                datapath.send_msg(req)

            elif table == 7:

                """ Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst}
                TODO - proto=TCP??   """
                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command = bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_TCP_SRC,
                                        ofproto.OXM_OF_TCP_DST],
                                        table_id = table)
                datapath.send_msg(req)

                """ Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst}"""
                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command = bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_TCP_SRC,
                                        ofproto.OXM_OF_TCP_DST],
                                        table_id = table)
                datapath.send_msg(req)

                req = bebaparser.OFPExpMsgKeyExtract(datapath = datapath,
                                command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                fields=[ofproto.OXM_OF_IPV4_SRC,
                                        ofproto.OXM_OF_IPV4_DST,
                                        ofproto.OXM_OF_TCP_SRC,
                                        ofproto.OXM_OF_TCP_DST],
                                        table_id = table,
                                        bit = 1)
                datapath.send_msg(req)

                LOG.info("Done")

            elif table ==8:
                ################################################################
                #                        MAC LEARNING IMPLEMENTATION           #
                ################################################################
                """ Set lookup extractor = {eth_dst} """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                    command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                    fields=[ofproto.OXM_OF_ETH_DST],
                                    table_id=table)
                datapath.send_msg(req)

                """ Set update extractor = {eth_src}  """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                    command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                    fields=[ofproto.OXM_OF_ETH_SRC],
                                    table_id=table)
                datapath.send_msg(req)
                # for each input port, for each state
                N = 3
                for i in range(1, N + 1):
                    for s in range(N + 1):
                        match = ofparser.OFPMatch(in_port=i, state=s)
                        if s == 0:
                            out_port = ofproto.OFPP_FLOOD
                        else:
                            out_port = s

                        actions = [bebaparser.OFPExpActionSetState(state=i,
                                            table_id=table, hard_timeout=10),
                                   ofparser.OFPActionOutput(out_port)]
                        inst = [ofparser.OFPInstructionActions
                                (ofproto.OFPIT_APPLY_ACTIONS, actions)]
                        mod = ofparser.OFPFlowMod(datapath=datapath,
                                                table_id=table, priority=0,
                                                match=match, instructions=inst)
                        datapath.send_msg(mod)
            ####################################################################

        """ Set switches behavior - start default behavior and after that start
        the monitoring thread
        Enable "ping" command """
        self.load_arp_icmp(datapath)
        ## Load FSM (table0) for normal mode of operation
        self.normal_FSM.load_fsm(datapath)
        ## Load SYN counter (table1)
        self.counter_engine.load_fsm(datapath)
        ## Create a monitoring thread (each X seconds start the collection)
        self.monitor_thread = hub.spawn(self._monitor)
        LOG.info("Starting DDoS detection ...")

    def load_arp_icmp(self, datapath):
        match = ofparser.OFPMatch(eth_type = ether_types.ETH_TYPE_ARP)
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath = datapath,
                      table_id = 0,
                      priority = 100,
                      match = match,
                      actions = actions)

        # ICMP packets flooding - simple, TEMPORARY and dull solution.
        match = ofparser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP,ip_proto=1)
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath = datapath,
                      table_id = 0,
                      priority = 1,
                      match = match,
                      actions=actions)

    def add_flow(self, datapath, table_id, priority,
                 match, actions, hard_timeout=0):
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions
                    (ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match,
                                  instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table. """
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath,
                0,
                0,
                table_id,
                ofproto.OFPFC_DELETE,
                0,
                0,
                1,
                ofproto.OFPCML_NO_BUFFER,
                ofproto.OFPP_ANY,
                ofproto.OFPG_ANY,
                0,
                match,
                instructions)
        return flow_mod

    def clear_table(self,datapath,table_id):
        """
        Cleans all table values
        Parameters:
            - datapath  = datapath to use
            - table_id  = id of the table
        """
        empty_match = ofparser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath,
                table_id,
                empty_match,
                instructions)
        datapath.send_msg(flow_mod)

    def _monitor(self):
        """
        This is the monitoring thread which is called
        periodically to retrieve statistics
        """
        while True:
            # Send the states requests to the state tables
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self.replies[dp.id] = 0

            hub.sleep(MONITORING_SLEEP_TIME)  # Wait X seconds

    def _request_stats(self, datapath):
        # for table in range(8):
        cookie = cookie_mask = 0

        req = ofparser.OFPFlowStatsRequest(datapath, 0, 7,ofproto.OFPP_ANY,
                                           ofproto.OFPG_ANY,cookie, cookie_mask)
        datapath.send_msg(req)

        for table in range(6):
            req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(datapath,
                                                                table_id=table)
            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        # Retreive and store states stats information
        if (msg.body.experimenter==0XBEBABEBA):
            if (msg.body.exp_type==bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
                data = msg.body.data
                state_stats_list = bebaparser.OFPStateStats.parser(data, 0)
                if (state_stats_list != 0):
                    self.replies[datapath.id] += 1
                    for index in range(len(state_stats_list)):
                        if (state_stats_list[index].entry.state != 0):
                            if (int(state_stats_list[index].table_id) == 0):
                                #IP src dictionary
                                self.IPsrc[(str(state_stats_list[index]
                                                .entry.key)[1:-1])
                                           .replace(", ",".")] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 1):
                                # IP dst dictionary
                                self.IPdst[(str(state_stats_list[index]
                                                .entry.key)[1:-1])
                                           .replace(", ",".")] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 2):
                                # TCP Port src + Port src dictionaries
                                portsrc = self.convertPort2Int(
                                    state_stats_list[index].entry.key)
                                self.Portsrc[portsrc] = \
                                state_stats_list[index].entry.state
                                self.TCPPortsrc[portsrc] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 3):
                                # TCP Port dst + Port dst dictionaries
                                portdst = self.convertPort2Int(
                                    state_stats_list[index].entry.key)
                                self.Portdst[portdst] = \
                                state_stats_list[index].entry.state
                                self.TCPPortdst[portdst] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 4):
                                # UDP Port src dictionary
                                portsrc = self.convertPort2Int(
                                    state_stats_list[index].entry.key)
                                self.UDPPortsrc[portsrc] = \
                                state_stats_list[index].entry.state

                            elif (int(state_stats_list[index].table_id) == 5):
                                # UDP Port dst dictionary
                                portdst = self.convertPort2Int(
                                    state_stats_list[index].entry.key)
                                self.UDPPortdst[portdst] = \
                                state_stats_list[index].entry.state

                else:
                    LOG.info("No data")

            if (self.replies[datapath.id] == 6): # If we have all the replies
                if (len(self.IPsrc)!=0): # if counters are != 0
                    self.entropy_computation(datapath)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handler for processing of records from table
        """
        # OFPFlowStats instantes will be transformed to FlowStat objecsts
        # and inserted to the list
        #pdb.set_trace()
        if len(ev.msg.body) == 0:
            return

        unknown_syn = int(ev.msg.body[0].packet_count)
        new_flows = unknown_syn - self.old_unknown_syn
        self.old_unknown_syn = unknown_syn
        self.detect_syn_ddos(new_flows, ev.msg.datapath)

    def entropy_computation(self, datapath):
        # Port src dictionary = TCP + UDP Port src dictionaries
        for index in self.UDPPortsrc:
            if index in self.Portsrc: # We add the two values
                new_port = self.Portsrc[index] + self.UDPPortsrc[index]
                self.Portsrc[index] = new_port
            else: # We create a new entry
                self.Portsrc[index] = self.UDPPortsrc[index]
            # Port dst dictionary = TCP + UDP Port dst dictionaries
        for index in self.UDPPortdst:
            if index in self.Portdst:
                new_port = self.Portdst[index] + self.UDPPortdst[index]
                self.Portdst[index] = new_port
            else:
                self.Portdst[index] = self.UDPPortdst[index]

        #Entropy calculation:
        entropy_ip_src = self.entropy(self.IPsrc)
        entropy_ip_dst = self.entropy(self.IPdst)
        entropy_port_src = self.entropy(self.Portsrc)
        entropy_port_dst = self.entropy(self.Portdst)

        # Storing entropies in lists:
        self.Entropy_IPsrc[datapath.id].append(entropy_ip_src)
        self.Entropy_IPdst[datapath.id].append(entropy_ip_dst)
        self.Entropy_Portsrc[datapath.id].append(entropy_port_src)
        self.Entropy_Portdst[datapath.id].append(entropy_port_dst)

        # Storing the Counters + Entropies in an output file:
        self.storeInFile(datapath)

        # Printing the entropies:
        LOG.info('===========================================')
        LOG.info("%d %s Entropy values for switch %d : %f %f %f %f"
                 % (time.mktime(time.localtime()),
                    time.strftime("%d.%m. %H:%M:%S"),
                    datapath.id,
                    entropy_ip_src, entropy_ip_dst,
                    entropy_port_src, entropy_port_dst))

        """
        Detection process
        Wait 20s before starting the detection,
        we need at least 2 elements in entropy lists
        """
        if ((len(self.Entropy_IPsrc[datapath.id]) > 3)
        and sum(self.Entropy_IPsrc[datapath.id]) > 1):
            self.detection(datapath)

        # Emptying dictionaries
        self.IPsrc.clear()
        self.IPdst.clear()
        self.Portsrc.clear()
        self.Portdst.clear()
        self.TCPPortsrc.clear()
        self.TCPPortdst.clear()
        self.UDPPortsrc.clear()
        self.UDPPortdst.clear()

    def mean(self, mylist):
        return float(sum(mylist))/len(mylist) if len(mylist)>0 else float('nan')

    def variance(self, mylist):
        xmean = self.mean(mylist)
        return self.mean([(x - xmean) ** 2 for x in mylist])

    def entropy(self, dictionary):
        total_states = 0
        entropy = 0
        p = 0

        for index in dictionary:
            total_states += dictionary[index]
        if (total_states != 1 and len(dictionary) !=1): # Division by 0
            for index in dictionary:
                p = float(dictionary[index])/total_states
                # Normalized entropy
                entropy += (-p * math.log(p,2))/(math.log(len(dictionary),2))
            return round(entropy,5)
        else:
            return 0

    def detect_syn_ddos(self,new_flows, datapath):
        # Traverse the list of all flows and compute the number of new flows
        LOG.info("%d %s New flow count is %d" % (time.mktime(time.localtime()),
                                time.strftime("%d.%m. %H:%M:%S"), new_flows))
        """
        A single detection is enough to trigger a global mitigation strategy.
        On the other side, mitigation mode is lifted only when ALL the switches
        does not detect DDoS anymore
        """
        if self._ddos_detected(new_flows):
            self.syn_ddos_detected[datapath.id] = True
            if self.is_mitigation_finished() :
               self._syn_mitigation(self.datapaths.values())
            # increase the detection timeout even if mitigation is still on
            self.increase_detection_timeout(self.FIXED_TIMEOUT_TIME)
            #IT MUST remain here !!

        elif self.mitig_on and self._ddos_finished(new_flows):
            self.syn_ddos_detected[datapath.id] = False
            """
            Two constraints to return to normal mode:
            all the switches have syn_ddos_detected = FALSE
            and the mitigation timeout is finished
            """
            if (not any(self.syn_ddos_detected.values())
            and self.is_mitigation_finished()):
                self._syn_return_to_normal_mode(self.datapaths.values())

    def _syn_mitigation(self, datapaths):
        ## Load FSM (table0) for DDoS mitigation mode of operation
        for dp in datapaths:
            self.ddos_mtg_FSM.load_fsm(dp)
            self.load_arp_icmp(dp)
            LOG.info("Mitigation FSM has been"\
                    " loaded to Table 6 of datapath %d", dp.id)
        self.mitig_on = True

    def _syn_return_to_normal_mode(self, datapaths):
        ## Load FSM (table6) for normal mode of operation
        #self.clear_table(self.datapath,0)
        for dp in datapaths:
            self.normal_FSM.load_fsm(dp)
            self.load_arp_icmp(dp)
            LOG.info("Normal FSM has been"\
                     " loaded to Table 6 of datapath %d", dp.id)
        self.mitig_on = False

    def _ddos_detected(self,flow_cnt):
        """
        This is the helping function which is used for mathing
        of ddos treshold.
        Parameters:
            - flow_cnt      = number of new flwos
        Return: True if ddos treshold has been detected
        """
        if flow_cnt >= self.DDOS_ACTIVE_TRESHOLD:
            return True
        return False

    def _ddos_finished(self,flow_cnt):
        """
        This is the helping function which is used for mathing
        of ddos treshold.
        Parameters:
            - flow_cnt      = number of new flwos
        Return: True if ddos treshold has been finished
        """
        if flow_cnt <= self.DDOS_INACTIVE_TRESHOLD:
            return True
        return False

    def is_mitigation_finished(self):
        LOG.info("Is mitigation finished ? %s",
                 time.mktime(time.localtime()) > self.timeout_time)
        return ( time.mktime(time.localtime()) > self.timeout_time)

    def increase_detection_timeout(self, timeout):
        """
        This function sets the timeout state for detection.
        It is used to synchronize the mitigation states among the different
        strategies (SYN-ACK, entropy, etc..)
        """
        self.timeout_time = time.mktime(time.localtime()) + timeout
        LOG.info("%d %s Detection timeout increased to %d"
                 % (time.mktime(time.localtime()),
                    time.strftime("%d.%m. %H:%M:%S"), self.timeout_time))

    def detection(self, datapath):

        # No threats
        attacktype = mitigationtype = i = 0
        Victimaddress, Victimport = ([] for i in range(2))
        Attackeraddress, Attackerport = ([] for i in range(2))
        protosrc, protodst = ([] for i in range(2))

        # Entropy IP/Port DST variance calculation
        variance_entropy_IPdst = self.variance(
            self.Entropy_IPdst[datapath.id][:-1])
        variance_entropy_IPsrc = self.variance(
            self.Entropy_IPsrc[datapath.id][:-1])
        variance_entropy_Portdst = self.variance(
            self.Entropy_Portdst[datapath.id][:-1])
        variance_entropy_Portsrc = self.variance(
            self.Entropy_Portsrc[datapath.id][:-1])

        ########################################################################
        # SLOW DDoS Detection, Reduction of the precision value to 2
        if ((self.mean(self.Entropy_IPdst[datapath.id][:-4])-2*(
                (self.variance(self.Entropy_IPdst[datapath.id][:-4]))**0.5) >
            self.Entropy_IPdst[datapath.id][-1])
            and (self.mean(self.Entropy_Portdst[datapath.id][:-4])-2*(
                (self.variance(self.Entropy_Portdst[datapath.id][:-4]))**0.5) >
            self.Entropy_Portdst[datapath.id][-1])
            and (self.Entropy_IPdst[datapath.id][-4] >
                 self.Entropy_IPdst[datapath.id][-3] >
                 self.Entropy_IPdst[datapath.id][-2] >
                 self.Entropy_IPdst[datapath.id][-1])
            and (self.Entropy_Portdst[datapath.id][-4] >
                 self.Entropy_Portdst[datapath.id][-3] >
                 self.Entropy_Portdst[datapath.id][-2] >
                 self.Entropy_Portdst[datapath.id][-1])):

            LOG.info('\033[91m******* SLOW (D)DoS Flooding DETECTED on switch'\
                     ' %d *******\033[0m', datapath.id)
            LOG.info('\033[91m******* Time: '
                     +str(datetime.datetime.now().time())+' *******\033[0m')
            mitigationtype = 1
            attacktype = 1
        ########################################################################
        elif (self.mean(self.Entropy_IPdst[datapath.id][:-1])-Precision*(
            variance_entropy_IPdst**0.5) > self.Entropy_IPdst[datapath.id][-1]):
            if (self.mean(self.Entropy_Portdst[datapath.id][:-1])-Precision*(
                    variance_entropy_Portdst**0.5) >
                self.Entropy_Portdst[datapath.id][-1]):
                """ DDoS Detection or port scan (normal values are in the
        [meanx-Precision*sigma;meanx+Precision*sigma] range, if NOT -> Attack!)
                """
                LOG.info('\033[91m******* (D)DoS Flooding  DETECTED on switch'\
                ' %d *******\033[0m', datapath.id)
                LOG.info('\033[91m******* Time: '
                         +str(datetime.datetime.now().time())+' *******\033[0m')
                mitigationtype = 1
                attacktype = 1

            elif (self.mean(self.Entropy_IPsrc[datapath.id][:-1])-Precision*(
                    variance_entropy_IPsrc**0.5) >
                  self.Entropy_IPsrc[datapath.id][-1]):

                if(self.mean(self.Entropy_Portdst[datapath.id][:-1])+Precision*(
                        variance_entropy_Portdst**0.5) <
                   self.Entropy_Portdst[datapath.id][-1]):

                    # PortScan detection
                    LOG.info('\033[91m******* PortScan  DETECTED on switch %d'\
                    '*******\033[0m', datapath.id)
                    LOG.info('\033[91m******* Time: '
                        +str(datetime.datetime.now().time())+' *******\033[0m')
                    mitigationtype = 1
                    attacktype = 2
                else:

                    # DoS ICMP FLOODING Detection
                    LOG.info('\033[91m******* DoS ICMP Flooding  DETECTED on'\
                    ' switch %d *******\033[0m', datapath.id)
                    LOG.info('\033[91m******* Time: '
                        +str(datetime.datetime.now().time())+' *******\033[0m')
                    mitigationtype = 1
                    attacktype = 3

            # DDoS ICMP FLOODING Detection
            elif (self.mean(self.Entropy_IPsrc[datapath.id][:-1])+Precision*(
                    variance_entropy_IPsrc**0.5) <
                  self.Entropy_IPsrc[datapath.id][-1]):

                LOG.info('\033[91m******* DDoS ICMP Flooding  DETECTED %d'\
                    '*******\033[0m', datapath.id)
                LOG.info('\033[91m******* Time: '
                         +str(datetime.datetime.now().time())+' *******\033[0m')
                mitigationtype = 1
                attacktype = 4

        #No mitigation to do
        if(mitigationtype == 0):
            # store all the candidates that are outside of the mean+sigma value
            variance_IPdst = self.variance((self.IPdst).values())
            for index in self.IPdst:
                # Store the IP values greater than the mean+sigma limit
                if (self.mean((self.IPdst).values()) +
                    Precision*(variance_IPdst ** 0.5) < self.IPdst[index]
                    and (index not in self.candidate_victim_address
                         or( self.candidate_victim_address[index] <
                             self.IPdst[index]))):
                    self.candidate_victim_address[index] = self.IPdst[index]
                   #LOG.info('\033[93m** storing candidate Host dest: %s %s'\
                   #'**\033[0m', index, self.candidate_victim_address[index])

            variance_Portdst = self.variance((self.Portdst).values())
            for index in self.Portdst:
                if (self.mean((self.Portdst).values()) + Precision*
                    (variance_Portdst ** 0.5) < self.Portdst[index]
                    and (index not in self.candidate_victim_port
                         or( self.candidate_victim_port[index] <
                             self.Portdst[index]))):
                    self.candidate_victim_port[index] = self.Portdst[index]
                   #LOG.info('\033[93m** storing candidate Port dest: %s %s'\
                   #'**\033[0m', index, self.candidate_victim_port[index])

            variance_IPsrc = self.variance((self.IPsrc).values())
            for index in self.IPsrc:
                if (self.mean((self.IPsrc).values()) + Precision *
                    (variance_IPsrc ** 0.5) < self.IPsrc[index]
                    and (index not in self.candidate_attacker_address
                         or( self.candidate_attacker_address[index] <
                             self.IPsrc[index]) ) ):
                    self.candidate_attacker_address[index] = self.IPsrc[index]
                   #LOG.info('\033[93m** storing candidate Host attacker: %s '\
                   #'%s **\033[0m',index,self.candidate_attacker_address[index])


            variance_Portsrc = self.variance((self.Portsrc).values())
            for index in self.Portsrc:
                if (self.mean((self.Portsrc).values()) + Precision *
                    (variance_Portsrc ** 0.5) < self.Portsrc[index]
                    and (index not in self.candidate_attacker_port
                         or( self.candidate_attacker_port[index] <
                             self.Portsrc[index]) ) ):
                    self.candidate_attacker_port[index] = self.Portsrc[index]
                   #LOG.info('\033[93m** storing candidate Port attacker: %s '\
                   #'%s **\033[0m',index,self.candidate_attacker_port[index])

            del self.Entropy_IPsrc[datapath.id][-4]
            del self.Entropy_IPdst[datapath.id][-4]
            del self.Entropy_Portsrc[datapath.id][-4]
            del self.Entropy_Portdst[datapath.id][-4]

        else:
            """
            There has been a detection, then increase the timeout for detection
            triggering at the same time the SYN-flood mitigation strategy
            """
            if self.is_mitigation_finished() :
                # This MUST stay in this order otherwise it doesn't work
                self._syn_mitigation(self.datapaths.values())
                self.increase_detection_timeout(self.FIXED_TIMEOUT_TIME)

            # Victims information:
            # IPs (always) & ports (if not portscan or ICMP)
            variance_IPdst = self.variance((self.IPdst).values())
            for index in self.IPdst:
                """Store the IP values greater than the mean and those
                that are greater than the outliers values stored before"""

                if (self.mean((self.IPdst).values())+Precision*
                    (variance_IPdst**0.5) < self.IPdst[index]
                    and ( index not in self.candidate_victim_address
                          or ( self.candidate_victim_address[index]+Precision*
                               (variance_IPdst**0.5) < self.IPdst[index]))):
                    Victimaddress.append(index)
                    if (index in self.candidate_victim_address):
                        del self.candidate_victim_address[index]

            # Ports
            if (attacktype == 1): # if not a portscan attack or ICMP Flooding
                variance_Portdst = self.variance((self.Portdst).values())
                for index in self.Portdst:
                    if (self.mean((self.Portdst).values())+Precision*
                        (variance_Portdst**0.5) < self.Portdst[index]
                        and (index not in self.candidate_victim_port
                        or(self.candidate_victim_port[index]+Precision*
                        (variance_Portdst**0.5) < self.Portdst[index]))):

                        Victimport.append(index)

                        if (index in self.candidate_victim_port):
                            del self.candidate_victim_port[index]
                # Protocols <-> Ports
                for port in Victimport:
                    if port in self.TCPPortdst and port in self.UDPPortdst:
                        if (self.TCPPortdst[port] > self.UDPPortdst[port]):
                            protodst.append(6)
                        elif (self.TCPPortdst[port] == self.UDPPortdst[port]):
                            protodst.append(0)
                        else:
                            protodst.append(17)
                    elif port in self.TCPPortdst:
                        protodst.append(6)
                    elif port in self.UDPPortdst:
                        protodst.append(17)

            # Printing the Victims' information:
            for ip in Victimaddress:
                LOG.info('\033[93m** Victim Host: %s \t %s **\033[0m', ip,
                         self.IPdst[ip] )
            for port in Victimport:
                LOG.info('\033[93m** Victim Portdst: %s \t %s**\033[0m', port,
                         self.Portdst[port])

            # Attackers information:
            variance_IPsrc = self.variance((self.IPsrc).values())
            for index in self.IPsrc:
                """
                Store the IP values that are greater than the mean+sigma limit
                and those that are greater than the outliers values stored befor
                """
                if (self.mean((self.IPsrc).values())+Precision*
                    (variance_IPsrc**0.5) < self.IPsrc[index]
                    and (index not in self.candidate_attacker_address
                         or ( self.candidate_attacker_address[index] +
                              Precision*(variance_IPsrc**0.5) <
                              self.IPsrc[index]) ) ):
                    Attackeraddress.append(index)
                    if (index in self.candidate_attacker_address):
                        del self.candidate_attacker_address[index]

            if (len(Attackeraddress)!=0):
                mitigationtype = 2

            """ Spoofed Ports Src ? and NOT AN ICMP FLOODING ATTACK"""
            if (attacktype != 3 and attacktype != 4):
                variance_Portsrc = self.variance((self.Portsrc).values())
                for index in self.Portsrc:
                    """
                    Store the Port values greater than the mean+sigma limit and
                    those greater than the outliers values stored before
                    """
                    if (self.mean((self.Portsrc).values())+Precision*
                        (variance_Portsrc**0.5) < self.Portsrc[index]
                        and (index not in self.candidate_attacker_port
                             or( self.candidate_attacker_port[index]+
                                 Precision*(variance_Portsrc**0.5) <
                                 self.Portsrc[index]) ) ):
                        Attackerport.append(index)
                        if (index in self.candidate_attacker_port):
                            del self.candidate_attacker_port[index]

                # Protocols <-> Ports
                # For each port store also the protocol type
                for port in Attackerport:
                    if port in self.TCPPortsrc and port in self.UDPPortsrc:
                        if (self.TCPPortsrc[port] > self.UDPPortsrc[port]):
                            protosrc.append(6)
                        elif (self.TCPPortsrc[port] == self.UDPPortsrc[port]):
                            protosrc.append(0)
                        else:
                            protosrc.append(17)
                    elif port in self.TCPPortsrc:
                        protosrc.append(6)
                    elif port in self.UDPPortsrc:
                        protosrc.append(17)

            # Printing the Attackers' information:
            for ip in Attackeraddress:
                LOG.info('\033[93m** Attacker IP: %s \t %s **\033[0m',
                         ip, self.IPsrc[ip])
            for port in Attackerport:
                LOG.info('\033[93m** Attacker Portsrc: %s \t %s **\033[0m',
                         port, self.Portsrc[port])

            # Don't store the last entropy values (during attack)
            del self.Entropy_IPsrc[datapath.id][-1]
            del self.Entropy_IPdst[datapath.id][-1]

            del self.Entropy_Portsrc[datapath.id][-1]
            del self.Entropy_Portdst[datapath.id][-1]

            #-------- MITIGATION------------------
            # Mitigation only if there is all the information needed:
            for dp in self.datapaths.values():
                i = j = 0
                if(len(Attackeraddress) !=0):
                    while (i < len(Attackeraddress)):
                        if(len(Attackerport) !=0):
                            while (j < len(Attackerport)):
                                """
                                If attacker IP address and port is present then
                                discard all packets from the malicious tuple
                                """
                                self.discardPackets (dp,Attackeraddress[i],
                                                Attackerport[j], protosrc[j])
                                j += 1
                        else:
                            """
                            If only the attacker IP address is present, discard
                            all packets coming from the given malicious host
                            """
                            self.blackHoleIp (dp,Attackeraddress[i])
                        i += 1

                elif (len(Victimaddress) !=0):
                    while (i < len(Victimaddress)):
                        if(len(Victimport) !=0 ):
                            while (j < len(Victimport)):
                                """
                                If no information about the attacker (e.g. for
                                DDoS attacks) reroute to honeypot/IDS
                                """
                                self.reroutePackets (dp,Victimaddress[i],
                                                     Victimport[j], protosrc[j])
                                j += 1
                        else:
                            self.reroutePackets (dp,Victimaddress[i], None, 1)
                        i += 1

    def blackHoleIp(self, datapath, ipaddress):
        # mitigation of all attacker traffic from a given IP
        actions = []

        match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                  ipv4_src=ipaddress,
                                  ip_proto=in_proto.IPPROTO_TCP)
        self.add_flow(datapath=datapath, table_id=0, priority=100,
                      match=match, actions=actions)

        match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                  ipv4_src=ipaddress,
                                  ip_proto=in_proto.IPPROTO_UDP)
        #timeout set to FIXED_TIMEOUT_TIME
        self.add_flow(datapath=datapath, table_id=0, priority=100, match=match,
                      actions=actions, hard_timeout=self.FIXED_TIMEOUT_TIME)

        LOG.info('\033[94m** Blackholing the attacker IP...'\
                    ' control message sent'\
                    ' to switch %d **\033[0m', datapath.id)

    def discardPackets(self, datapath, ipaddress, port, protocoltype):
        # mitigation of packets coming from a given IP address and port number
        if (protocoltype == 6):
            match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_src=ipaddress,
                                      ip_proto=protocoltype,tcp_src=port)
        elif (protocoltype == 17):
            match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_src=ipaddress,
                                      ip_proto=protocoltype,
                                      udp_src=port)
        elif (protocoltype == 0):
            match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_src=ipaddress,
                                      ip_proto=in_proto.IPPROTO_TCP,
                                      tcp_src=port)
            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions)
            match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_dst=ipaddress,
                                      ip_proto=in_proto.IPPROTO_UDP,
                                      udp_src=port)

        actions = []
        self.add_flow(datapath=datapath, table_id=0, priority=100, match=match,
                      actions=actions, hard_timeout=self.FIXED_TIMEOUT_TIME)
        LOG.info('\033[94m** Discarding all packets coming from the Attacker'\
                 ' IP, port tuple. Control message sent to switch %d **\033[0m',
                 datapath.id)

    def reroutePackets(self, datapath, ipdst, portdst, protocoltype):
        # mitigation of packets coming to a IP or IP:port rerouting
        if (portdst != None):
            if (protocoltype == 6):
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst,
                                          ip_proto=protocoltype,
                                          tcp_dst=portdst)
            elif (protocoltype == 17):
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst,
                                          ip_proto=protocoltype,
                                          udp_dst=portdst)
            elif (protocoltype == 0):
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst,
                                          ip_proto=in_proto.IPPROTO_TCP,
                                          tcp_dst=portdst)
                actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
                self.add_flow(datapath=datapath, table_id=0, priority=100,
                              match=match, actions=actions, hard_timeout=100)
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst,
                                          ip_proto=in_proto.IPPROTO_UDP,
                                          udp_dst=portdst)
        else:
            if (protocoltype==1):
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst,ip_proto=protocoltype)
            else:
                match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                          ipv4_dst=ipdst)

            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions,
                          hard_timeout=self.FIXED_TIMEOUT_TIME)

        LOG.info('\033[94m** Mitigation of the receiver IP, port tuple,'\
                    ' all packets rerouted... control message sent'\
                    ' to switch %d**\033[0m',datapath.id)

    def mitigation(self,
                   datapath, mitigationtype, ipaddress, protocoltype, port):
        if (mitigationtype==1): # Mitigation of the Victim's traffic
            if (port!=None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress,
                                              ip_proto=protocoltype,
                                              tcp_dst=port)
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress,
                                              ip_proto=protocoltype,
                                              udp_dst=port)
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress,
                                              ip_proto=in_proto.IPPROTO_TCP,
                                              tcp_dst=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                match=match, actions=actions, hard_timeout=100)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress,
                                              ip_proto=in_proto.IPPROTO_UDP,
                                              udp_dst=port)
            else:
                if (protocoltype==1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress,
                                              ip_proto=protocoltype)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_dst=ipaddress)
            actions = []

            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions,
                          hard_timeout=self.FIXED_TIMEOUT_TIME)
            LOG.info('\033[94m** Mitigation (of the Victim) message sent'\
                    ' **\033[0m')
        elif (mitigationtype==2): # Mitigation of the Attacker's traffic
            if (port!=None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress,
                                              ip_proto=protocoltype,
                                              tcp_src=port)
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress,
                                              ip_proto=protocoltype,
                                              udp_src=port)
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress,
                                              ip_proto=in_proto.IPPROTO_TCP,
                                              tcp_src=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                match=match, actions=actions, hard_timeout=100)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress,
                                              ip_proto=in_proto.IPPROTO_UDP,
                                              udp_src=port)
            else:
                if (protocoltype==1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress,
                                              ip_proto=protocoltype)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                              ipv4_src=ipaddress)

            actions = []
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                          match=match, actions=actions,
                          hard_timeout=self.FIXED_TIMEOUT_TIME)
            LOG.info('\033[94m** Mitigation (of the Attacker) message sent'\
                    ' **\033[0m')

    def convertPort2Int(self, keys):
        Portint = 0
        for index in range(len(keys)):
            Portint += keys[index] * math.pow(256,index)
        return int(Portint)

    def storeInFile(self,datapath):
        # Storing the time
        self.Abscisse_time[datapath.id].append(MONITORING_SLEEP_TIME*self.timer)
        self.timer += 1

        with open('entropy.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile,delimiter=',',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow([self.Abscisse_time[datapath.id][-1],
                             self.Entropy_IPsrc[datapath.id][-1],
                             self.Entropy_IPdst[datapath.id][-1],
                             self.Entropy_Portsrc[datapath.id][-1],
                             self.Entropy_Portdst[datapath.id][-1]])
            csvfile.close()

        with open('counters.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile,delimiter=';',
                                quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            for index in self.IPsrc:
                writer.writerow([self.Abscisse_time[datapath.id][-1],
                                 index,self.IPsrc[index],None,None,
                                 None,None,
                                 None,None])
            for index in self.IPdst:
                writer.writerow([self.Abscisse_time[datapath.id][-1],
                                 None,None,index,self.IPdst[index],
                                 None,None,
                                 None,None])
            for index in self.Portsrc:
                writer.writerow([self.Abscisse_time[datapath.id][-1],
                                 None,None,
                                 None,None,index,self.Portsrc[index],
                                 None,None])
            for index in self.Portdst:
                writer.writerow([self.Abscisse_time[datapath.id][-1],
                                 None,None,
                                 None,None,
                                 None,None,index,self.Portdst[index]])
            csvfile.close()

        with open('counter_ip_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["IP Src"," IP Src ID"," State"])
            positionID = 1
            for index in self.IPsrc:
                writer.writerow([index, positionID, self.IPsrc[index]])
                positionID += 1
            csvfile.close()

        with open('counter_ip_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["IP Dst"," IP Dst ID"," State"])
            positionID = 1
            for index in self.IPdst:
                writer.writerow([index, positionID, self.IPdst[index]])
                positionID += 1
            csvfile.close()

        with open('counter_port_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["Port Src"," State"])
            for index in self.Portsrc:
                writer.writerow([index,self.Portsrc[index]])
            csvfile.close()

        with open('counter_port_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',',
                                quoting=csv.QUOTE_MINIMAL,
                                lineterminator='\n')
            writer.writerow(["Port Dst"," State"])
            for index in self.Portdst:
                writer.writerow([index,self.Portdst[index]])
            csvfile.close()

    def printcounters(self):
        # Print the state stats of the dictionaries
        if ((len(self.IPsrc)!= 0) and
            (len(self.IPdst)!= 0) and
            (len(self.Portsrc)!= 0) and
            (len(self.Portdst)!= 0)):
            LOG.info('===========================================')
            for index in self.IPsrc:
                LOG.info('IPsrc= %s \t\tState= %s', index, self.IPsrc[index])
            LOG.info(' ')
            for index in self.IPdst:
                LOG.info('IPdst= %s \t\tState= %s', index, self.IPdst[index])
            LOG.info(' ')
            for index in self.Portsrc:
                LOG.info('Portsrc= %d \t\t\tState= %s', index,
                         self.Portsrc[index])
            LOG.info(' ')
            for index in self.Portdst:
                LOG.info('Portdst= %d \t\t\tState= %s', index,
                         self.Portdst[index])
