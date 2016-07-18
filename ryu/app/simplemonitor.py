from operator import attrgetter
from ryu.base import app_manager
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types, in_proto
from ryu.ofproto import ofproto_v1_3

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import csv
import logging
import math
import time
import datetime

LOG = logging.getLogger('app.simplemonitor')
Timewindow = 1
Precision = 3 # 1 -> small precision 68% / 2 -> medium precision 95% / 3 -> high precision 99,7%

class SimpleMonitor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.Entropy_IPsrc, self.Entropy_IPdst, self.Entropy_Portsrc, self.Entropy_Portdst, self.Abscisse_time = ([] for i in range(5)) # Entropy Lists
        self.datapaths, self.IPsrc, self.IPdst, self.Portsrc, self.Portdst, self.TCPPortsrc, self.TCPPortdst, self.UDPPortsrc, self.UDPPortdst = ({} for i in range(9)) # Datapath + Features dictionaries
        # Lists specific for sFlow to drop counters that were detected as possible attacks
        self.Victimaddress_sflow, self.Victimport_sflow, self.Attackeraddress_sflow, self.Attackerport_sflow, self.protosrc_sflow, self.protodst_sflow = ([] for i in range(6))
        with open('sflow_entropy.csv', 'wb') as csvfile: # Set the header and Empty the file
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Time (s)"," IP Src Entropy"," IP Dst Entropy"," Port Src Entropy"," Port Dst Entropy"])
            csvfile.close()
        with open('sflow_counters.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Time (s)"," IPsrc"," State"," IPdst"," State"," Portsrc"," State"," Portdst"," State"])
            csvfile.close()
        open('sflow_counter_ip_src.csv', 'wb').close()
        open('sflow_counter_ip_dst.csv', 'wb').close()
        open('sflow_counter_port_src.csv', 'wb').close()
        open('sflow_counter_port_dst.csv', 'wb').close()
        self.timer = 1
        self.line_offset = 0
        with open('sflowtraces.csv', 'wb') as csvfile: # Set the header and Empty the file
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            csvfile.close()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        """ Drop IP-dst Broadcast (for DEMO/EVAL only) """
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="255.255.255.255")
        actions = []
        self.add_flow(datapath, 20, match, actions)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # if src not in self.mac_to_port[dpid]:
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install flow(s) to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                # return
            else:
                self.add_flow(datapath, 10, match, actions)
            if src in self.mac_to_port[dpid]:
                match = parser.OFPMatch(eth_dst=src)
                actions1 = [parser.OFPActionOutput(in_port)]            
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 10, match, actions1, msg.buffer_id)
                else:
                    self.add_flow(datapath, 10, match, actions1)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

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
            self.getsFlowvalues()
            if (len(self.UDPPortdst)!= 0 or len(self.TCPPortdst)!= 0): # If counters are != 0
               self.entropy_computation()
            hub.sleep(Timewindow) # Wait X seconds

    def getsFlowvalues(self):
        with open('sflowtraces.csv', 'rb') as csvfile:
            csvfile.seek(self.line_offset)
            reader = csv.reader(csvfile)
            for row in reader:
                if (len(row) ==5 and len(row[4]) != 0):
                    for i in range(len(row)):
                        self.line_offset += len(row[i])
                    self.line_offset += 5 # add the number of commas + escape char
                    if (len(row[0]) <= 15 and (row[2] == '17' or row[2] == '6' or row[2]== '1') and row[1] != '255.255.255.255'):# An IPv4, NOT An IPv6, only TCP, UDP and ICMP packets; NOT TO BROADCAST DST
                        Count = True
                        # Do not count features if we have mitigate the attack
                        # Time to retrieve all information about the attack
                        if (len(self.Attackeraddress_sflow) != 0 and len(self.Victimaddress_sflow) != 0 and len(self.Attackerport_sflow) != 0 and len(self.Victimport_sflow) != 0): 
                            if (len(self.Attackeraddress_sflow) != 0 and len(self.Attackerport_sflow) != 0 and Count):
                                i = j= 0
                                while i < len(self.Attackeraddress_sflow):
                                    if (row[0] == self.Attackeraddress_sflow[i]):
                                        for j in range(len(self.Attackerport_sflow)):
                                            if (row[3] == self.Attackerport_sflow[j] and int(row[2]) == self.protosrc_sflow[j]):
                                                i = len(self.Attackeraddress_sflow)
                                                Count = False
                                                break;
                                    i += 1
                            elif (len(self.Attackeraddress_sflow) != 0 and len(self.Attackerport_sflow) == 0 and Count):
                                i = j= 0
                                while i < len(self.Attackeraddress_sflow):
                                    if (row[0] == self.Attackeraddress_sflow[i]):
                                        i = len(self.Attackeraddress_sflow)
                                        Count = False
                                        break;
                                    i += 1
                            elif (len(self.Victimaddress_sflow) != 0 and len(self.Victimport_sflow) != 0 and Count):
                                i = j= 0
                                while i < len(self.Victimaddress_sflow):
                                    if (row[0] == self.Victimaddress_sflow[i]):
                                        for j in range(len(self.Victimport_sflow)):
                                            if (row[3] == self.Victimport_sflow[j] and int(row[2]) == self.protodst_sflow[j]):
                                                i = len(self.Victimaddress_sflow)
                                                Count = False
                                                break;
                                    i += 1
                            elif (len(self.Victimaddress_sflow) != 0 and len(self.Victimport_sflow) == 0 and Count):
                                i = j= 0
                                while i < len(self.Victimaddress_sflow):
                                    if (row[0] == self.Victimaddress_sflow[i]):
                                        i = len(self.Victimaddress_sflow)
                                        Count = False
                                        break;
                                    i += 1
                        
                        if (Count):
                            # Counters:
                            # IP_Src
                            if (row[0] in self.IPsrc):
                                new_state = self.IPsrc[row[0]] + 1
                                self.IPsrc[row[0]] = new_state
                            else:
                                self.IPsrc[row[0]] = 1
                            # IP_Dst
                            if (row[1] in self.IPdst):
                                new_state = self.IPdst[row[1]] + 1
                                self.IPdst[row[1]] = new_state
                            else:
                                self.IPdst[row[1]] = 1
                            # Port_Src/Dst
                            # UDP
                            if (row[2] == '17'):
                                # UDP_Port_Src
                                if (row[3] in self.UDPPortsrc):
                                    new_state = self.UDPPortsrc[row[3]] + 1
                                    self.UDPPortsrc[row[3]] = new_state
                                else:
                                    self.UDPPortsrc[row[3]] = 1
                                # UDP_Port_Dst
                                if (row[4] in self.UDPPortdst):
                                    new_state = self.UDPPortdst[row[4]] + 1
                                    self.UDPPortdst[row[4]] = new_state
                                else:
                                    self.UDPPortdst[row[4]] = 1
                            # TCP
                            elif (row[2] == '6'):
                                # TCP_Port_Src
                                if (row[3] in self.TCPPortsrc):
                                    new_state = self.TCPPortsrc[row[3]] + 1
                                    self.TCPPortsrc[row[3]] = new_state
                                    self.Portsrc[row[3]] = new_state
                                else:
                                    self.TCPPortsrc[row[3]] = 1
                                    self.Portsrc[row[3]] = 1
                                # TCP_Port_Dst
                                if (row[4] in self.TCPPortdst):
                                    new_state = self.TCPPortdst[row[4]] + 1
                                    self.TCPPortdst[row[4]] = new_state
                                    self.Portdst[row[4]] = new_state
                                else:
                                    self.TCPPortdst[row[4]] = 1
                                    self.Portdst[row[4]] = 1
            csvfile.close()

    def mean(self, mylist):
        return float(sum(mylist))/len(mylist) if len(mylist) > 0 else float('nan')

    def variance(self, mylist):
        xmean = self.mean(mylist)
        return self.mean([(x-xmean)**2 for x in mylist])

    def entropy(self, dictionary):
        total_states = 0
        entropy = 0
        p = 0

        for index in dictionary:        
            total_states += dictionary[index]
        if (total_states != 1 and len(dictionary) !=1): # Division by 0
            for index in dictionary:
                p = float(dictionary[index])/total_states
                entropy += (-p * math.log(p,2))/(math.log(len(dictionary),2)) # Normalized entropy
            return round(entropy,5)
        else:
            return 0

    def detection(self):
        # No threats
        attacktype = mitigationtype = i = 0
        Victimaddress, Victimport, Attackeraddress, Attackerport, protosrc, protodst = ([] for i in range(6))
        
        # Entropy IP/Port DST variance calculation for the Statistic Gauss's law limits  
        variance_entropy_IPdst = self.variance(self.Entropy_IPdst[:-1])
        variance_entropy_IPsrc = self.variance(self.Entropy_IPsrc[:-1])
        variance_entropy_Portdst = self.variance(self.Entropy_Portdst[:-1])

        # DDoS Detection (normal values are in the [meanx-Precision*sigma;meanx+Precision*sigma] range, if NOT -> Attack!)
        if ( (self.mean(self.Entropy_IPdst[:-1])-Precision*(variance_entropy_IPdst**0.5) > self.Entropy_IPdst[-1]) 
            and (self.mean(self.Entropy_Portdst[:-1])-Precision*(variance_entropy_Portdst**0.5) > self.Entropy_Portdst[-1])):    
            
            LOG.info('\033[91m******* (D)DoS Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: '+str(datetime.datetime.now().time())+' *******\033[0m')
            mitigationtype = 1
            attacktype = 1

        # DoS ICMP FLOODING Detection
        elif ( (self.mean(self.Entropy_IPdst[:-1])-Precision*(variance_entropy_IPdst**0.5) > self.Entropy_IPdst[-1])
            and  (self.mean(self.Entropy_IPsrc[:-1])-Precision*(variance_entropy_IPsrc**0.5) > self.Entropy_IPsrc[-1])):
        
            LOG.info('\033[91m******* DoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: '+str(datetime.datetime.now().time())+' *******\033[0m')
            mitigationtype = 1
            attacktype = 3

        # DDoS ICMP FLOODING Detection
        elif ( (self.mean(self.Entropy_IPdst[:-1])-Precision*(variance_entropy_IPdst**0.5) > self.Entropy_IPdst[-1])
            and  (self.mean(self.Entropy_IPsrc[:-1])+Precision*(variance_entropy_IPsrc**0.5) < self.Entropy_IPsrc[-1])):
        
            LOG.info('\033[91m******* DDoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: '+str(datetime.datetime.now().time())+' *******\033[0m')
            mitigationtype = 1
            attacktype = 4

        # PortScan detection
        elif ( (self.mean(self.Entropy_IPdst[:-1])-Precision*(variance_entropy_IPdst**0.5) > self.Entropy_IPdst[-1]) 
            and (self.mean(self.Entropy_Portdst[:-1])+Precision*(variance_entropy_Portdst**0.5) < self.Entropy_Portdst[-1])):

            LOG.info('\033[91m******* PortScan  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: '+str(datetime.datetime.now().time())+' *******\033[0m')
            mitigationtype = 1
            attacktype = 2

        # Extract information about the attack
        if (mitigationtype != 0):
            # Victims information:
            # IPs
            variance_IPdst = self.variance((self.IPdst).values())
            for index in self.IPdst: # Store the IP values greater than the mean+sigma limit
                if (self.mean((self.IPdst).values())+Precision*(variance_IPdst**0.5) < self.IPdst[index]):
                    Victimaddress.append(index)
                    self.Victimaddress_sflow.append(index)

            # Ports
            if (attacktype ==1): # if not a portscan attack or ICMP Flooding
                variance_Portdst = self.variance((self.Portdst).values())
                for index in self.Portdst:
                    if (self.mean((self.Portdst).values())+Precision*(variance_Portdst**0.5) < self.Portdst[index]):
                        Victimport.append(index)
                        self.Victimport_sflow.append(index)
                # Protocols <-> Ports
                for port in Victimport:
                    if port in self.TCPPortdst and port in self.UDPPortdst:
                        if (self.TCPPortdst[port] > self.UDPPortdst[port]):
                            protodst.append(6)
                            self.protodst_sflow.append(6)
                        elif (self.TCPPortdst[port] == self.UDPPortdst[port]):
                            protodst.append(0)
                            self.protodst_sflow.append(0)
                        else:
                            protodst.append(17)
                            self.protodst_sflow.append(17)
                    elif port in self.TCPPortdst:
                        protodst.append(6)
                        self.protodst_sflow.append(6)
                    elif port in self.UDPPortdst:
                        protodst.append(17)
                        self.protodst_sflow.append(17)

            # Printing the Victims' information:
            for ip in Victimaddress:
                LOG.info('\033[93m** Victim Host: %s **\033[0m', ip)
            for port in Victimport:
                LOG.info('\033[93m** Victim Portdst: %s **\033[0m', port)    

            # Attackers information:
            variance_IPsrc = self.variance((self.IPsrc).values())
            for index in self.IPsrc: # Store the IP values that are greater than the mean+sigma limit  
                if (self.mean((self.IPsrc).values())+Precision*(variance_IPsrc**0.5) < self.IPsrc[index]):
                    Attackeraddress.append(index)
                    self.Attackeraddress_sflow.append(index)
            if (len(Attackeraddress)!=0):
                mitigationtype = 2

            # Spoofed Ports Src ? and NOT AN ICMP FLOODING ATTACK
            if (attacktype != 3 and attacktype!=4):
                variance_Portsrc = self.variance((self.Portsrc).values())
                for index in self.Portsrc: # Store the Port values that are greater than the mean+sigma limit
                    if (self.mean((self.Portsrc).values())+Precision*(variance_Portsrc**0.5) < self.Portsrc[index]):
                        Attackerport.append(index)
                        self.Attackerport_sflow.append(index)
                # Protocols <-> Ports
                for port in Attackerport: # For each port store also the protocol type (needed to send the OF rule)
                    if port in self.TCPPortsrc and port in self.UDPPortsrc:
                        if (self.TCPPortsrc[port] > self.UDPPortsrc[port]):
                            protosrc.append(6)
                            self.protosrc_sflow.append(6)
                        elif (self.TCPPortsrc[port] == self.UDPPortsrc[port]):
                            protosrc.append(0)
                            self.protosrc_sflow.append(0)
                        else:
                            protosrc.append(17)
                            self.protosrc_sflow.append(17)
                    elif port in self.TCPPortsrc:
                        protosrc.append(6)
                        self.protosrc_sflow.append(6)
                    elif port in self.UDPPortsrc:
                        protosrc.append(17)
                        self.protosrc_sflow.append(17)
            
            # Printing the Attackers' information:
            for ip in Attackeraddress:
                LOG.info('\033[93m** Attacker IP: %s **\033[0m', ip)
            for port in Attackerport:
                LOG.info('\033[93m** Attacker Portsrc: %s **\033[0m', port)

            # Don't store the last entropy values because it was during an abnormal traffic 
            del self.Entropy_IPsrc[-1]
            del self.Entropy_IPdst[-1]
            if (attacktype!=3 and attacktype!=4):
                del self.Entropy_Portsrc[-1]
                del self.Entropy_Portdst[-1]

            # Mitigation process
            # Mitigation only if there is all the information needed:
            if (len(Attackeraddress) != 0 and len(Victimaddress) != 0 and len(Attackerport) !=0 and len(Victimport) !=0): 
                for dp in self.datapaths.values():
                    # ICMP Mitigation
                    if (attacktype == 3 or attacktype == 4):
                        i = 0
                        if (len(Attackeraddress) != 0):
                            mitigationtype = 2
                            while (i < len(Attackeraddress)):
                                self.mitigation(dp,mitigationtype,Attackeraddress[i],1,None)
                                i += 1
                        elif (len(Victimaddress) != 0):
                            while (i < len(Victimaddress)):
                                self.mitigation(dp,mitigationtype,Victimaddress[i],1,None)
                                i += 1
                    else:
                        if (len(Attackeraddress) != 0):
                            mitigationtype = 2
                            i = j= 0
                            while i < len(Attackeraddress):
                                if len(Attackerport) != 0:
                                    for j in range(len(Attackerport)):
                                        self.mitigation(dp,mitigationtype,Attackeraddress[i],protosrc[j],Attackerport[j])
                                else:
                                    self.mitigation(dp,mitigationtype,Attackeraddress[i],None,None)
                                i += 1
                        elif (len(Victimaddress) != 0):
                            i = j = 0
                            while i < len(Victimaddress):
                                if len(Victimport) != 0:
                                    for j in range(len(Victimport)):
                                        self.mitigation(dp,mitigationtype,Victimaddress[i],protodst[j],Victimport[j])
                                else:
                                    self.mitigation(dp,mitigationtype,Victimaddress[i],None,None)
                                i += 1

    def mitigation(self, datapath, mitigationtype, ipaddress, protocoltype, port):
        ofparser = datapath.ofproto_parser
        port = int(port)
        if (mitigationtype==1): # Mitigation of the Victim's traffic
            if (port!=None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress,ip_proto=protocoltype,tcp_dst=port) 
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress,ip_proto=protocoltype,udp_dst=port) 
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress,ip_proto=in_proto.IPPROTO_TCP,tcp_dst=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                            match=match, actions=actions)      
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress,ip_proto=in_proto.IPPROTO_UDP,udp_dst=port) 
            else:
                if (protocoltype==1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress,ip_proto=protocoltype) 
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=ipaddress)

            actions = []
            self.add_flow(datapath=datapath, priority=100,
                        match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Victim) message sent **\033[0m')
        elif (mitigationtype==2): # Mitigation of the Attacker's traffic
            if (port!=None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress,ip_proto=protocoltype,tcp_src=port) 
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress,ip_proto=protocoltype,udp_src=port) 
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress,ip_proto=in_proto.IPPROTO_TCP,tcp_src=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                        match=match, actions=actions)      
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress,ip_proto=in_proto.IPPROTO_UDP,udp_src=port)            
            else:
                if (protocoltype==1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress,ip_proto=protocoltype) 
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=ipaddress)
            
            actions = []
            self.add_flow(datapath=datapath, priority=100,
                            match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Attacker) message sent **\033[0m')

    def storeInFile(self):
        # Storing the time
        self.Abscisse_time.append(Timewindow*self.timer)
        self.timer += 1
        
        with open('sflow_entropy.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow([self.Abscisse_time[-1],self.Entropy_IPsrc[-1],self.Entropy_IPdst[-1],self.Entropy_Portsrc[-1],self.Entropy_Portdst[-1]])
            csvfile.close()

        with open('sflow_counters.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            for index in self.IPsrc:
                writer.writerow([self.Abscisse_time[-1],index,self.IPsrc[index],None,None,None,None,None,None])
            for index in self.IPdst:
                writer.writerow([self.Abscisse_time[-1],None,None,index,self.IPdst[index],None,None,None,None])
            for index in self.Portsrc:
                writer.writerow([self.Abscisse_time[-1],None,None,None,None,index,self.Portsrc[index],None,None])
            for index in self.Portdst:
                writer.writerow([self.Abscisse_time[-1],None,None,None,None,None,None,index,self.Portdst[index]])
            csvfile.close()

        with open('sflow_counter_ip_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Src"," IP Src ID"," State"])
            positionID = 1
            for index in self.IPsrc:
                writer.writerow([index, positionID, self.IPsrc[index]])
                positionID += 1
            csvfile.close()

        with open('sflow_counter_ip_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Dst"," IP Dst ID"," State"])
            positionID = 1
            for index in self.IPdst:
                writer.writerow([index, positionID, self.IPdst[index]])
                positionID += 1
            csvfile.close()

        with open('sflow_counter_port_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Src"," State"])
            for index in self.Portsrc:
                writer.writerow([index,self.Portsrc[index]])
            csvfile.close()

        with open('sflow_counter_port_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Dst"," State"])
            for index in self.Portdst:
                writer.writerow([index,self.Portdst[index]])
            csvfile.close()

    def printcounters(self):
        # Print the state stats of the dictionaries
        if ((len(self.IPsrc)!= 0) and (len(self.IPdst)!= 0) and (len(self.Portsrc)!= 0) and (len(self.Portdst)!= 0)):
            LOG.info('===========================================')
            for index in self.IPsrc:
                LOG.info('IPsrc= %s \t\tState= %s', index, self.IPsrc[index])
            LOG.info(' ')
            for index in self.IPdst:    
                LOG.info('IPdst= %s \t\tState= %s', index, self.IPdst[index])
            LOG.info(' ')
            for index in self.Portsrc:    
                LOG.info('Portsrc= %s \t\t\tState= %s', index, self.Portsrc[index])
            LOG.info(' ')
            for index in self.Portdst:    
                LOG.info('Portdst= %s \t\t\tState= %s', index, self.Portdst[index])

    def entropy_computation(self):
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

        # self.printcounters()
        LOG.info('===========================================')

        # # Entropy calculation:
        entropy_ip_src = self.entropy(self.IPsrc)
        entropy_ip_dst = self.entropy(self.IPdst)
        entropy_port_src = self.entropy(self.Portsrc)
        entropy_port_dst = self.entropy(self.Portdst)
    
        # # Storing entropies in lists:
        self.Entropy_IPsrc.append(entropy_ip_src)
        self.Entropy_IPdst.append(entropy_ip_dst)
        self.Entropy_Portsrc.append(entropy_port_src)
        self.Entropy_Portdst.append(entropy_port_dst)

        LOG.info('Entropy IP Dst')
        LOG.info(self.Entropy_IPdst)
        # LOG.info('Entropy Port Src')
        # LOG.info(self.Entropy_Portsrc)
        LOG.info('Entropy Port Dst')
        LOG.info(self.Entropy_Portdst)

        # Storing the Counters + Entropies in an output file:
        self.storeInFile()

        # Detection process
        if ((len(self.Entropy_IPsrc) > int(20/Timewindow)) and sum(self.Entropy_IPsrc) > 1): # Wait 20s before starting the detection, we need at least 2 elements in entropy lists
            self.detection()

        # Emptying dictionaries
        self.IPsrc.clear()
        self.IPdst.clear()
        self.Portsrc.clear()
        self.Portdst.clear()
        self.TCPPortsrc.clear()
        self.TCPPortdst.clear()
        self.UDPPortsrc.clear()
        self.UDPPortdst.clear()

    # OF 1.3
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if len(actions) > 0:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match, instructions=inst)
        
        datapath.send_msg(mod)