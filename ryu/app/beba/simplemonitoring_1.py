import logging
import selectivemonitoring_1
import math
import time
import csv
from ryu.lib.packet import ether_types, in_proto
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
import datetime

LOG = logging.getLogger('app.beba.simplemonitoring_1')
Timewindow = 4
Precision = 3 # 1 -> small precision 68% / 2 -> medium precision 95% / 3 -> high precision 99,7%

class SimpleMonitoring(selectivemonitoring_1.BebaSelectiveMonitoring_1):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitoring, self).__init__(*args, **kwargs)
        self.monitor_thread = hub.spawn(self._monitor)
        self.Entropy_IPsrc, self.Entropy_IPdst, self.Entropy_Portsrc, self.Entropy_Portdst, self.Abscisse_time = ([] for i in range(5)) # Entropy Lists
        self.datapaths, self.IPsrc, self.IPdst, self.Portsrc, self.Portdst, self.TCPPortsrc, self.TCPPortdst, self.UDPPortsrc, self.UDPPortdst = ({} for i in range(9)) # Datapath + Features dictionaries
        # External files to store calculated values
        with open('entropy.csv', 'wb') as csvfile: # Set the header and Empty the file
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Time (s)"," IP Src Entropy"," IP Dst Entropy"," Port Src Entropy"," Port Dst Entropy"])
            csvfile.close()
        with open('counters.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Time (s)"," IPsrc"," State"," IPdst"," State"," Portsrc"," State"," Portdst"," State"])
            csvfile.close()
        open('counter_ip_src.csv', 'wb').close()
        open('counter_ip_dst.csv', 'wb').close()
        open('counter_port_src.csv', 'wb').close()
        open('counter_port_dst.csv', 'wb').close()
        self.timer = 1
        self.replies = 0

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
            # Send the states requests to the state tables
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(Timewindow) # Wait X seconds
            self.replies = 0

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

            # Ports
            if (attacktype ==1): # if not a portscan attack or ICMP Flooding
                variance_Portdst = self.variance((self.Portdst).values())
                for index in self.Portdst:
                    if (self.mean((self.Portdst).values())+Precision*(variance_Portdst**0.5) < self.Portdst[index]):
                        Victimport.append(index)
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
                LOG.info('\033[93m** Victim Host: %s **\033[0m', ip)
            for port in Victimport:
                LOG.info('\033[93m** Victim Portdst: %s **\033[0m', port)    

            # Attackers information:
            variance_IPsrc = self.variance((self.IPsrc).values())
            for index in self.IPsrc: # Store the IP values that are greater than the mean+sigma limit  
                if (self.mean((self.IPsrc).values())+Precision*(variance_IPsrc**0.5) < self.IPsrc[index]):
                    Attackeraddress.append(index)
            if (len(Attackeraddress)!=0):
                mitigationtype = 2

            # Spoofed Ports Src ? and NOT AN ICMP FLOODING ATTACK
            # if (((self.Entropy_Portsrc[-2]-self.Entropy_Portsrc[-1])<0) and (attacktype != 3 and attacktype != 4)):
            #     LOG.info('\033[91m** SPOOFED Port Src **\033[0m')
            if (attacktype != 3 and attacktype!=4):
                variance_Portsrc = self.variance((self.Portsrc).values())
                for index in self.Portsrc: # Store the Port values that are greater than the mean+sigma limit
                    if (self.mean((self.Portsrc).values())+Precision*(variance_Portsrc**0.5) < self.Portsrc[index]):
                        Attackerport.append(index)
                # Protocols <-> Ports
                for port in Attackerport: # For each port store also the protocol type (needed to send the OF rule)
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
            self.add_flow(datapath=datapath, table_id=0, priority=100,
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
            self.add_flow(datapath=datapath, table_id=0, priority=100,
                            match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Attacker) message sent **\033[0m')

    def _request_stats(self, datapath):
        for table in range(6):
            req = bebaparser.OFPExpStateStatsMultipartRequestAndDelete(datapath, table_id=table)
            datapath.send_msg(req)

    def convertPort2Int(self, keys):
        Portint = 0
        for index in range(len(keys)):
            Portint += keys[index] * math.pow(256,index)
        return int(Portint)

    def storeInFile(self):
        # Storing the time
        self.Abscisse_time.append(Timewindow*self.timer)
        self.timer += 1
        
        with open('entropy.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow([self.Abscisse_time[-1],self.Entropy_IPsrc[-1],self.Entropy_IPdst[-1],self.Entropy_Portsrc[-1],self.Entropy_Portdst[-1]])
            csvfile.close()

        with open('counters.csv', 'ab') as csvfile:
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

        with open('counter_ip_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Src"," IP Src ID"," State"])
            positionID = 1
            for index in self.IPsrc:
                writer.writerow([index, positionID, self.IPsrc[index]])
                positionID += 1
            csvfile.close()

        with open('counter_ip_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Dst"," IP Dst ID"," State"])
            positionID = 1
            for index in self.IPdst:
                writer.writerow([index, positionID, self.IPdst[index]])
                positionID += 1
            csvfile.close()

        with open('counter_port_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile,delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Src"," State"])
            for index in self.Portsrc:
                writer.writerow([index,self.Portsrc[index]])
            csvfile.close()

        with open('counter_port_dst.csv', 'wb') as csvfile:
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
                LOG.info('Portsrc= %d \t\t\tState= %s', index, self.Portsrc[index])
            LOG.info(' ')
            for index in self.Portdst:    
                LOG.info('Portdst= %d \t\t\tState= %s', index, self.Portdst[index])
        # State Stats General Parser:
        """ LOG.info('Length=%s Table ID=%s Duration_sec=%s Duration_nsec=%s Field_count=%s\n'
            'Keys:%s State=%s\n'
            'Hard_rollback=%s Idle_rollback=%s Hard_timeout=%s Idle_timeout=%s',
            str(state_stats_list[index].length), str(state_stats_list[index].table_id), str(state_stats_list[index].dur_sec), str(state_stats_list[index].dur_nsec), str(state_stats_list[index].field_count),
            bebaparser.state_entry_key_to_str(state_stats_list[index].fields, state_stats_list[index].entry.key, state_stats_list[index].entry.key_count), str(state_stats_list[index].entry.state),
            str(state_stats_list[index].hard_rb), str(state_stats_list[index].idle_rb), str(state_stats_list[index].hard_to), str(state_stats_list[index].idle_to))
            LOG.info('*************************************************************') """

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
        
        # Entropy calculation:
        entropy_ip_src = self.entropy(self.IPsrc)
        entropy_ip_dst = self.entropy(self.IPdst)
        entropy_port_src = self.entropy(self.Portsrc)
        entropy_port_dst = self.entropy(self.Portdst)
    
        # Storing entropies in lists:
        self.Entropy_IPsrc.append(entropy_ip_src)
        self.Entropy_IPdst.append(entropy_ip_dst)
        self.Entropy_Portsrc.append(entropy_port_src)
        self.Entropy_Portdst.append(entropy_port_dst)

        # Storing the Counters + Entropies in an output file:
        self.storeInFile()

        # print self.Entropy_IPdst
        # print self.Entropy_IPsrc
        # print self.Entropy_Portsrc
        # print self.Entropy_Portdst
        
        # Printing the entropies:
        # LOG.info('Entropy IP Src')
        # LOG.info(self.Entropy_IPsrc)
        LOG.info('Entropy IP Dst')
        LOG.info(self.Entropy_IPdst)
        # LOG.info('Entropy Port Src')
        # LOG.info(self.Entropy_Portsrc)
        LOG.info('Entropy Port Dst')
        LOG.info(self.Entropy_Portdst)

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

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # Retreive and store states stats information 
        if (msg.body.experimenter == 0XBEBABEBA):
          if(msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE):
            data = msg.body.data
            state_stats_list = bebaparser.OFPStateStats.parser(data,0)
            if (state_stats_list!=0):
                self.replies += 1
                for index in range(len(state_stats_list)):
                    if (state_stats_list[index].entry.state != 0):
                        
                        if (int(state_stats_list[index].table_id) == 0): # IP src dictionary
                            self.IPsrc[(str(state_stats_list[index].entry.key)[1:-1]).replace(", ",".")] = state_stats_list[index].entry.state
                        
                        elif (int(state_stats_list[index].table_id) == 1): # IP dst dictionary
                            self.IPdst[(str(state_stats_list[index].entry.key)[1:-1]).replace(", ",".")] = state_stats_list[index].entry.state
                        
                        elif (int(state_stats_list[index].table_id) == 2): # TCP Port src + Port src dictionaries
                            portsrc = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.Portsrc[portsrc] = state_stats_list[index].entry.state
                            self.TCPPortsrc[portsrc] = state_stats_list[index].entry.state
                       
                        elif (int(state_stats_list[index].table_id) == 3): # TCP Port dst + Port dst dictionaries
                            portdst = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.Portdst[portdst] = state_stats_list[index].entry.state
                            self.TCPPortdst[portdst] = state_stats_list[index].entry.state
                        
                        elif (int(state_stats_list[index].table_id) == 4): # UDP Port src dictionary
                            portsrc = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.UDPPortsrc[portsrc] = state_stats_list[index].entry.state
                       
                        elif (int(state_stats_list[index].table_id) == 5): # UDP Port dst dictionary
                            portdst = self.convertPort2Int(state_stats_list[index].entry.key)
                            self.UDPPortdst[portdst] = state_stats_list[index].entry.state
            else:
              LOG.info("No data")
        if (self.replies == 6): # If we have all the replies
            if (len(self.IPsrc)!=0): # if counters are != 0
                self.entropy_computation()