BEBA APP Descriptions:
----------------------

-    nativeMonitoring.py implements:
        
	MAC learning and ARP forwarding
        IP forwarding: rules inserted for each couple IP src/dst
        monitoring: every <timeInterval>, a FlowStatsReq is sent to the switch for collecting flows' counters

-    selectivemonitoring_1.py implements:
    
        Switch flow tables configuration for MAC learning/ARP forwarding
        Counters for four features: -IP Src/Dst and Port Src/Dst

-    simplemonitoring_1.py implements:
        
	Inherit from selectivemonitoring
        Sends requests and receives replies from the switch to get counter values of the features monitored
        Every N seconds (Timewindow) process these counter values into an DDoS entropy-based algorithm in order to detect specific attacks
        If an attack is detected sends flow rules to the switch for the attack mitigation

-   simplemonitor.py implements:

        Switch flow tables configuration for MAC learning/ARP forwarding
        Combined with an sFlow Agent and Collector
        Receives samples send by the Agent to the Collector, and parse them to retrieve counters information for the -IP Src/Dst and Port Src/Dst
        Every N seconds (Timewindow) process these counter values into an DDoS entropy-based algorithm in order to detect specific attacks
        If an attack is detected sends flow rules to the switch for the attack mitigation

-   selectivemonitoring.py (same as selectivemonitoring_1.py but for only one feature)

-   simplemonitoring.py (same as seimplemonitoring_1.py but for only one feature)
