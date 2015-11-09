Instructions on how to run the state synchronization tests
####

After executing the tests and incorporating the new functionality, you can safely delete this file, or move it to ryu/app/beba/state_sync/.


State Sync implements five messages from controller to switch
Examples are in ryu/app/beba/state_sync/

To run examples:
-run ryu controller:
 cd <ryu folder>
 PYTHONPATH=. bin/ryu-manager ryu/app/beba/state_sync/<example file> 

  
1.  obtainFlowState.py
    Example how to ask for state of the flow and how to parse the respond

2.  obtainFlowsInState.py
    Example how to ask for flow in the state and how to parse the respond

3.  getGlobalStates.py
    Example how to ask for global state of a switch and how to parse the respond

4.  stateChangeNotifications.py
    Example how to parse state change notification message from switch to controller
    Message contains :
    - table id
    - key
    - new state
    - old state

5.  flowModificationNotifications.py
    Example how to parse state flow notification message from switch to controller
    Message contains:
    - table id 
    - match
    - number of instructions
    - implemented instructions (actions are not sent in the notification)
     

-run mininet:
 sudo mn --topo single,4 --mac --switch user --controller remote

