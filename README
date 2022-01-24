# Netflowlabeler

Netflowlabeler is a python tool to add labels to netflow text files. 
If you have a netflow text file and you want to add labels to it, you can add the lables and conditions to a configuration file and use this tool to assign them.
For now it works only in Zeek conn.log files separated by TABS.
In the future it will include Zeek with JSON and CSV, Argus with CSV and TABS, Nfdump with CSV and Suricata with JSON

## Configuration File of Labels

The conf file syntax is like this:

Background:
    - srcIP=all
Normal:
    - Proto=ARP
    - Proto=IGMP
Botnet-DGA:
    - Proto=UDP & dstPort=53
    - Proto=UDP & srcPort=53
Botnet-CC:
    - srcIP=10.0.0.151 & Proto=TCP
    - dstIP=10.0.0.151 & Proto=TCP

The position is the priority of the rule. First we check the first rule and if it matches then we assign that label. Then we check the second rule, etc.
All the rules below a label are ORed. You can use & to AND different rules.

These are the possible fields that you can use in a configuration file to create the rules used for labeling.
Date , start , Duration , Proto , srcIP , srcPort , dstIP , dstPort , Flags , Tos , Packets , Bytes , Flows
