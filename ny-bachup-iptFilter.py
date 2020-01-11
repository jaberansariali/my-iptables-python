#!/usr/bin/python3.6
##############################################################################################################################
#########                                  WRITE BY A.ANSARI                                                                ##
#########                                                                                                                   ##
##############################################################################################################################
##########Do not change any thing ###########################
import iptc
import sys
import os 
############################################Discription###################################
# This the input parameter  1#Ch:input/output  2#Po:tcp/udp/all  3#: interface/all 4#S:ip/subnet or all 5#D:ip/subnet or all 6#SP:portnumber/all 7#DP:portnumber/all 8#ACCEPT/DROP/REJECT
if len(sys.argv) > 9:
    print('You have specified too many arguments')
    sys.exit()

if len(sys.argv) < 9:
    print('You need to specify the path to be listed')
    sys.exit()

Chain = sys.argv[1]
protocol = sys.argv[2]
interface = sys.argv[3]
source = sys.argv[4]
destination = sys.argv[5]
source_port = sys.argv[6]
destination_port = sys.argv[7]
targets = sys.argv[8]
if Chain == "input":
   Chain = "INPUT"
elif Chain == "output":
   Chain = "OUTPUT"
else:
    Chain = sys.argv[1]


#print(len(sys.argv))
def drop():
   # chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), Chain)
   # rule = iptc.Rule()
   # rule.protocol = protocol
   # rule.in_interface = interface
   # rule.add_match(match)
   # match = iptc.Match(rule, "iprange")
   # match.src_range = "192.168.1.100-192.168.1.200"
   # match.dst_range = "172.22.33.106"
   # rule.add_match(match)
   # target = iptc.Target(rule, targets)
   # rule.target = target
   # chain.insert_rule(rule)
   rule = iptc.Rule()
#   if protocol == "tcp" or protocol == "udp" :
   rule.protocol = protocol
   match = iptc.Match(rule, protocol)
#   elif protocl == "all" or protocol == "ALL":
#      os.system("date")
   match.sport = source_port
   match.dport = destination_port
   rule.add_match(match)
   rule.src = source
   rule.dst = destination
   rule.add_match(match)
   rule.target = iptc.Target(rule, targets)
   chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), Chain)
   chain.insert_rule(rule)


def allowLoopback():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "lo"
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target
    chain.insert_rule(rule)

def allowEstablished():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT')
    rule = iptc.Rule()
    match = rule.create_match('state')
    match.state = "RELATED,ESTABLISHED"
    rule.target = iptc.Target(rule, 'ACCEPT')
    chain.insert_rule(rule)

def static_iptables():
     all_condition = [protocol,  source,  destination,  source_port,  destination_port]
#    for X in all_condition:
     if protocol == "all":
         X_protocol = ""
         IPTABLES_final = "iptables -t filter -I " + Chain + "  " + X_protocol
     else:
         IPTABLES_final = "iptables -t filter -I " + Chain + " " + "-p " + protocol

     if source == "all":
         X_source = ""
         IPTABLES_final +=  "  " + X_source
     else:
         IPTABLES_final += " " + "-s " + source

     if destination == "all":
         X_destination = "" 
         IPTABLES_final += "  " + X_destination
     else:
         IPTABLES_final += " " + "-d " + destination

     if source_port == "all":
         X_source_port = ""
         IPTABLES_final += "" + X_source_port
     else:
         IPTABLES_final += " " + " --sport "  + source_port

     if destination_port == "all":
         X_destination_port = ""
         IPTABLES_final += " " + X_destination_port
     else:
         IPTABLES_final += " " + " --dport " + destination_port
    
     IPTABLES_final += " -j " + targets
     print (IPTABLES_final)
#     os.system (IPTABLES_final)


           
#            Y = "iptables -t filter -I {} -p {} -s {} -d {} --sport {} --dport {} -j {}"
#            IPTABLES_final = "iptables -t filter" + " " + "-I" 

#        print (X)
if protocol == "all" or  source == "all" or  destination == "all" or  source_port == "all" or  destination_port == "all": 
   IPTABLES_sample = "iptables -t filter -I {} -p {} -s {} -d {} --sport {} --dport {} -j {}"
   IPTABLES_1 = IPTABLES_sample.format(Chain, protocol, source, destination, source_port, destination_port, targets)
#   print (IPTABLES_1)
   static_iptables()

else: 
    drop()

#drop()

#allowLoopback()
#allowEstablished()

#print (sys.argv[1])
#print (sys.argv[2])
