#!/usr/bin/python3.6
##############################################################################################################################
#########                                  WRITE BY A.ANSARI                                                                ##
#########                                                                                                                   ##
##############################################################################################################################
##########Do not change any thing ###########################
import iptc
import sys
############################################Discription###################################
# This the input parameter  1#Ch:input/output  2#Po:tcp/udp/all  3#: interface/all 4#S:ip/subnet or all 5#D:ip/subnet or all 6# source range ip 7# destination range ip 6#SP:portnumber/all 7#DP:portnumber/all 8#ACCEPT/DROP
if len(sys.argv) > 11:
    print('You have specified too many arguments')
    sys.exit()

if len(sys.argv) < 11:
    print('You need to specify the path to be listed')
    sys.exit()

Chain = sys.argv[1]
protocol = sys.argv[2]
interface = sys.argv[3]
source = sys.argv[4]
destination = sys.argv[5]
source_Range = sys.argv[6]
destination_Range = sys.argv[7]
source_port = sys.argv[8]
destination_port = sys.argv[9]
targets = sys.argv[10]
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
   rule.protocol = protocol
   match = iptc.Match(rule, protocol)
   match.sport = source_port
   match.dport = destination_port
   rule.add_match(match)
   match = iptc.Match(rule, "iprange")
   match.src_range = source_Range
   match.dst_range = destination_Range
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

drop()
#allowLoopback()
#allowEstablished()

#print (sys.argv[1])
#print (sys.argv[2])
