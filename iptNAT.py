#!/usr/bin/python3.6
##############################################################################################################################
#########                                  WRITE BY A.ANSARI                                                                ##
#########                                                                                                                   ##
##############################################################################################################################
##########Do not change any thing ###########################
####################### discription #################
import sys
import iptc
################################## 1) source ip 2) destionation ip 3) interface 4) snat_ip
source_for_nat = sys.argv[1]
destination_for_nat = sys.argv[2]
Interface = sys.argv[3]
Snat_ip = sys.argv[4]
class pop_table:
    def __init__(self, table_name):
        self.table = iptc.Table(table_name)
        self.chains = dict()

        for i in self.table.chains:
            self.chains[i.name] = iptc.Chain(self.table, i.name)

        self.method = {'append': self.append,
                       'insert': self.insert}

    def append(self, chain, rule):
        tmp = self.chains[chain]
        tmp.append_rule(rule)

    def insert(self, chain, rule):
        tmp = self.chains[chain]
        tmp.insert_rule(rule)


class make_rule(iptc.Rule):
    def __init__(self):
        iptc.Rule.__init__(self)

        self.method={'block': self.block,
                     'snat': self.snat,
                     'allow': self.allow,
                     'i_iface': self.i_iface,
                     'o_iface': self.o_iface,
                     'source': self.source,
                     'destination': self.destination}

    def block(self):
        t = iptc.Target(self, 'REJECT')
        self.target = t

    def snat(self, snat_ip):
        t = iptc.Target(self, 'SNAT')
        t.to_source = snat_ip
        self.target = t

    def allow(self):
        t = iptc.Target(self, 'ACCEPT')
        self.target = t

    def i_iface(self, iface):
        self.in_interface = iface

    def o_iface(self, iface):
        self.out_interface = iface

    def source(self, netaddr):
        self.src = netaddr

    def destination(self, netaddr):
        self.dst = netaddr

class phyawall:
    def __init__(self):
        self.list = []

    def add_rule(self, rule_dict):
        tbl = pop_table(rule_dict['tblchn']['table'])
        chn = rule_dict['tblchn']['chain']
        act = tbl.method[rule_dict['tblchn']['action']]
        tmp = make_rule()

        for i in rule_dict['rule']:
            tmp.method[i](rule_dict['rule'][i])
        act(chn, tmp)

# Testing :: below will go into main app and the variables for change the chain 

phyrule = dict()
phyrule['tblchn'] = dict()
phyrule['tblchn']['table'] = 'nat'
phyrule['tblchn']['chain'] = 'POSTROUTING'
phyrule['tblchn']['action'] = 'insert'
phyrule['rule'] = dict()
phyrule['rule']['o_iface'] = Interface
phyrule['rule']['snat'] = Snat_ip
phyrule['rule']['source'] = source_for_nat
phyrule['rule']['destination'] = destination_for_nat


a = phyawall()
a.add_rule(phyrule)
