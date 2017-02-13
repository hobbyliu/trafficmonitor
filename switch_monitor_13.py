# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types


class SwitchMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchMonitor13, self).__init__(*args, **kwargs)
        self.ip_to_table = {}
        self.flow_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 256)]
        self.add_flow(datapath, 1, match, actions)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 0, match, actions)

    def add_monitor_flow(self, datapath, ipv4):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        table_id = int(ipv4[ipv4.rfind(".")+1:]);
        if table_id == 0 or table_id == 255:
            table_id = 1

        self.logger.info("add monitor flow to table %d", table_id)

        inst = [parser.OFPInstructionGotoTable(table_id)]
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ipv4)
        self.add_flow(datapath, 2, match, None, None, 0, inst)

        self.ip_to_table[dpid][ipv4] = table_id

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0, inst=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("add flow")
        if not inst:
        	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
            	                                 actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    table_id=table_id, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    table_id=table_id)
        datapath.send_msg(mod)

    def packet_flood(self, datapath, msg):
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def add_traffic_flow(self, datapath, ipv4_src, ipv4_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        table_id = self.ip_to_table[dpid][ipv4_src]
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 2, match, actions, None, table_id)

        self.flow_table[dpid][ipv4_src][ipv4_dst] = table_id

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

        # ignore non-ip packet
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        ipv4_src = ip_pkt.src
        ipv4_dst = ip_pkt.dst

        dpid = datapath.id
        self.ip_to_table.setdefault(dpid, {})
        self.flow_table.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, ipv4_src, ipv4_dst, in_port)

        if ipv4_src not in self.ip_to_table[dpid]:
            self.add_monitor_flow(datapath, ipv4_src)

        self.flow_table[dpid].setdefault(ipv4_src, {})
        if ipv4_dst not in self.flow_table[dpid][ipv4_src]:
            self.add_traffic_flow(datapath, ipv4_src, ipv4_dst)

        self.packet_flood(datapath, msg)