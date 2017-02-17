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
from ryu.lib.packet import ipv4, tcp, udp
from ryu.lib.packet import ether_types
import sqlite3
import netaddr
import time
import ipaddress

class SwitchMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SwitchMonitor13, self).__init__(*args, **kwargs)
        self.ipv4_flow = {}
        self.table_flow = {}
        self.dbconn = sqlite3.connect("traffic.db")
        self.dbconn.execute('''CREATE TABLE IF NOT EXISTS TRAFFIC
                               (ID     integer primary key autoincrement,
                                SRC    INT    NOT NULL,
                                SPORT  INT    NOT NULL,
                                DST    INT    NOT NULL,
                                DPORT  INT    NOT NULL,
                                SECS   INT    NOT NULL,
                                PKTS   INT    NOT NULL,
                                BYTES  INT    NOT NULL,
                                TIME   INT    NOT NULL);''')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id

        self.ipv4_flow.setdefault(dpid, {})
        self.table_flow.setdefault(dpid, {})

        self.delete_table_flow(datapath, ofproto.OFPTT_ALL)
        self.install_table_flow(datapath, 0)

    def add_flow(self, datapath, priority, match, actions, inst=None,
                 table_id=0, buffer_id=None, idle_timeout=0,
                 hard_timeout=0, flags=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("add flow to %s", table_id)
        if not inst:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, flags=flags,
                                    table_id=table_id, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, flags=flags,
                                    hard_timeout=hard_timeout, table_id=table_id)
        datapath.send_msg(mod)

    def delete_table_flow(self, datapath, table_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        command=ofproto.OFPFC_DELETE
        match = parser.OFPMatch()
        out_port = ofproto.OFPP_ANY
        out_group = ofproto.OFPG_ANY

        mod = parser.OFPFlowMod(datapath, 0, 0, table_id, command,
                                out_port=out_port, out_group=out_group,
                                match=match)
        datapath.send_msg(mod)

    def install_table_flow(self, datapath, table_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        if table_id in self.table_flow[dpid]:
            return

        self.table_flow[dpid][table_id] = table_id

        match = parser.OFPMatch(eth_type=0x0800)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 256)]
        self.add_flow(datapath, 1, match, actions, None, table_id)

        if table_id == 0:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 0, match, actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="255.255.255.255")
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, 20, match, actions)
        else:
            mask = ("0.0.0."+str(table_id), "0.0.0.255")
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=mask)
            inst = [parser.OFPInstructionGotoTable(table_id)]
            self.add_flow(datapath, 10, match, None, inst)

    def add_traffic_flow(self, msg, table_id, ipv4_src, ipv4_dst, port_src, port_dst):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']
        buffer_id = None

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            buffer_id = msg.buffer_id

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 2, match, actions, None, table_id,
                      buffer_id, 60, 600, ofproto.OFPFF_SEND_FLOW_REM)

        if not buffer_id:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

        self.ipv4_flow[dpid][ipv4_src][ipv4_dst] = (port_src, port_dst)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        match = msg.match
        ofproto = datapath.ofproto
        dpid = datapath.id

        ipv4_src = match['ipv4_src']
        ipv4_dst = match['ipv4_dst']
        (port_src, port_dst) = (0, 0)

        if ipv4_src in self.ipv4_flow[dpid] and ipv4_dst in self.ipv4_flow[dpid][ipv4_src]:
            (port_src, port_dst) = self.ipv4_flow[dpid][ipv4_src].pop(ipv4_dst, (0,0))
        self.dbconn.execute("INSERT into TRAFFIC values(NULL,?,?,?,?,?,?,?,?)",
                            (int(netaddr.IPAddress(ipv4_src)), port_src,
                             int(netaddr.IPAddress(ipv4_dst)), port_dst,
                             msg.duration_sec, msg.packet_count,
                             msg.byte_count, int(time.time())))
        self.dbconn.commit()
        self.logger.info("%.15s -> %.15s %4d seconds %4d packets %d bytes",
                         ipv4_src, ipv4_dst, msg.duration_sec,
                         msg.packet_count, msg.byte_count)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore non-ip packet
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
        ipv4_src = ipv4_pkt.src
        ipv4_dst = ipv4_pkt.dst

        self.ipv4_flow[dpid].setdefault(ipv4_src, {})

        (port_src, port_dst) = (0, 0)
        if ipaddress.IPv4Address(ipv4_src).is_private:
            hdr = pkt.get_protocols(tcp.tcp)
            if not hdr:
                hdr = pkt.get_protocols(udp.udp)
            if hdr:
                port_src = hdr[0].src_port
                port_dst = hdr[0].dst_port

        self.logger.info("IPv4 packet in %s %s(%s) %s(%s) %s", dpid, ipv4_src,
                        port_src, ipv4_dst, port_dst, in_port)

        table_id = int(ipv4_src[ipv4_src.rfind(".")+1:]);
        if table_id not in self.table_flow[dpid]:
            self.install_table_flow(datapath, table_id)

        if ipv4_dst not in self.ipv4_flow[dpid][ipv4_src]:
            self.add_traffic_flow(msg, table_id, ipv4_src, ipv4_dst,
                                  port_src, port_dst)
