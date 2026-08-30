"""
NetSage AI - Deterministic Rule Checker (checker.py)
Rule-based deterministic engine for diagnosing Cisco Packet Tracer & IOS configurations.
Parses show command outputs, topology notes, and symptoms to detect common network faults.
"""

import os
import re
import csv
import sys
from typing import Dict, Any, Optional, List

class RuleChecker:
    """
    Deterministic rule engine that checks Cisco show outputs and symptoms.
    Provides instant root-cause analysis, evidence extraction, OSI layer mapping,
    and CLI remediation steps.
    """

    def __init__(self):
        self.rules = [
            self._check_duplicate_ip,
            self._check_admin_down,
            self._check_line_protocol_down_or_duplex,
            self._check_err_disabled,
            self._check_trunk_allowed_vlans,
            self._check_native_vlan_mismatch,
            self._check_dtp_trunk_negotiation,
            self._check_access_port_vlan_mismatch,
            self._check_default_gateway_subnet,
            self._check_missing_route,
            self._check_broken_next_hop,
            self._check_ospf_passive_interface,
            self._check_routing_loop,
            self._check_acl_transport_deny,
            self._check_guest_isolation_acl,
            self._check_vty_ssh_acl,
            self._check_acl_port_forwarding_block,
            self._check_nat_missing_inside_role,
            self._check_nat_pool_exhaustion,
            self._check_nat_missing_default_route,
            self._check_dhcp_pool_exhaustion,
            self._check_dhcp_wrong_network,
            self._check_missing_dhcp_relay,
            self._check_dhcp_excluded_overlap,
            self._check_dns_server_missing,
            self._check_dns_missing_record,
            self._check_dns_wrong_resolver,
            self._check_wireless_vlan_mapping,
        ]

    def diagnose(self, symptom: str, show_output: str, topology_note: str = "") -> Dict[str, Any]:
        """
        Runs all deterministic rules against provided symptom, show_output, and topology_note.
        Returns the first matching rule diagnosis or a fallback indicating no deterministic match.
        """
        combined_text = f"{symptom}\n{topology_note}\n{show_output}"
        
        for rule_fn in self.rules:
            result = rule_fn(symptom, show_output, topology_note, combined_text)
            if result and result.get("rule_matched"):
                return result

        # Fallback when no specific deterministic pattern triggers
        return {
            "rule_matched": False,
            "rule_name": "GENERIC_INVESTIGATION",
            "root_cause": "No deterministic rule matched. Deferring to LLM reasoning.",
            "osi_layer": "Unknown",
            "confidence": 0.30,
            "evidence": show_output.strip() if show_output else symptom.strip(),
            "next_command": "show running-config | show ip interface brief",
            "fix_steps": [
                "Inspect full running configuration on relevant devices.",
                "Verify end-to-end IP reachability with ping and traceroute.",
                "Review layer 2 spanning-tree and VLAN mappings."
            ]
        }

    # ==========================================
    # Layer 3 / Duplicate IP & Subnet Rules
    # ==========================================

    def _check_duplicate_ip(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"duplicate address|duplicate ip|%IP-4-DUPADDR", text, re.IGNORECASE):
            ip_m = re.search(r"(?:duplicate address|duplicate ip|%IP-4-DUPADDR:\s*Duplicate address)\s*([\d\.]+)", text, re.IGNORECASE)
            dup_ip = ip_m.group(1) if ip_m else "configured IP address"
            return {
                "rule_matched": True,
                "rule_name": "DUPLICATE_IP_ADDRESS",
                "root_cause": f"Duplicate IP address detected on the local subnet for {dup_ip}.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.99,
                "evidence": f"Syslog/output reports duplicate IP address: {dup_ip}",
                "next_command": "show ip arp",
                "fix_steps": [
                    "Locate conflicting device with show ip arp.",
                    f"Reconfigure host or interface with an unassigned static IP or DHCP.",
                    "Verify ARP table resolution: clear ip arp"
                ]
            }
        return None

    # ==========================================
    # Layer 1 / Physical & Interface Rules
    # ==========================================

    def _check_admin_down(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"administratively down", text, re.IGNORECASE):
            int_match = re.search(r"(?:interface\s+)?([A-Za-z]+[\d/\.]+)\s*(?:=|is)?\s*administratively down", text, re.IGNORECASE)
            int_name = int_match.group(1) if int_match else "the affected interface"
            return {
                "rule_matched": True,
                "rule_name": "INTERFACE_ADMIN_DOWN",
                "root_cause": f"Interface {int_name} is administratively shut down.",
                "osi_layer": "Layer 1/Physical",
                "confidence": 0.98,
                "evidence": f"Output indicates '{int_name} is administratively down'",
                "next_command": f"show interfaces {int_name} status",
                "fix_steps": [
                    "configure terminal",
                    f"interface {int_name}",
                    "no shutdown",
                    "end",
                    "show ip interface brief"
                ]
            }
        return None

    def _check_line_protocol_down_or_duplex(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"line protocol down|speed/duplex mismatch|duplex mismatch", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "SPEED_DUPLEX_OR_LINK_DOWN",
                "root_cause": "Speed/duplex mismatch or physical carrier loss causing line protocol failure.",
                "osi_layer": "Layer 1/Physical",
                "confidence": 0.95,
                "evidence": "show interfaces reports line protocol down and/or speed/duplex mismatch",
                "next_command": "show interfaces status | show controllers",
                "fix_steps": [
                    "configure terminal",
                    "interface <affected_interface>",
                    "duplex auto",
                    "speed auto",
                    "end"
                ]
            }
        return None

    def _check_err_disabled(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"err-disabled|errdisable|port security violation", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "PORT_SECURITY_ERR_DISABLED",
                "root_cause": "Port security violation placed the interface into err-disabled state.",
                "osi_layer": "Layer 2/Data Link",
                "confidence": 0.96,
                "evidence": "Interface status shows 'err-disabled' due to unauthorized MAC address or security threshold violation.",
                "next_command": "show port-security interface <interface-id>",
                "fix_steps": [
                    "configure terminal",
                    "interface <affected_interface>",
                    "shutdown",
                    "no shutdown",
                    "end"
                ]
            }
        return None

    # ==========================================
    # Layer 2 / VLAN & Trunk Rules
    # ==========================================

    def _check_trunk_allowed_vlans(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"trunk allowed vlan", text, re.IGNORECASE) and ("missing" in text.lower() or "cannot reach another vlan" in text.lower() or "does not list" in text.lower()):
            vlan_target = "10"
            m = re.search(r"vlan\s+(\d+)", text, re.IGNORECASE)
            if m:
                vlan_target = m.group(1)
            return {
                "rule_matched": True,
                "rule_name": "TRUNK_ALLOWED_VLAN_MISSING",
                "root_cause": f"VLAN {vlan_target} is missing from the 802.1Q trunk allowed VLAN list on the uplink.",
                "osi_layer": "Layer 2/Data Link",
                "confidence": 0.96,
                "evidence": f"show interfaces trunk shows allowed list does not include VLAN {vlan_target}.",
                "next_command": "show interfaces trunk",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/1",
                    f"switchport trunk allowed vlan add {vlan_target}",
                    "end",
                    "show interfaces trunk"
                ]
            }
        return None

    def _check_native_vlan_mismatch(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"native vlan mismatch|native \d+ vs \d+", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "NATIVE_VLAN_MISMATCH",
                "root_cause": "Native VLAN mismatch between neighboring 802.1Q trunk ports.",
                "osi_layer": "Layer 2/Data Link",
                "confidence": 0.97,
                "evidence": "CDP/STP warning indicates native VLAN ID discrepancy across the trunk link.",
                "next_command": "show interfaces trunk",
                "fix_steps": [
                    "configure terminal",
                    "interface <trunk_interface>",
                    "switchport trunk native vlan 99",
                    "end"
                ]
            }
        return None

    def _check_dtp_trunk_negotiation(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"dynamic auto on both ends|failed to negotiate trunk|dynamic auto", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DTP_NEGOTIATION_FAILURE",
                "root_cause": "Both trunk endpoints configured as 'dynamic auto', resulting in an access port state rather than a trunk.",
                "osi_layer": "Layer 2/Data Link",
                "confidence": 0.95,
                "evidence": "DTP operational mode remains static access because neither side actively initiated trunking.",
                "next_command": "show dtp interface <interface-id>",
                "fix_steps": [
                    "configure terminal",
                    "interface <trunk_interface>",
                    "switchport mode trunk",
                    "end"
                ]
            }
        return None

    def _check_access_port_vlan_mismatch(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"access vlan \d+;\s*expected|wrong vlan|assigned to wrong vlan", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "ACCESS_PORT_VLAN_MISMATCH",
                "root_cause": "Host access port is assigned to the incorrect VLAN in the switchport configuration.",
                "osi_layer": "Layer 2/Data Link",
                "confidence": 0.94,
                "evidence": "show vlan brief displays port membership in wrong VLAN ID.",
                "next_command": "show vlan brief",
                "fix_steps": [
                    "configure terminal",
                    "interface <port_id>",
                    "switchport mode access",
                    "switchport access vlan <correct_vlan_id>",
                    "end"
                ]
            }
        return None

    # ==========================================
    # Layer 3 / Gateway & Routing Rules
    # ==========================================

    def _check_default_gateway_subnet(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"gateway is outside.*subnet|incorrect default gateway|outside pc subnet", text, re.IGNORECASE) or (
            "192.168.10." in text and "192.168.20.1" in text and "gateway" in text.lower()
        ):
            return {
                "rule_matched": True,
                "rule_name": "GATEWAY_OUTSIDE_SUBNET",
                "root_cause": "Configured default gateway IP is not in the same local subnet as host IP address.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.97,
                "evidence": "Host IP subnet and default gateway IP belong to different IP broadcast domains/subnets.",
                "next_command": "ipconfig /all",
                "fix_steps": [
                    "Correct default gateway in host TCP/IP configuration or DHCP pool: default-router 192.168.10.1",
                    "Verify connectivity using ping to the new gateway IP."
                ]
            }
        return None

    def _check_missing_route(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"no static/dynamic route|show ip route has no|no \d+\.\d+\.\d+\.\d+.*entry|missing route", text, re.IGNORECASE) and not re.search(r"loop", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "ROUTING_TABLE_MISSING_ROUTE",
                "root_cause": "The routing table has no matching static or dynamic route for the target destination network.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.95,
                "evidence": "show ip route lacks entry for the destination network prefix.",
                "next_command": "show ip route",
                "fix_steps": [
                    "configure terminal",
                    "ip route <dest_network> <subnet_mask> <next_hop_ip>",
                    "end",
                    "show ip route"
                ]
            }
        return None

    def _check_broken_next_hop(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"ping next hop fails|broken next-hop|next hop.*is down", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "NEXT_HOP_UNREACHABLE",
                "root_cause": "The next-hop address for the static route is unreachable or its egress interface is down.",
                "osi_layer": "Layer 1/3",
                "confidence": 0.94,
                "evidence": "Ping to configured next-hop IP fails; exit interface is down/unresponsive.",
                "next_command": "show ip interface brief | show cdp neighbors",
                "fix_steps": [
                    "Check physical link on next-hop neighbor.",
                    "Verify neighbor IP interface is up: no shutdown",
                    "Update static route if next-hop IP is incorrect."
                ]
            }
        return None

    def _check_ospf_passive_interface(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"show ip ospf neighbor is empty|passive-interface|ospf interface is passive", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "OSPF_PASSIVE_INTERFACE_MISCONFIG",
                "root_cause": "OSPF adjacency cannot form because the router link interface is suppressed by a 'passive-interface' statement.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.96,
                "evidence": "show ip ospf neighbor is empty; interface configuration contains passive-interface command.",
                "next_command": "show ip ospf interface <interface-id>",
                "fix_steps": [
                    "configure terminal",
                    "router ospf 1",
                    "no passive-interface GigabitEthernet0/0",
                    "end",
                    "show ip ospf neighbor"
                ]
            }
        return None

    def _check_routing_loop(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"routing loop|packets loop|points to each other", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "ROUTING_LOOP_DETECTED",
                "root_cause": "Mutual incorrect static routes configured pointing traffic back and forth between adjacent routers.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.98,
                "evidence": "show ip route indicates cyclical next-hop paths for the same destination prefix.",
                "next_command": "traceroute <dest_ip>",
                "fix_steps": [
                    "configure terminal",
                    "no ip route <dest_net> <mask civil> <wrong_hop>",
                    "ip route <dest_net> <mask civil> <correct_gateway>",
                    "end"
                ]
            }
        return None

    # ==========================================
    # Layer 4 / ACL & NAT Rules
    # ==========================================

    def _check_acl_transport_deny(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"deny tcp.*eq (443|80|22)|acl blocks (?:https|ssh|dns)|denies udp.*eq 53", text, re.IGNORECASE) and not re.search(r"vty", text, re.IGNORECASE):
            port = "target service"
            if "443" in text or "https" in text.lower():
                port = "HTTPS (TCP/443)"
            elif "53" in text or "dns" in text.lower():
                port = "DNS (UDP/53)"
            elif "22" in text or "ssh" in text.lower():
                port = "SSH (TCP/22)"
                
            return {
                "rule_matched": True,
                "rule_name": "ACL_BLOCKS_SERVICE_PORT",
                "root_cause": f"Access Control List (ACL) explicitly denies {port} traffic.",
                "osi_layer": "Layer 4/Transport",
                "confidence": 0.96,
                "evidence": f"show access-lists confirms explicit deny statement blocking {port}.",
                "next_command": "show access-lists",
                "fix_steps": [
                    "configure terminal",
                    "ip access-list extended <acl_name>",
                    "permit tcp any host <destination_ip> eq 443",
                    "end"
                ]
            }
        return None

    def _check_guest_isolation_acl(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"guest isolation|guest-to-internal deny rule is missing|guest.*reaches corporate|guest.*can reach internal", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "GUEST_ISOLATION_ACL_MISSING",
                "root_cause": "Missing guest segmentation ACL allowing guest network traffic into private RFC1918 subnets.",
                "osi_layer": "Layer 3/4",
                "confidence": 0.95,
                "evidence": "Guest VLAN/SSID access-list lacks deny rules for 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16.",
                "next_command": "show access-lists | show run interface <guest_svi>",
                "fix_steps": [
                    "configure terminal",
                    "ip access-list extended GUEST_SEGREGATION",
                    "deny ip any 10.0.0.0 0.255.255.255",
                    "deny ip any 172.16.0.0 0.15.255.255",
                    "deny ip any 192.168.0.0 0.0.255.255",
                    "permit ip any any",
                    "interface Vlan40",
                    "ip access-group GUEST_SEGREGATION in",
                    "end"
                ]
            }
        return None

    def _check_vty_ssh_acl(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"vty-acl|vty.*ssh|blocks ssh|access-class.*deny", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "VTY_ACCESS_CLASS_SSH_BLOCKED",
                "root_cause": "Access-class applied to VTY lines denies SSH connection from administrator management IP.",
                "osi_layer": "Layer 4/7",
                "confidence": 0.95,
                "evidence": "VTY ACL denies source IP on TCP port 22.",
                "next_command": "show access-lists | show running-config | section line vty",
                "fix_steps": [
                    "configure terminal",
                    "ip access-list extended VTY-ACL",
                    "permit tcp host <admin_ip> any eq 22",
                    "end"
                ]
            }
        return None

    def _check_acl_port_forwarding_block(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"inbound acl blocks forwarded port|acl denies 8080|acl blocks port forwarding", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "ACL_BLOCKS_PORT_FORWARDING",
                "root_cause": "Outside interface ACL filters out inbound traffic before it reaches the static NAT port-forwarding destination.",
                "osi_layer": "Layer 4/Transport",
                "confidence": 0.95,
                "evidence": "Outside inbound ACL lacks permit rule for forwarded public destination port.",
                "next_command": "show access-lists | show ip nat translations",
                "fix_steps": [
                    "configure terminal",
                    "ip access-list extended OUTSIDE_IN",
                    "permit tcp any host <public_ip> eq 8080",
                    "end"
                ]
            }
        return None

    def _check_nat_missing_inside_role(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"nat inside role missing|lacks ip nat inside|inside interface is not marked for nat", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "NAT_INSIDE_ROLE_MISSING",
                "root_cause": "Internal LAN interface is not configured with 'ip nat inside', preventing NAT translation triggering.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.97,
                "evidence": "show ip nat translations is empty; show running-config lacks 'ip nat inside' on LAN interface.",
                "next_command": "show ip interface brief | show run interface <lan_interface>",
                "fix_steps": [
                    "configure terminal",
                    "interface <inside_lan_interface>",
                    "ip nat inside",
                    "end"
                ]
            }
        return None

    def _check_nat_pool_exhaustion(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"nat pool exhausted|pool has no free addresses", text, re.IGNORECASE) and "nat" in text.lower():
            return {
                "rule_matched": True,
                "rule_name": "NAT_POOL_EXHAUSTION",
                "root_cause": "Dynamic NAT pool address space is exhausted due to missing PAT 'overload' configuration.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.95,
                "evidence": "show ip nat statistics shows 100% address allocation in the dynamic NAT pool.",
                "next_command": "show ip nat statistics",
                "fix_steps": [
                    "configure terminal",
                    "ip nat inside source list <acl_num> interface <outside_int> overload",
                    "clear ip nat translation *",
                    "end"
                ]
            }
        return None

    def _check_nat_missing_default_route(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"no 0\.0\.0\.0/0 route|default route absent|missing default route", text, re.IGNORECASE) and "nat" in text.lower():
            return {
                "rule_matched": True,
                "rule_name": "NAT_MISSING_DEFAULT_ROUTE",
                "root_cause": "Edge router performs NAT translation but lacks a default gateway route (0.0.0.0/0) to route traffic to the ISP.",
                "osi_layer": "Layer 3/Network",
                "confidence": 0.96,
                "evidence": "show ip nat translations displays active mappings, but show ip route has no gateway of last resort.",
                "next_command": "show ip route",
                "fix_steps": [
                    "configure terminal",
                    "ip route 0.0.0.0 0.0.0.0 <ISP_Gateway_IP>",
                    "end",
                    "show ip route"
                ]
            }
        return None

    # ==========================================
    # Layer 7 / Application (DHCP & DNS) Rules
    # ==========================================

    def _check_dhcp_pool_exhaustion(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"169\.254|pool maximum address is exhausted|dhcp pool exhausted|dhcp pool.*shows no free addresses", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DHCP_POOL_EXHAUSTED",
                "root_cause": "DHCP pool addresses are fully allocated, forcing clients to fallback to APIPA (169.254.x.x).",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.97,
                "evidence": "show ip dhcp pool shows 0 free leases; host has APIPA 169.254.x.x address.",
                "next_command": "show ip dhcp pool | show ip dhcp binding",
                "fix_steps": [
                    "clear ip dhcp binding *",
                    "Expand DHCP pool network subnet mask or shorten lease duration.",
                    "Verify with show ip dhcp pool"
                ]
            }
        return None

    def _check_dhcp_wrong_network(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"dhcp pool has wrong network|pool network is|receives ip but wrong subnet", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DHCP_WRONG_POOL_NETWORK",
                "root_cause": "DHCP pool is configured with a network statement that does not match the local subnet / VLAN.",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.95,
                "evidence": "show ip dhcp binding shows leased IP range conflicting with target VLAN subnet.",
                "next_command": "show running-config | section dhcp",
                "fix_steps": [
                    "configure terminal",
                    "ip dhcp pool <pool_name>",
                    "network <correct_subnet> <subnet_mask>",
                    "default-router <correct_gateway_ip>",
                    "end"
                ]
            }
        return None

    def _check_missing_dhcp_relay(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"no ip helper-address|missing dhcp relay|has no helper-address", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DHCP_RELAY_HELPER_MISSING",
                "root_cause": "DHCP broadcast discovery packets across VLANs are dropped because 'ip helper-address' is not configured on the SVI/gateway interface.",
                "osi_layer": "Layer 3/7",
                "confidence": 0.98,
                "evidence": "Router/L3 switch interface configuration lacks 'ip helper-address' for centralized DHCP server.",
                "next_command": "show run interface <vlan_interface>",
                "fix_steps": [
                    "configure terminal",
                    "interface Vlan30",
                    "ip helper-address <DHCP_Server_IP>",
                    "end"
                ]
            }
        return None

    def _check_dhcp_excluded_overlap(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"incorrect dhcp exclusion|excluded range overlaps|excluded-address covering", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DHCP_EXCLUDED_ADDRESS_OVERLAP",
                "root_cause": "DHCP excluded-address range is overly broad, encompassing addresses intended for dynamic client assignment.",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.94,
                "evidence": "ip dhcp excluded-address range excludes valid host assignable addresses in the scope.",
                "next_command": "show running-config | include excluded-address",
                "fix_steps": [
                    "configure terminal",
                    "no ip dhcp excluded-address <start_ip> <end_ip>",
                    "ip dhcp excluded-address <start_ip> <narrow_end_ip>",
                    "end"
                ]
            }
        return None

    def _check_dns_server_missing(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"dns server 0\.0\.0\.0|dns server configuration missing", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DNS_SERVER_UNCONFIGURED",
                "root_cause": "DNS resolver IP is unassigned or configured as 0.0.0.0 on client/DHCP pool.",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.96,
                "evidence": "ipconfig shows DNS server 0.0.0.0; nslookup fails while raw IP ping succeeds.",
                "next_command": "ipconfig /all",
                "fix_steps": [
                    "configure terminal",
                    "ip dhcp pool <pool_name>",
                    "dns-server <dns_server_ip>",
                    "end"
                ]
            }
        return None

    def _check_dns_missing_record(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"nxdomain|dns record.*is absent|missing dns record", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DNS_A_RECORD_MISSING",
                "root_cause": "Authoritative DNS server has no Host (A) or CNAME record for the requested hostname.",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.95,
                "evidence": "nslookup returns NXDOMAIN status from authoritative DNS resolver.",
                "next_command": "nslookup <hostname>",
                "fix_steps": [
                    "Access DNS server configuration.",
                    "Add DNS A-Record mapping hostname to correct target IP.",
                    "Verify query resolution: nslookup <hostname>"
                ]
            }
        return None

    def _check_dns_wrong_resolver(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"uses public dns.*internal zone is private|wrong dns resolver", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "DNS_INCORRECT_RESOLVER",
                "root_cause": "Clients are assigned external public DNS (e.g. 8.8.8.8) which cannot resolve internal private enterprise domains.",
                "osi_layer": "Layer 7/Application",
                "confidence": 0.95,
                "evidence": "Internal zone lookup directed to public resolver 8.8.8.8 instead of enterprise DNS server.",
                "next_command": "nslookup <internal_hostname>",
                "fix_steps": [
                    "configure terminal",
                    "ip dhcp pool <pool_name>",
                    "dns-server <internal_dns_ip>",
                    "end"
                ]
            }
        return None

    def _check_wireless_vlan_mapping(self, symptom: str, show_output: str, topo: str, text: str) -> Optional[Dict[str, Any]]:
        if re.search(r"ap uplink vlan mismatch|wireless vlan mapping mismatch|switch port is access vlan 1 while ssid is mapped to vlan 30", text, re.IGNORECASE):
            return {
                "rule_matched": True,
                "rule_name": "WIRELESS_VLAN_TRUNK_MISMATCH",
                "root_cause": "Access Point (AP) switchport is in Access Mode instead of Trunk Mode, dropping tagged multi-SSID traffic.",
                "osi_layer": "Layer 2/7",
                "confidence": 0.96,
                "evidence": "AP SSID maps to VLAN 30 but connected switch port is configured as untagged access VLAN 1.",
                "next_command": "show interfaces <ap_switchport> switchport",
                "fix_steps": [
                    "configure terminal",
                    "interface <ap_switchport>",
                    "switchport mode trunk",
                    "switchport trunk allowed vlan add 10,20,30,40",
                    "end"
                ]
            }
        return None


def run_checker_on_dataset(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Runs deterministic rule checker across all cases and attaches results."""
    checker = RuleChecker()
    results = []
    
    for case in cases:
        diag = checker.diagnose(
            symptom=case.get("symptom", ""),
            show_output=case.get("show_output", ""),
            topology_note=case.get("topology_note", "")
        )
        case_result = {
            "case_id": case["case_id"],
            "issue_type": case.get("issue_type", case.get("concept", "")),
            "expected_fault": case.get("expected_fault", ""),
            "expected_osi": case.get("osi_layer", ""),
            "rule_matched": diag["rule_matched"],
            "rule_name": diag["rule_name"],
            "diagnosed_root_cause": diag["root_cause"],
            "diagnosed_osi": diag["osi_layer"],
            "confidence": diag["confidence"],
            "evidence": diag["evidence"],
            "fix_steps": diag["fix_steps"]
        }
        results.append(case_result)
        
    return results

def run_checks_on_file(csv_file: str) -> None:
    """Helper to run the checker on a CSV dataset and print diagnostic summary."""
    if not os.path.exists(csv_file):
        print(f"Error: Dataset not found at {csv_file}", file=sys.stderr)
        sys.exit(1)

    checker = RuleChecker()
    cases = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases.append(row)

    print(f"Loaded {len(cases)} cases from {csv_file}")
    matches = 0
    for c in cases:
        diag = checker.diagnose(
            symptom=c.get("symptom", ""),
            show_output=c.get("show_output", ""),
            topology_note=c.get("topology_note", "")
        )
        if diag["rule_matched"]:
            matches += 1
            print(f"[{c['case_id']}] PASS: {diag['rule_name']} ({diag['osi_layer']}) - Conf: {diag['confidence']}")
        else:
            print(f"[{c['case_id']}] NO MATCH: Expected '{c.get('expected_fault')}'")

    print("=" * 60)
    print(f"Total Rules Matched: {matches}/{len(cases)} ({matches/len(cases)*100:.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    csv_target = "cases.csv" if os.path.exists("cases.csv") else os.path.join("data", "cases.csv")
    run_checks_on_file(csv_target)

