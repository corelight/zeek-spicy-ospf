# @TEST-EXEC: zeek -Cr ${TRACES}/OSPFv3_broadcast_adjacency.cap %INPUT >output.txt
# @TEST-EXEC: btest-diff output.txt
# @TEST-EXEC: btest-diff ospf.log
#
# @TEST-DOC: Test OSPF against Zeek with a small trace.

@load analyzer

event OSPF::message(pkt: raw_pkt_hdr, version: count, ospf_type: zeek_spicy_ospf::MsgType,
                    router_id: addr, area_id: addr)
	{
    print(cat("OSPF Packet ", pkt$ip6$src, " ", pkt$ip6$dst, " ", version, " ", ospf_type, " ", 
              router_id, " ", area_id, " ", pkt));
    }