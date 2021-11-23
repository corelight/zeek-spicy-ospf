# @TEST-EXEC: zeek -Cr ${TRACES}/OSPF_LSA_types.cap %INPUT >output.txt
# @TEST-EXEC: btest-diff output.txt
# @TEST-EXEC: btest-diff ospf.log
#
# @TEST-DOC: Test OSPF against Zeek with a small trace.

@load analyzer

event OSPF::message(pkt: raw_pkt_hdr, version: count, ospf_type: zeek_spicy_ospf::MsgType,
                    router_id: addr, area_id: addr)
	{
    print(cat("OSPF Packet ", pkt$ip$src, " ", pkt$ip$dst, " ", version, " ", ospf_type, " ", 
              router_id, " ", area_id, " ", pkt));
    }