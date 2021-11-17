# @TEST-EXEC: zeek -Cr ${TRACES}/ospf.cap %INPUT >output.txt
# @TEST-EXEC: btest-diff output.txt
# @TEST-EXEC: btest-diff ospf.log
#
# @TEST-DOC: Test OSPF against Zeek with a small trace.

@load analyzer

event OSPF::message(version: count, ospf_type: zeek_spicy_ospf::MsgType,
                    router_id: addr, area_id: addr, autype: count, auth: count)
	{
    print(cat("OSPF Packet ", version, " ", ospf_type, " ", 
              router_id, " ", area_id, " ", autype, " ", auth));
    }