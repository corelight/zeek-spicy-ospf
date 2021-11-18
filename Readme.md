# zeek-spicy-ospf

This is a Spicy based OSPF packet analyzer for Zeek.  You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

Links: 
* Original logic imported from https://github.com/s-wells/spicy_parsers/tree/main/ospf, with author's permission. 
* https://datatracker.ietf.org/doc/html/rfc2328
* https://datatracker.ietf.org/doc/html/rfc2740
* https://datatracker.ietf.org/doc/html/rfc5340
* https://wiki.wireshark.org/OSPF

Testing PCAPs sources:

* https://wiki.wireshark.org/SampleCaptures
    * https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ospf.cap
    * https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ospf-md5.cap
    * https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=hsrp-and-ospf-in-LAN
    * https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=mpls-te.cap
* https://packetlife.net/captures/protocol/ospf/
    * https://packetlife.net/media/captures/OSPF_with_MD5_auth.cap
* https://www.cloudshark.org/captures/111cb2076caa

### Example Log:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ospf
#open	2021-11-18-20-14-15
#fields	ts	ospf_type	router_id	area_id	link_state_id	advert_router	netmask	routers	link_id	link_data	fwd_addr	route_tag
#types	time	enum	addr	addr	addr	addr	addr	vector[addr]	addr	addr	addr	count
1098361214.418357	zeek_spicy_ospf::MsgType_LSU	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	-	-	192.168.170.0	255.255.255.0	-	-
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	-	-
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	-	-
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	80.212.16.0	192.168.170.2	255.255.255.255	-	-	-	0.0.0.0	0
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	148.121.171.0	192.168.170.2	255.255.255.0	-	-	-	192.168.170.1	0
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.130.120.0	192.168.170.2	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.0.0	192.168.170.2	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.1.0	192.168.170.2	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420459	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.172.0	192.168.170.2	255.255.255.0	-	-	-	192.168.170.10	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	148.121.171.0	192.168.170.3	255.255.255.0	-	-	-	192.168.170.1	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.130.120.0	192.168.170.3	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.0.0	192.168.170.3	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.1.0	192.168.170.3	255.255.255.0	-	-	-	0.0.0.0	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.172.0	192.168.170.3	255.255.255.0	-	-	-	192.168.170.10	0
1098361214.420698	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	80.212.16.0	192.168.170.3	255.255.255.255	-	-	-	0.0.0.0	0
1098361214.450077	zeek_spicy_ospf::MsgType_LSU	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	255.255.255.0	192.168.170.3,192.168.170.8	-	-	-	-
1098361214.450161	zeek_spicy_ospf::MsgType_LSU	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	-	-	192.168.170.8	192.168.170.8	-	-
1098361218.427849	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	-	-
1098361218.427849	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	-	-
1098361219.417823	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	-	-
1098361219.417823	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	-	-
1098361220.858006	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	-	-
1098361220.858006	zeek_spicy_ospf::MsgType_LSU	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	-	-
#close	2021-11-18-20-14-15
```

### License:

Creative Commons BY-SA

https://creativecommons.org/licenses/by-sa/4.0/

