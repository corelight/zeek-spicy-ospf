# zeek-spicy-ospf

This is a Spicy based OSPF packet analyzer for Zeek.  You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

Links: 
* Original logic imported from https://github.com/s-wells/spicy_parsers/tree/main/ospf, with author's permission. 
* https://datatracker.ietf.org/doc/html/rfc2328
* https://datatracker.ietf.org/doc/html/rfc2740
* https://datatracker.ietf.org/doc/html/rfc5340
* https://datatracker.ietf.org/doc/html/rfc4813#page-2
* https://wiki.wireshark.org/OSPF

Testing PCAPs sources:

* https://wiki.wireshark.org/SampleCaptures
    * https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ospf.cap
* https://packetlife.net/captures/protocol/ospf/
    * https://packetlife.net/media/captures/OSPF_LSA_types.cap

### Example Logs:

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ospf
#open	2021-11-19-17-23-59
#fields	ts	ip_src	ip_dst	ospf_type	router_id	area_id	link_state_id	advert_router	netmask	routers	link_id	link_data	link_type	lsa_type	fwd_addr	route_tag
#types	time	addr	addr	string	addr	addr	addr	addr	addr	vector[addr]	addr	addr	string	string	addr	count
1098361214.418357	192.168.170.8	224.0.0.5	Link State Update	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	80.212.16.0	192.168.170.2	255.255.255.255	-	-	-	-	External	0.0.0.0	0
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	148.121.171.0	192.168.170.2	255.255.255.0	-	-	-	-	External	192.168.170.1	0
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.130.120.0	192.168.170.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.0.0	192.168.170.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.1.0	192.168.170.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420459	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.172.0	192.168.170.2	255.255.255.0	-	-	-	-	External	192.168.170.10	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	148.121.171.0	192.168.170.3	255.255.255.0	-	-	-	-	External	192.168.170.1	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.130.120.0	192.168.170.3	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.0.0	192.168.170.3	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.1.0	192.168.170.3	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.172.0	192.168.170.3	255.255.255.0	-	-	-	-	External	192.168.170.10	0
1098361214.420698	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	80.212.16.0	192.168.170.3	255.255.255.255	-	-	-	-	External	0.0.0.0	0
1098361214.450077	192.168.170.8	224.0.0.5	Link State Update	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	255.255.255.0	192.168.170.3,192.168.170.8	-	-	-	Network	-	-
1098361214.450161	192.168.170.8	224.0.0.5	Link State Update	192.168.170.8	0.0.0.1	192.168.170.8	192.168.170.8	-	-	192.168.170.8	192.168.170.8	Transit	Router	-	-
1098361218.427849	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361218.427849	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.3	192.168.170.3	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361219.417823	192.168.170.2	192.168.170.8	Link State Update	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361219.417823	192.168.170.2	192.168.170.8	Link State Update	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361220.858006	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
1098361220.858006	192.168.170.2	224.0.0.6	Link State Update	192.168.170.3	0.0.0.1	192.168.170.2	192.168.170.2	-	-	192.168.170.0	255.255.255.0	Stub	Router	-	-
#close	2021-11-19-17-23-59
```

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ospf
#open	2021-11-19-21-08-30
#fields	ts	ip_src	ip_dst	ospf_type	router_id	area_id	link_state_id	advert_router	netmask	routers	link_id	link_data	link_type	lsa_type	fwd_addr	route_tag
#types	time	addr	addr	string	addr	addr	addr	addr	addr	vector[addr]	addr	addr	string	string	addr	count
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	5.5.5.5	5.5.5.5	-	-	192.168.20.0	255.255.255.0	Stub	Router	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	5.5.5.5	5.5.5.5	-	-	10.0.20.2	10.0.20.2	Transit	Router	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	4.4.4.4	4.4.4.4	-	-	10.0.20.0	255.255.255.252	Stub	Router	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	10.0.20.2	5.5.5.5	255.255.255.252	5.5.5.5,4.4.4.4	-	-	-	Network	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	192.168.10.0	4.4.4.4	255.255.255.0	-	-	-	-	Summary IP	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	10.0.10.0	4.4.4.4	255.255.255.252	-	-	-	-	Summary IP	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	10.0.0.0	4.4.4.4	255.255.255.252	-	-	-	-	Summary IP	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	2.2.2.2	4.4.4.4	0.0.0.0	-	-	-	-	Summary ASBR	-	-
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	172.16.3.0	2.2.2.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	172.16.2.0	2.2.2.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	172.16.1.0	2.2.2.2	255.255.255.0	-	-	-	-	External	0.0.0.0	0
1213679915.828110	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	172.16.0.0	2.2.2.2	255.255.255.252	-	-	-	-	External	0.0.0.0	0
1213679915.840078	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	5.5.5.5	5.5.5.5	-	-	192.168.20.0	255.255.255.0	Stub	Router	-	-
1213679915.840078	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	5.5.5.5	5.5.5.5	-	-	10.0.20.0	255.255.255.252	Stub	Router	-	-
1213679915.888070	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	10.0.20.2	5.5.5.5	255.255.255.252	5.5.5.5,4.4.4.4	-	-	-	Network	-	-
1213679916.380138	10.0.20.1	224.0.0.5	Link State Update	4.4.4.4	0.0.0.20	4.4.4.4	4.4.4.4	-	-	10.0.20.2	10.0.20.1	Transit	Router	-	-
1213679920.832374	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	5.5.5.5	5.5.5.5	-	-	192.168.20.0	255.255.255.0	Stub	Router	-	-
1213679920.832374	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	5.5.5.5	5.5.5.5	-	-	10.0.20.2	10.0.20.2	Transit	Router	-	-
1213679920.880373	10.0.20.2	224.0.0.5	Link State Update	5.5.5.5	0.0.0.20	10.0.20.2	5.5.5.5	255.255.255.252	5.5.5.5,4.4.4.4	-	-	-	Network	-	-
1213679921.268421	10.0.20.1	10.0.20.2	Link State Update	4.4.4.4	0.0.0.20	4.4.4.4	4.4.4.4	-	-	10.0.20.2	10.0.20.1	Transit	Router	-	-
```

### License:

Creative Commons BY-SA

https://creativecommons.org/licenses/by-sa/4.0/

