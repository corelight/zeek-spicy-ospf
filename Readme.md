# zeek-spicy-ospf

This is a Spicy based OSPF v2 & v3 packet analyzer for Zeek.  You must install [Spicy](https://docs.zeek.org/projects/spicy/en/latest/)
to use this package.

Links:

* Original logic imported from <https://github.com/s-wells/spicy_parsers/tree/main/ospf>, with author's permission.
* <https://datatracker.ietf.org/doc/html/rfc2328>
* <https://datatracker.ietf.org/doc/html/rfc2740>
* <https://datatracker.ietf.org/doc/html/rfc5340>
* <https://datatracker.ietf.org/doc/html/rfc4813#page-2>
* <https://wiki.wireshark.org/OSPF>

Testing PCAPs sources:

* <https://wiki.wireshark.org/SampleCaptures>
  * <https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=ospf.cap>
* <https://packetlife.net/captures/protocol/ospf/>
  * <https://packetlife.net/media/captures/OSPF_LSA_types.cap>
  * <https://packetlife.net/media/captures/OSPFv3_broadcast_adjacency.cap>
  * <https://packetlife.net/media/captures/OSPFv3_with_AH.cap>

## Example Logs

```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   ospf
#open   2021-11-23-07-32-16
#fields ts      ip_src  ip_dst  ospf_type       version router_id       area_id interface_id    netmask desig_router    backup_router   neighbors       lsa_type        link_state_id   advert_router   routers link_id link_data       link_type       neighbor_router_id      metrics fwd_addrs       route_tags      neighbor_interface_id   prefix  metric  dest_router_id  link_prefixes   intra_prefixes
#types  time    addr    addr    string  count   addr    addr    count   addr    addr    addr    vector[addr]    string  addr    addr    vector[addr]    addr    addr    string  addr    vector[count]   vector[addr]    vector[count]   count   subnet  count   addr    set[subnet]     set[subnet]
1220202735.459206       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       0.0.0.0 0.0.0.0 (empty) -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202740.303003       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       0.0.0.0 0.0.0.0 (empty) -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202745.479174       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       0.0.0.0 0.0.0.0 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202750.294469       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       0.0.0.0 0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202755.486054       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       0.0.0.0 0.0.0.0 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202760.293859       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       0.0.0.0 0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202765.457555       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 2.2.2.2 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202770.289278       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       0.0.0.0 0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202775.477004       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 2.2.2.2 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202780.292824       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       0.0.0.0 -       -       -       Network 0.0.0.5 2.2.2.2 2.2.2.2,1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.4 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       74      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.3 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       84      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.2 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      74      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.1 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8::/64   64      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.8 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       74      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.7 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       84      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.6 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      74      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.5 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8::/64   64      -       -       -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       Link    0.0.0.5 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64      -
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.20.0        2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64
1220202780.312726       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.8 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       74      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.7 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       84      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.6 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      74      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.5 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8::/64   64      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.4 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       74      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.3 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       84      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.2 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      74      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.1 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8::/64   64      -       -       -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       Link    0.0.0.5 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64      -
1220202780.316781       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64
1220202780.828736       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       (empty)
1220202780.828736       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 2.2.2.2 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202780.832711       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 1.1.1.1 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202780.832711       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       (empty)
1220202785.460439       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202785.592475       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       (empty)
1220202785.592475       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 2.2.2.2 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       0.0.0.0 -       -       -       Network 0.0.0.5 2.2.2.2 2.2.2.2,1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.4 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       16777215        -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.3 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       16777215        -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.2 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      16777215        -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.1 2.2.2.2 -       -       -       -       -       -       -       -       -       2001:db8::/64   16777215        -       -       -
1220202785.632476       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.20.0        2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       2001:db8:0:12::/64
1220202785.724441       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 1.1.1.1 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202785.724441       fe80::1 fe80::2 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IntraA Prefix   0.0.0.0 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       (empty)
1220202786.012442       fe80::2 ff02::5 Link State Update       3       2.2.2.2 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 2.2.2.2 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202786.380396       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.4 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:3::/64       16777215        -       -       -
1220202786.380396       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.3 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:4::/64       16777215        -       -       -
1220202786.380396       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.2 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8:0:34::/64      16777215        -       -       -
1220202786.380396       fe80::1 ff02::5 Link State Update       3       1.1.1.1 0.0.0.1 -       -       -       -       -       IA Prefix       0.0.0.1 1.1.1.1 -       -       -       -       -       -       -       -       -       2001:db8::/64   16777215        -       -       -
1220202790.274555       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202790.610521       fe80::2 fe80::1 Link State Update       3       2.2.2.2 0.0.0.1 5       -       -       -       -       Router  0.0.0.0 2.2.2.2 -       -       -       Transit 2.2.2.2 -       -       -       5       -       -       -       -       -
1220202795.486676       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202800.303679       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202805.458102       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202810.301380       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202815.461594       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202820.288904       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202825.457035       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202830.300820       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202835.461659       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202840.273418       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202845.461068       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202850.272863       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202855.480521       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202860.276308       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202865.459906       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202870.295685       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202875.475366       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202880.283128       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202885.462797       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202890.302556       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202895.458188       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202900.290036       fe80::2 ff02::5 Hello   3       2.2.2.2 0.0.0.1 5       -       2.2.2.2 1.1.1.1 1.1.1.1 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
1220202905.453721       fe80::1 ff02::5 Hello   3       1.1.1.1 0.0.0.1 5       -       2.2.2.2 1.1.1.1 2.2.2.2 -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -       -
#close  2021-11-23-07-32-16
```
