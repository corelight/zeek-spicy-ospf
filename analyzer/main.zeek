module OSPF;

export {
    redef enum Log::ID += { OSPF_LOG };

    type Info: record {
		## Time
		ts: time &log &default=network_time();

        # IP fields
        ip_src: addr &log &optional;
        ip_dst: addr &log &optional;

        # These columns have the original meanings from the OSPF RFC.
        # LSA = Link State Advertisement(s)
        # OSPF Header
        ospf_type: string &log &optional;
        version: count &log &optional;
        router_id: addr &log &optional;
        area_id: addr &log &optional;
        # Hello Packet
        interface_id: count &log &optional; # V3
        netmask: addr &log &optional;
        desig_router: addr &log &optional;
        backup_router: addr &log &optional;
        neighbors: vector of addr &log &optional;
        # LSA Header
        lsa_type: string &log &optional;
        link_state_id: addr &log &optional;
        advert_router: addr &log &optional;
        # Network LSA
        routers: vector of addr &log &optional;
        # Router LSA
        link_id: addr &log &optional;
        link_data: addr &log &optional;
        link_type: string &log &optional;
        neighbor_router_id: addr &log &optional;
        # External LSA
        metrics: vector of count &log &optional;
        fwd_addrs: vector of addr &log &optional;
        route_tags: vector of count &log &optional;
        neighbor_interface_id: count &log &optional;
        prefix: subnet &log &optional;
        # IA Router
        metric: count &log &optional;
        dest_router_id: addr &log &optional;
        # Link Prefixes
        link_prefixes: set[subnet] &log &optional;
        # Intra Prefixes
        intra_prefixes: set[subnet] &log &optional;
    };

    ### Events ###

    global OSPF::message: event(pkt: raw_pkt_hdr, version: count, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr);

    global OSPF::hello: event(pkt: raw_pkt_hdr, version: count, router_id: addr, area_id: addr, netmask: addr, interface_id: count,
                              desig_router: addr, backup_router: addr, neighbors: vector of addr);

    global OSPF::router_lsa_link: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                        router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                        link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType);

    global OSPF::router_lsa_link_v3: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                           router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                           link_type: zeek_spicy_ospf::RouterLSAType,
                                           interface_id: count, neighbor_interface_id: count, neighbor_router_id: addr);

    global OSPF::network_lsa: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                    router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                    netmask: addr, routers: vector of addr);

    global OSPF::summary_lsa_item: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                         router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                         netmask: addr, metric: count);

    global OSPF::external_lsa: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                     router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, netmask: addr);

    global OSPF::external_lsa_item: event(pkt: raw_pkt_hdr, metric: count, fwd_addr: addr, route_tag: count);

    global OSPF::ia_prefix: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                  router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                  metric: count, prefix_len: count, prefix_data: string);

    global OSPF::external_v3: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                    router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                                    metric: count, prefix_len: count, prefix_data: string, fwd_addr: addr);

    global OSPF::link_lsa: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                 router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr);

    global OSPF::link_prefix: event(pkt: raw_pkt_hdr, prefix_len: count, prefix_data: string);

    global OSPF::intra_prefixes: event(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                                       router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr);

    global OSPF::intra_prefix: event(pkt: raw_pkt_hdr, prefix_len: count, prefix_data: string);

    # Log event
    global OSPF::log_ospf: event(rec: OSPF::Info);
}

redef record raw_pkt_hdr += {
	ospf: Info &optional;
};

function set_session(p: raw_pkt_hdr)
    {
    if ( ! p?$ospf )
        {
        p$ospf = [];
        p$ospf$intra_prefixes = set();
        p$ospf$link_prefixes = set();
        p$ospf$metrics = vector();
        p$ospf$fwd_addrs = vector();
        p$ospf$route_tags = vector();
        }
    }

const MsgTypes = {
    [zeek_spicy_ospf::MsgType_Hello] = "Hello",
    [zeek_spicy_ospf::MsgType_DB_Desc] = "DB Description",
    [zeek_spicy_ospf::MsgType_LSR] = "Link State Request",
    [zeek_spicy_ospf::MsgType_LSU] = "Link State Update",
    [zeek_spicy_ospf::MsgType_LSAck] = "Link State Ack",
  } &default = "FIXME-Unknown";

const LSATypes = {
    [zeek_spicy_ospf::LSAType_Router] = "Router",
    [zeek_spicy_ospf::LSAType_Network] = "Network",
    [zeek_spicy_ospf::LSAType_Summary_IP] = "Summary IP",
    [zeek_spicy_ospf::LSAType_Summary_ASBR] = "Summary ASBR",
    [zeek_spicy_ospf::LSAType_External] = "External",
  } &default = "FIXME-Unknown";

const LSATypesV3 = {
    [zeek_spicy_ospf::LSATypeV3_Router] = "Router",
    [zeek_spicy_ospf::LSATypeV3_Network] = "Network",
    [zeek_spicy_ospf::LSATypeV3_IA_Prefix] = "IA Prefix",
    [zeek_spicy_ospf::LSATypeV3_IA_Router] = "IA Router",
    [zeek_spicy_ospf::LSATypeV3_External] = "External",
    [zeek_spicy_ospf::LSATypeV3_Group_Membership] = "Grp Membership",
    [zeek_spicy_ospf::LSATypeV3_Type_Seven] = "Type 7",
    [zeek_spicy_ospf::LSATypeV3_Link] = "Link",
    [zeek_spicy_ospf::LSATypeV3_IntraA_Prefix] = "IntraA Prefix",
  } &default = "FIXME-Unknown";

const LinkTypes = {
    [zeek_spicy_ospf::RouterLSAType_Point_to_Point] = "Point to Point",
    [zeek_spicy_ospf::RouterLSAType_Transit] = "Transit",
    [zeek_spicy_ospf::RouterLSAType_Stub] = "Stub",
    [zeek_spicy_ospf::RouterLSAType_Virtual] = "Virtual",
  } &default = "FIXME-Unknown";

event zeek_init()
    {
    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x59, "spicy::OSPF") )
		Reporter::error("cannot register OSPF Spicy analyzer");
    }

event OSPF::hello(pkt: raw_pkt_hdr, version: count, router_id: addr, area_id: addr, netmask: addr, interface_id: count,
                  desig_router: addr, backup_router: addr, neighbors: vector of addr)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[zeek_spicy_ospf::MsgType_Hello], $version=version, $router_id=router_id, $area_id=area_id,
                        $ip_src=src, $ip_dst=dst, $desig_router=desig_router, $backup_router=backup_router, $neighbors=neighbors];
    if (version == 2)
        {
        info$netmask = netmask;
        }
    if (version == 3)
        {
        info$interface_id = interface_id;
        }
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::router_lsa_link(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                            router_id: addr, area_id: addr,
                            link_state_id: addr, advert_router: addr, link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $link_id=link_id, $link_data=link_data, $link_type=LinkTypes[link_type],
                        $lsa_type=LSATypes[lsa_type], $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::router_lsa_link_v3(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                               router_id: addr, area_id: addr,
                               link_state_id: addr, advert_router: addr, link_type: zeek_spicy_ospf::RouterLSAType,
                               interface_id: count, neighbor_interface_id: count, neighbor_router_id: addr)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $link_type=LinkTypes[link_type], $lsa_type=LSATypes[lsa_type], $ip_src=src,
                        $ip_dst=dst, $interface_id=interface_id,
                        $neighbor_interface_id=neighbor_interface_id, $neighbor_router_id=neighbor_router_id];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::network_lsa(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                        router_id: addr, area_id: addr,
                        link_state_id: addr, advert_router: addr, netmask: addr, routers: vector of addr)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $netmask=netmask, $routers=routers, $lsa_type=LSATypes[lsa_type],
                        $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::summary_lsa_item(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                             router_id: addr, area_id: addr,
                             link_state_id: addr, advert_router: addr, netmask: addr, metric: count)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $netmask=netmask, $lsa_type=LSATypes[lsa_type], $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::external_lsa(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                         router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, netmask: addr)
    {
    set_session(pkt);
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $netmask=netmask, $metrics=pkt$ospf$metrics, $fwd_addrs=pkt$ospf$fwd_addrs, $route_tags=pkt$ospf$route_tags,
                        $lsa_type=LSATypes[lsa_type], $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::external_lsa_item(pkt: raw_pkt_hdr, metric: count, fwd_addr: addr, route_tag: count)
    {
    set_session(pkt);
    pkt$ospf$metrics += metric;
    pkt$ospf$fwd_addrs += fwd_addr;
    pkt$ospf$route_tags += route_tag;
    }

function raw_bytes_to_v6_addr(rawbytes: string) : addr
	{
    local v: vector of count;
    local a: count;
    local pos: count = 0;

    while (pos < |rawbytes|)
        {
        a = bytestring_to_count(rawbytes[pos:pos+4]);
        v += a;
        pos += 4;
        }

    while (|v| < 4)
        v += 0;

	return counts_to_addr(v);
	}

event OSPF::ia_prefix(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                      router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                      metric: count, prefix_len: count, prefix_data: string)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local prefix_addr: addr = raw_bytes_to_v6_addr(prefix_data);
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $metric=metric, $prefix=prefix_addr/prefix_len, $lsa_type=LSATypesV3[lsa_type],
                        $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::ia_router(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                      router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr,
                      metric: count, dest_router_id: addr)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $metrics=vector(metric), $dest_router_id=dest_router_id, $lsa_type=LSATypesV3[lsa_type],
                        $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::external_v3(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                        router_id: addr, area_id: addr,
                        link_state_id: addr, advert_router: addr, metric: count, prefix_len: count, prefix_data: string, fwd_addr: addr)
    {
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local prefix_addr: addr = raw_bytes_to_v6_addr(prefix_data);
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $metrics=vector(metric), $prefix=prefix_addr/prefix_len, $fwd_addrs=vector(fwd_addr), $lsa_type=LSATypesV3[lsa_type],
                        $ip_src=src, $ip_dst=dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::link_prefix(pkt: raw_pkt_hdr, prefix_len: count, prefix_data: string)
    {
    set_session(pkt);
    local prefix_addr: addr = raw_bytes_to_v6_addr(prefix_data);
    add pkt$ospf$link_prefixes[prefix_addr/prefix_len];
    }

event OSPF::link_lsa(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                     router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr)
    {
    set_session(pkt);
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $lsa_type=LSATypesV3[lsa_type], $ip_src=src, $ip_dst=dst,
                        $link_prefixes=pkt$ospf$link_prefixes];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::intra_prefix(pkt: raw_pkt_hdr, prefix_len: count, prefix_data: string)
    {
    set_session(pkt);
    local prefix_addr: addr = raw_bytes_to_v6_addr(prefix_data);
    add pkt$ospf$intra_prefixes[prefix_addr/prefix_len];
    }

event OSPF::intra_prefixes(pkt: raw_pkt_hdr, version: count, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType,
                           router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr)
    {
    set_session(pkt);
    local src: addr = version==3 ? pkt$ip6$src : pkt$ip$src;
    local dst: addr = version==3 ? pkt$ip6$dst : pkt$ip$dst;
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $version=version, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id,
                        $advert_router=advert_router, $lsa_type=LSATypesV3[lsa_type], $ip_src=src, $ip_dst=dst,
                        $intra_prefixes=pkt$ospf$intra_prefixes];
    Log::write(OSPF::OSPF_LOG, info);
    }

event zeek_init() &priority=5
    {
    Log::create_stream(OSPF::OSPF_LOG, [$columns=Info, $ev=log_ospf, $path="ospf"]);
    }
