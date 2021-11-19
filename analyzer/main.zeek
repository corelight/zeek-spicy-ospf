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
        ospf_type: string &log;
        router_id: addr &log &optional;
        area_id: addr &log &optional;
        link_state_id: addr &log &optional;
        advert_router: addr &log &optional;
        netmask: addr &log &optional;
        routers: vector of addr &log &optional;
        link_id: addr &log &optional;
        link_data: addr &log &optional;
        link_type: string &log &optional;
        lsa_type: string &log &optional;
        fwd_addr: addr &log &optional;
        route_tag: count &log &optional;
    };

    ### Events ###

    global OSPF::message: event(pkt: raw_pkt_hdr, version: count, ospf_type: zeek_spicy_ospf::MsgType,
                                router_id: addr, area_id: addr, autype: count, auth: count);

    global OSPF::router_lsa_link: event(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                        link_state_id: addr, advert_router: addr, link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType);

    global OSPF::network_lsa: event(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                    link_state_id: addr, advert_router: addr, netmask: addr, routers: vector of addr);

    global OSPF::summary_lsa_item: event(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                         link_state_id: addr, advert_router: addr, netmask: addr, metric: count);

    global OSPF::external_lsa_item: event(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                          link_state_id: addr, advert_router: addr, netmask: addr, metric: count, fwd_addr: addr, route_tag: count);

    # Log event
    global OSPF::log_ospf: event(rec: OSPF::Info);
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

event OSPF::router_lsa_link(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                            link_state_id: addr, advert_router: addr, link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType)
    {
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $link_id=link_id, $link_data=link_data, $link_type=LinkTypes[link_type], $lsa_type=LSATypes[lsa_type], $ip_src=pkt$ip$src, $ip_dst=pkt$ip$dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::network_lsa(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                        link_state_id: addr, advert_router: addr, netmask: addr, routers: vector of addr)
    {
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router, 
                        $netmask=netmask, $routers=routers, $lsa_type=LSATypes[lsa_type], $ip_src=pkt$ip$src, $ip_dst=pkt$ip$dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::summary_lsa_item(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                             link_state_id: addr, advert_router: addr, netmask: addr, metric: count)
    {
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $netmask=netmask, $lsa_type=LSATypes[lsa_type], $ip_src=pkt$ip$src, $ip_dst=pkt$ip$dst];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::external_lsa_item(pkt: raw_pkt_hdr, lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                              link_state_id: addr, advert_router: addr, netmask: addr, metric: count, fwd_addr: addr, route_tag: count)
    {
    local info: Info = [$ospf_type=MsgTypes[ospf_type], $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $netmask=netmask, $fwd_addr=fwd_addr, $route_tag=route_tag, $lsa_type=LSATypes[lsa_type], $ip_src=pkt$ip$src, $ip_dst=pkt$ip$dst];
    Log::write(OSPF::OSPF_LOG, info);
    }


event zeek_init() &priority=5 
    {
    Log::create_stream(OSPF::OSPF_LOG, [$columns=Info, $ev=log_ospf, $path="ospf"]);
    }