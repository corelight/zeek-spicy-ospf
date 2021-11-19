module OSPF;

export {
    redef enum Log::ID += { OSPF_LOG };

    type Info: record {
		## Time
		ts: time &log &default=network_time();

        # These columns have the original meanings from the OSPF RFC.
        ospf_type: zeek_spicy_ospf::MsgType &log;
        router_id: addr &log &optional;
        area_id: addr &log &optional;
        link_state_id: addr &log &optional;
        advert_router: addr &log &optional;
        netmask: addr &log &optional;
        routers: vector of addr &log &optional;
        link_id: addr &log &optional;
        link_data: addr &log &optional;
        link_type: zeek_spicy_ospf::RouterLSAType &log &optional;
        lsa_type: zeek_spicy_ospf::LSAType &log &optional;
        fwd_addr: addr &log &optional;
        route_tag: count &log &optional;
    };

    ### Events ###

    global OSPF::message: event(version: count, ospf_type: zeek_spicy_ospf::MsgType,
                                router_id: addr, area_id: addr, autype: count, auth: count);

    global OSPF::router_lsa_link: event(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                        link_state_id: addr, advert_router: addr, 
                                        link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType);

    global OSPF::network_lsa: event(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                    link_state_id: addr, advert_router: addr, 
                                    netmask: addr, routers: vector of addr);

    global OSPF::summary_lsa_item: event(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                         link_state_id: addr, advert_router: addr, 
                                         netmask: addr, metric: count, TOS: count);

    global OSPF::external_lsa_item: event(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, 
                                          link_state_id: addr, advert_router: addr, 
                                          netmask: addr, metric: count, fwd_addr: addr, route_tag: count);

    # Log event
    global OSPF::log_ospf: event(rec: OSPF::Info);
}


event zeek_init()
    {
#    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x0800, "spicy::OSPF") )
    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("IP", 0x59, "spicy::OSPF") )
		Reporter::error("cannot register OSPF Spicy analyzer");
    }

#event OSPF::message(version: count, ospf_type: zeek_spicy_ospf::MsgType,
#                    router_id: addr, area_id: addr, autype: count, auth: count)
#	{
#    local info: Info = [$ospf_type=ospf_type, $router_id=router_id, $area_id=area_id];
#    Log::write(OSPF::OSPF_LOG, info);
#	}

event OSPF::router_lsa_link(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, 
                            link_id: addr, link_data: addr, link_type: zeek_spicy_ospf::RouterLSAType)
    {
    local info: Info = [$ospf_type=ospf_type, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $link_id=link_id, $link_data=link_data, $link_type=link_type, $lsa_type=lsa_type];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::network_lsa(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, 
                        netmask: addr, routers: vector of addr)
    {
    local info: Info = [$ospf_type=ospf_type, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router, 
                        $netmask=netmask, $routers=routers, $lsa_type=lsa_type];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::summary_lsa_item(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, 
                             netmask: addr, metric: count, TOS: count)
    {
    local info: Info = [$ospf_type=ospf_type, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $netmask=netmask, $lsa_type=lsa_type];
    Log::write(OSPF::OSPF_LOG, info);
    }

event OSPF::external_lsa_item(lsa_type: zeek_spicy_ospf::LSAType, ospf_type: zeek_spicy_ospf::MsgType, router_id: addr, area_id: addr, link_state_id: addr, advert_router: addr, 
                              netmask: addr, metric: count, fwd_addr: addr, route_tag: count)
    {
    local info: Info = [$ospf_type=ospf_type, $router_id=router_id, $area_id=area_id, $link_state_id=link_state_id, $advert_router=advert_router,
                        $netmask=netmask, $fwd_addr=fwd_addr, $route_tag=route_tag, $lsa_type=lsa_type];
    Log::write(OSPF::OSPF_LOG, info);
    }


event zeek_init() &priority=5 
    {
    Log::create_stream(OSPF::OSPF_LOG, [$columns=Info, $ev=log_ospf, $path="ospf"]);
    }