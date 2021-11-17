spicy_add_analyzer(
    NAME OSPF
    PACKAGE_NAME OSPF
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
