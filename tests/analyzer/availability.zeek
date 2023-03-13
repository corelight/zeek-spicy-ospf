## Note below -P did not work on a Mac, so I tried -E.
# @TEST-EXEC: zeek -NN | grep -Eqi "(ANALYZER_SPICY__OSPF|ANALYZER_SPICY_OSPF)"
#
# @TEST-DOC: Check that the OSPF analyzer is available.
