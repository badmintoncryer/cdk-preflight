package cdk_preflight

import rego.v1

# An endpoint group is keyed by (listener, Region), so a second group for the same
# Region on the same listener fails with EndpointGroupAlreadyExistsException. Each
# resource is schema-clean on its own; only a whole-template view sees the clash.
violation contains make_diag_full("pf-ga-endpoint-group-unique-per-listener-region", "ERROR", g1,
	"Properties.EndpointGroupRegion",
	sprintf("Endpoint group %v already covers %v on listener %v; a listener holds at most one endpoint group per Region", [g2, region, l]),
	"Keep one endpoint group per Region on a listener, or move one of them to another Region",
	"https://docs.aws.amazon.com/global-accelerator/latest/api/API_CreateEndpointGroup.html") if {
	some g1 in _pf_galib_groups
	some g2 in _pf_galib_groups
	g1 < g2
	l := _pf_galib_listener(g1)
	l == _pf_galib_listener(g2)
	region := _pf_galib_str(g1, "EndpointGroupRegion")
	region == _pf_galib_str(g2, "EndpointGroupRegion")
}
