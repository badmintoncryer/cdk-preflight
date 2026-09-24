package cdk_preflight

import rego.v1

# "Endpoint ports can't overlap listener port ranges. The endpoint ports that you
# specify in a port override cannot be included in any of the listener port ranges
# that you've configured for the accelerator." The check spans the endpoint group,
# its listener and every other listener on the same accelerator.
violation contains make_diag_full("pf-ga-port-override-endpoint-port-not-in-listener-range", "ERROR", name,
	sprintf("Properties.PortOverrides.%d.EndpointPort", [o.index]),
	sprintf("Endpoint port %v sits inside the %v-%v port range of listener %v on the same accelerator; a port override cannot target a port the accelerator listens on", [ep, other[0], other[1], peer]),
	"Override to an endpoint port that no listener port range of the accelerator covers",
	"https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoint-groups-port-override.html") if {
	some name in _pf_galib_groups
	acc := _pf_galib_accel(_pf_galib_listener(name))
	some o in flatten_list(name, "Properties.PortOverrides")
	ep := _pf_galib_int(_pf_galib_oget(o.value, "EndpointPort"))
	some peer in _pf_galib_listeners
	acc == _pf_galib_accel(peer)
	some other in _pf_galib_ranges(peer)
	ep >= other[0]
	ep <= other[1]
}
