package cdk_preflight

import rego.v1

# A port override redirects traffic that arrives on a listener port, so the
# ListenerPort has to be a port the endpoint group's listener actually accepts.
# The schema bounds it to 0-65535 and never looks at the listener.
violation contains make_diag_full("pf-ga-port-override-listener-port-in-range", "ERROR", name,
	sprintf("Properties.PortOverrides.%d.ListenerPort", [o.index]),
	sprintf("Listener %v does not accept port %v, so the port override has no traffic to redirect", [l, lp]),
	"Point ListenerPort at a port covered by the listener's PortRanges",
	"https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoint-groups-port-override.html") if {
	some name in _pf_galib_groups
	l := _pf_galib_listener(name)
	count(_pf_galib_ranges(l)) > 0
	some o in flatten_list(name, "Properties.PortOverrides")
	lp := _pf_galib_int(_pf_galib_oget(o.value, "ListenerPort"))
	not _pf_galib_in_ranges(l, lp)
}
