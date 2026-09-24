package cdk_preflight

import rego.v1

# One accelerator routes a given port to exactly one listener, so two listeners on
# the same accelerator cannot claim overlapping ranges: CreateListener answers
# InvalidPortRangeException ("not unique for this accelerator"). Nothing but this
# pack sees both listeners at once - each resource is schema-clean on its own.
violation contains make_diag_full("pf-ga-listener-port-ranges-unique-per-accelerator", "ERROR", l1,
	"Properties.PortRanges",
	sprintf("Listener %v on the same accelerator (%v) already claims port %v; port ranges must be unique across the listeners of one accelerator", [l2, acc, p]),
	"Give each listener on the accelerator a port range that no other listener covers",
	"https://docs.aws.amazon.com/global-accelerator/latest/api/API_CreateListener.html") if {
	some l1 in _pf_galib_listeners
	some l2 in _pf_galib_listeners
	l1 < l2
	acc := _pf_galib_accel(l1)
	acc == _pf_galib_accel(l2)
	some r1 in _pf_galib_ranges(l1)
	some r2 in _pf_galib_ranges(l2)
	r1[0] <= r2[1]
	r2[0] <= r1[1]
	p := max([r1[0], r2[0]])
}
