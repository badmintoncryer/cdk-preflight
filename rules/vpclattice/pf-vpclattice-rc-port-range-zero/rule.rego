package cdk_preflight

import rego.v1

# The schema pattern accepts any digits, but a port below 1 is rejected
# ("0 is not a valid port range"). Both ends of a range are checked.
_pf_vpclrczero_nums(s) := ns if {
	regex.match(`^[0-9]+(-[0-9]+)?$`, s)
	ns := [n | some x in split(s, "-"); n := to_number(x)]
}

violation contains make_diag_full("pf-vpclattice-rc-port-range-zero", "ERROR", name,
	sprintf("Properties.PortRanges.%d", [it.index]),
	sprintf("Port range '%s' has a port below 1; the create fails with \"%s is not a valid port range\"", [s, s]),
	"Use ports from 1 to 65535",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	some it in flatten_list(name, "Properties.PortRanges")
	s := it.value
	is_string(s)
	some x in _pf_vpclrczero_nums(s)
	x < 1
}
