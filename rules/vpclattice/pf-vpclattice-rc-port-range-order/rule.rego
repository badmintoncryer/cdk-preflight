package cdk_preflight

import rego.v1

# The schema pattern accepts any "N-M", but a range whose start is above its
# end is rejected ("30-22 is not a valid port range").
violation contains make_diag_full("pf-vpclattice-rc-port-range-order", "ERROR", name,
	sprintf("Properties.PortRanges.%d", [it.index]),
	sprintf("Port range '%s' starts above its end; the create fails with \"%s is not a valid port range\"", [s, s]),
	"Write the range low-high (for example 22-30)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	some it in flatten_list(name, "Properties.PortRanges")
	s := it.value
	is_string(s)
	regex.match(`^[0-9]+-[0-9]+$`, s)
	p := split(s, "-")
	to_number(p[0]) > to_number(p[1])
}
