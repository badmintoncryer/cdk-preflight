package cdk_preflight

import rego.v1

# The schema checks only the length of IpResource (4 to 39). A dotted quad with
# an octet over 255 is rejected ("10.0.0.256 is not a valid IP address"). Other
# malformed strings and IPv6 addresses are not checked.
violation contains make_diag_full("pf-vpclattice-rc-ip-format", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.IpResource",
	sprintf("IpResource '%s' has an octet over 255; the create fails with \"%s is not a valid IP address\"", [ip, ip]),
	"Use a valid IPv4 address (each octet 0 to 255)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	ip := resolve(name, "Properties.ResourceConfigurationDefinition.IpResource")
	is_string(ip)
	regex.match(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`, ip)
	some o in split(ip, ".")
	to_number(o) > 255
}
