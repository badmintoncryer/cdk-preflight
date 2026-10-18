package cdk_preflight

import rego.v1

# A resource configuration reaches private addresses only: an IPv4 IpResource
# must fall in 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12 or 192.168.0.0/16
# ("IP address 172.32.0.10 is not in allowed ranges"). Well-formed dotted quads
# only; IPv6 is not checked.
_pf_vpclrcip_ranges := ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"]

violation contains make_diag_full("pf-vpclattice-rc-ip-private-range", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.IpResource",
	sprintf("IpResource '%s' is outside the private ranges; the create fails with \"IP address %s is not in allowed ranges\"", [ip, ip]),
	"Use an address in 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12 or 192.168.0.0/16",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	ip := resolve(name, "Properties.ResourceConfigurationDefinition.IpResource")
	is_string(ip)
	regex.match(`^[0-9]{1,3}(\.[0-9]{1,3}){3}$`, ip)
	_pf_ec2lib_ip_int(ip)
	not _pf_vpclrcip_private(ip)
}

_pf_vpclrcip_private(ip) if {
	some c in _pf_vpclrcip_ranges
	_pf_ec2lib_cidr_has_ip(c, ip)
}
