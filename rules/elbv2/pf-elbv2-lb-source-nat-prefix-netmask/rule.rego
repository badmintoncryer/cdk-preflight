package cdk_preflight

import rego.v1

_pf_elbsnp_fix := "Use auto_assigned, or a /80 prefix out of the subnet IPv6 CIDR"

_pf_elbsnp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-source-nat-prefix-netmask", "ERROR", name,
	sprintf("Properties.SubnetMappings.%d.SourceNatIpv6Prefix", [m.index]),
	sprintf("SourceNatIpv6Prefix '%s' is neither auto_assigned nor a /80 prefix; the service only accepts a /80 netmask", [p]),
	_pf_elbsnp_fix, _pf_elbsnp_url) if {
	some name in _pf_elb_lbs
	some m in flatten_list(name, "Properties.SubnetMappings")
	p := _pf_elb_oget(m.value, "SourceNatIpv6Prefix")
	_pf_elb_lit(p)
	p != "auto_assigned"
	not endswith(p, "/80")
}
