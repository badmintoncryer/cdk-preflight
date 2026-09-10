package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidr-private-zone", "ERROR", name,
	"Properties.CidrRoutingConfig",
	"A record in a private hosted zone cannot use IP-based routing; the CIDR routing policy is public-zone only",
	"Use a different routing policy in the private zone, or move the record to a public zone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	rs := _pf_r53lib_props(name)
	z := _pf_r53lib_own_zone(rs)
	_pf_r53lib_private_zone(z)
	_pf_r53lib_has(rs, "CidrRoutingConfig")
}

violation contains make_diag_full("pf-route53-cidr-private-zone", "ERROR", name,
	sprintf("Properties.RecordSets[%d].CidrRoutingConfig", [_pf_it.index]),
	"A record in a private hosted zone cannot use IP-based routing; the CIDR routing policy is public-zone only",
	"Use a different routing policy in the private zone, or move the record to a public zone",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy.html") if {
	some name in resources_of_type("AWS::Route53::RecordSetGroup")
	some _pf_it in flatten_list(name, "Properties.RecordSets")
	rs := _pf_it.value
	is_object(rs)
	z := _pf_r53lib_own_zone(rs)
	_pf_r53lib_private_zone(z)
	_pf_r53lib_has(rs, "CidrRoutingConfig")
}
