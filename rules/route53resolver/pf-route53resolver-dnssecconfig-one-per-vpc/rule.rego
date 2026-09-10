package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-dnssecconfig-one-per-vpc", "ERROR", name,
	"Properties.ResourceId",
	"another ResolverDNSSECConfig in this template targets the same VPC",
	"Keep one ResolverDNSSECConfig per VPC",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_UpdateResolverDnssecConfig.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverDNSSECConfig")
	k := _pf_r53r_key(_pf_r53r_props(name), "ResourceId")
	dup := [1 |
		some o in resources_of_type("AWS::Route53Resolver::ResolverDNSSECConfig")
		_pf_r53r_key(_pf_r53r_props(o), "ResourceId") == k
	]
	count(dup) > 1
}
