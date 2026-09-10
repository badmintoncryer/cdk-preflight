package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetips-max-six", "ERROR", name,
	"Properties.TargetIps",
	sprintf("the rule declares %d target IPs; Route 53 Resolver allows at most 6", [n]),
	"Keep at most 6 entries in TargetIps",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	n := count(_pf_r53r_arr(p, "TargetIps"))
	n > 6
}
