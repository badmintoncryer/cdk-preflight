package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetip-sni-doh-only", "ERROR", name,
	"Properties.TargetIps",
	"TargetIps sets ServerNameIndication without Protocol DoH; SNI only applies to DoH targets",
	"Set Protocol to DoH, or drop ServerNameIndication",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_TargetAddress.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	some t in _pf_r53r_arr(p, "TargetIps")
	_pf_r53r_has(t, "ServerNameIndication")
	object.get(t, "Protocol", "") != "DoH"
}
