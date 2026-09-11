package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-endpointid-must-be-outbound", "ERROR", name,
	"Properties.ResolverEndpointId",
	sprintf("the rule points at endpoint %s, whose Direction is %s; Resolver rules require an outbound endpoint", [e, d]),
	"Point the rule at an OUTBOUND Resolver endpoint",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	e := _pf_r53r_endpoint_of(p)
	d := _pf_r53r_str(_pf_r53r_props(e), "Direction")
	d != "OUTBOUND"
}
