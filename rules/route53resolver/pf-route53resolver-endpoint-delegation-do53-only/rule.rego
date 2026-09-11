package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-delegation-do53-only", "ERROR", name,
	"Properties.Protocols",
	sprintf("the inbound delegation endpoint declares protocol '%s'; delegation endpoints only support Do53", [x]),
	"Drop Protocols, or set it to Do53 only",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "Direction") == "INBOUND_DELEGATION"
	some x in _pf_r53r_protos(p)
	x != "Do53"
}
