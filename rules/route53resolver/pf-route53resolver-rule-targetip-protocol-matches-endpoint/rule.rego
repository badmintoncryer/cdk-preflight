package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetip-protocol-matches-endpoint", "ERROR", name,
	"Properties.TargetIps",
	sprintf("TargetIps asks for protocol %s but endpoint %s does not declare it", [v, e]),
	"Add the protocol to the endpoint's Protocols, or use one the endpoint already has",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-resolverrule-targetaddress.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	e := _pf_r53r_endpoint_of(p)
	some t in _pf_r53r_arr(p, "TargetIps")
	v := _pf_r53r_str(t, "Protocol")
	v in {"Do53", "DoH", "DoH-FIPS"}
	not v in _pf_r53r_protos(_pf_r53r_props(e))
}
