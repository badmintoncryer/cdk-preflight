package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-direction-enum", "ERROR", name,
	"Properties.Direction",
	sprintf("Direction is '%s'; Route 53 Resolver only accepts INBOUND, OUTBOUND or INBOUND_DELEGATION", [d]),
	"Set Direction to INBOUND, OUTBOUND or INBOUND_DELEGATION",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	d := _pf_r53r_str(p, "Direction")
	not d in {"INBOUND", "OUTBOUND", "INBOUND_DELEGATION"}
}
