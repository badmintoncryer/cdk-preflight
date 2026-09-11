package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-dns64-inbound-only", "ERROR", name,
	"Properties.Dns64Enabled",
	"the outbound endpoint sets Dns64Enabled; DNS64 is an inbound-endpoint feature",
	"Drop Dns64Enabled, or move it to an inbound endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_get(p, "Dns64Enabled") == true
	_pf_r53r_str(p, "Direction") == "OUTBOUND"
}
