package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-type-enum", "ERROR", name,
	"Properties.ResolverEndpointType",
	sprintf("ResolverEndpointType is '%s'; Route 53 Resolver only accepts IPV4, IPV6 or DUALSTACK", [t]),
	"Set ResolverEndpointType to IPV4, IPV6 or DUALSTACK",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	t := _pf_r53r_str(p, "ResolverEndpointType")
	not t in {"IPV4", "IPV6", "DUALSTACK"}
}
