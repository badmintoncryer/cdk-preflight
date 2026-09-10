package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-ipv6-internet-access-outbound-only", "ERROR", name,
	"Properties.Ipv6InternetAccessEnabled",
	"the inbound endpoint sets Ipv6InternetAccessEnabled; it is an outbound-endpoint feature",
	"Drop Ipv6InternetAccessEnabled, or move it to an outbound endpoint",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_get(p, "Ipv6InternetAccessEnabled") == true
	_pf_r53r_str(p, "Direction") == "INBOUND"
}
