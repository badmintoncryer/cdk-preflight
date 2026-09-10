package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-doh-dohfips-exclusive", "ERROR", name,
	"Properties.Protocols",
	"the endpoint declares both DoH and DoH-FIPS; a Resolver endpoint can only have one of them",
	"Keep either DoH or DoH-FIPS, not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	pr := _pf_r53r_protos(p)
	"DoH" in pr
	"DoH-FIPS" in pr
}
