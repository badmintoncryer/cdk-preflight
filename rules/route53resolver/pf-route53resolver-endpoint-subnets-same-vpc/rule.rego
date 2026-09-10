package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-subnets-same-vpc", "ERROR", name,
	"Properties.IpAddresses",
	"IpAddresses points at subnets in more than one VPC; a Resolver endpoint lives in a single VPC",
	"Use subnets from one VPC, or create one endpoint per VPC",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-resolverendpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	vpcs := {v |
		some s in _pf_r53r_subnets(p)
		v := _pf_r53r_key(_pf_r53r_props(s), "VpcId")
	}
	count(vpcs) > 1
}
