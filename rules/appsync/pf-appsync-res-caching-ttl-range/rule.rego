package cdk_preflight

import rego.v1

_pf_rescachingttlrange_bad(t) if t < 1

_pf_rescachingttlrange_bad(t) if t > 3600

violation contains make_diag_full("pf-appsync-res-caching-ttl-range", "ERROR", name,
	"Properties.CachingConfig.Ttl",
	sprintf("CachingConfig.Ttl is %v; the resolver create fails because the TTL has to be between 1 and 3600 seconds", [t]),
	"Use a TTL between 1 and 3600 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	t := to_number(resolve(name, "Properties.CachingConfig.Ttl"))
	_pf_rescachingttlrange_bad(t)
}
