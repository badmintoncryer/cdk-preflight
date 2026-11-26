package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-elasticache-serverless-public-valkey-only", "ERROR", name,
	"Properties.ConnectionType",
	sprintf("ConnectionType public with engine %v; the cache create fails with \"Public connection type is only supported for the valkey engine\"", [eng]),
	"Use Engine valkey (major version 9 or later) or drop ConnectionType public",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-serverlesscache.html") if {
	some name in resources_of_type("AWS::ElastiCache::ServerlessCache")
	_pf_ecpub_vo(name)
	eng := resolve(name, "Properties.Engine")
	is_string(eng)
	not input.resources[eng]
	lower(eng) != "valkey"
}

_pf_ecpub_vo(name) if {
	ct := resolve(name, "Properties.ConnectionType")
	is_string(ct)
	not input.resources[ct]
	lower(ct) == "public"
}
