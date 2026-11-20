package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-elasticache-serverless-public-valkey9", "ERROR", name,
	"Properties.MajorEngineVersion",
	sprintf("ConnectionType public with valkey %v; the cache create fails with \"Engine version 9 or higher is required for connectionType PUBLIC\"", [v]),
	"Set MajorEngineVersion to 9 or later (or omit it), or drop ConnectionType public",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticache-serverlesscache.html") if {
	some name in resources_of_type("AWS::ElastiCache::ServerlessCache")
	_pf_ecpub_v9(name)
	eng := resolve(name, "Properties.Engine")
	is_string(eng)
	lower(eng) == "valkey"
	v := _pf_num(name, "Properties.MajorEngineVersion")
	v < 9
}

_pf_ecpub_v9(name) if {
	ct := resolve(name, "Properties.ConnectionType")
	is_string(ct)
	lower(ct) == "public"
}
