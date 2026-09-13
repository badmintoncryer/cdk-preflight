package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-cache-type-deprecated-instance", "ERROR", name,
	"Properties.Type",
	sprintf("cache type '%s' belongs to a retired generation; the cache create fails because AppSync no longer provisions T2 or R4 cache instances", [t]),
	"Use a current generation type (SMALL, MEDIUM, LARGE, XLARGE, LARGE_2X, LARGE_4X, LARGE_8X, LARGE_12X)",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateApiCache.html") if {
	some name in resources_of_type("AWS::AppSync::ApiCache")
	t := resolve(name, "Properties.Type")
	is_string(t)
	regex.match(`^(T2_|R4_)`, t)
}
