package cdk_preflight

import rego.v1

_pf_cachettlrange_bad(t) if t < 1

_pf_cachettlrange_bad(t) if t > 3600

violation contains make_diag_full("pf-appsync-cache-ttl-range", "ERROR", name,
	"Properties.Ttl",
	sprintf("Ttl is %v; the cache create fails because the TTL has to be between 1 and 3600 seconds", [t]),
	"Use a TTL between 1 and 3600 seconds",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateApiCache.html") if {
	some name in resources_of_type("AWS::AppSync::ApiCache")
	t := to_number(resolve(name, "Properties.Ttl"))
	_pf_cachettlrange_bad(t)
}
