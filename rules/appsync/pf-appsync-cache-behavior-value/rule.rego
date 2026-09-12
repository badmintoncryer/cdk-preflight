package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-cache-behavior-value", "ERROR", name,
	"Properties.ApiCachingBehavior",
	sprintf("ApiCachingBehavior '%s' is not one of FULL_REQUEST_CACHING, PER_RESOLVER_CACHING, OPERATION_LEVEL_CACHING; the cache create rejects the value", [v]),
	"Use one of FULL_REQUEST_CACHING, PER_RESOLVER_CACHING, OPERATION_LEVEL_CACHING",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-apicache.html") if {
	some name in resources_of_type("AWS::AppSync::ApiCache")
	v := resolve(name, "Properties.ApiCachingBehavior")
	is_string(v)
	not v in {"FULL_REQUEST_CACHING", "PER_RESOLVER_CACHING", "OPERATION_LEVEL_CACHING"}
}
