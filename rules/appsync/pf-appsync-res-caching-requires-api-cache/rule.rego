package cdk_preflight

import rego.v1

# Judged only when the API is a sibling resource: a cache belongs to the API,
# so an API created here has to get its cache here too.
_pf_rescachingrequiresapicache_cached(api) if {
	some c in resources_of_type("AWS::AppSync::ApiCache")
	resolve(c, "Properties.ApiId") == api
}

violation contains make_diag_full("pf-appsync-res-caching-requires-api-cache", "ERROR", name,
	"Properties.CachingConfig",
	sprintf("CachingConfig is set but API '%s' has no AWS::AppSync::ApiCache in this template; the resolver create fails because there is no cache to configure", [api]),
	"Add an AWS::AppSync::ApiCache for the API, or drop CachingConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	is_object(resolve(name, "Properties.CachingConfig"))
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::AppSync::GraphQLApi")
	not _pf_rescachingrequiresapicache_cached(api)
}
