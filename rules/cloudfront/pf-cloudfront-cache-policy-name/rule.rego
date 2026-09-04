package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudfront-cache-policy-name", "ERROR", name,
	"Properties.CachePolicyConfig.Name",
	sprintf("CachePolicyConfig.Name '%s' is rejected by the service: alphanumerics, dash and underscore", [v]),
	"Rename it to satisfy alphanumerics, dash and underscore",
	"https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CreateCachePolicy.html") if {
	some name in resources_of_type("AWS::CloudFront::CachePolicy")
	v := resolve(name, "Properties.CachePolicyConfig.Name")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]+$`, v)
}
