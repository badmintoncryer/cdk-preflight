package cdk_preflight

import rego.v1

_pf_cf_methods_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-cachebehavior.html"

_pf_cf_methods_behaviors(name) := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior", "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index]), "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)

# CloudFront defaults AllowedMethods to GET/HEAD when the property is omitted,
# so an omitted AllowedMethods still constrains what may be cached.
_pf_cf_methods_allowed(b) := object.get(b.value, "AllowedMethods", ["GET", "HEAD"])

violation contains make_diag_full("pf-cloudfront-cached-methods-subset", "ERROR", name,
	sprintf("%s.CachedMethods", [b.path]),
	sprintf("CachedMethods contains %s, which is not in AllowedMethods %v", [method, allowed]),
	"Every method in CachedMethods must also appear in AllowedMethods",
	_pf_cf_methods_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_methods_behaviors(name)
	is_object(b.value)
	cached := object.get(b.value, "CachedMethods", null)
	is_array(cached)
	allowed := _pf_cf_methods_allowed(b)
	is_array(allowed)
	some method in cached
	not method in allowed
}
