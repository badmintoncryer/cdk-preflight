package cdk_preflight

import rego.v1

_pf_cf_cpconflict_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-cachebehavior.html"

_pf_cf_cpconflict_legacy := ["ForwardedValues", "MinTTL", "MaxTTL", "DefaultTTL"]

_pf_cf_cpconflict_behaviors(name) := array.concat(
	[{"path": "Properties.DistributionConfig.DefaultCacheBehavior", "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.DefaultCacheBehavior")],
	[{"path": sprintf("Properties.DistributionConfig.CacheBehaviors.%d", [it.index]), "value": it.value} |
		some it in flatten_list(name, "Properties.DistributionConfig.CacheBehaviors")],
)

violation contains make_diag_full("pf-cloudfront-cache-policy-legacy-conflict", "ERROR", name,
	sprintf("%s.%s", [b.path, prop]),
	sprintf("%s cannot be used on a cache behavior that has a CachePolicyId", [prop]),
	"Move the setting into the cache policy (or the origin request policy) and drop the legacy property",
	_pf_cf_cpconflict_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cf_cpconflict_behaviors(name)
	is_object(b.value)
	policy := object.get(b.value, "CachePolicyId", null)
	is_string(policy)
	policy != ""
	some prop in _pf_cf_cpconflict_legacy
	object.get(b.value, prop, null) != null
}
