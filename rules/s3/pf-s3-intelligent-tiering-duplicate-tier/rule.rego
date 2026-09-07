package cdk_preflight

import rego.v1

_pf_s3itt_fix := "Declare each access tier at most once per configuration"

_pf_s3itt_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-intelligenttieringconfiguration.html"

violation contains make_diag_full("pf-s3-intelligent-tiering-duplicate-tier", "ERROR", name,
	sprintf("Properties.IntelligentTieringConfigurations.%d.Tierings", [c.index]),
	sprintf("access tier '%v' appears more than once in the same configuration", [tier]),
	_pf_s3itt_fix, _pf_s3itt_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some c in flatten_list(name, "Properties.IntelligentTieringConfigurations")
	is_object(c.value)
	tiers := object.get(c.value, "Tierings", [])
	is_array(tiers)
	some i, j
	tiers[i]
	tiers[j]
	i < j
	is_object(tiers[i])
	is_object(tiers[j])
	tier := object.get(tiers[i], "AccessTier", "")
	tier != ""
	tier == object.get(tiers[j], "AccessTier", "")
}
