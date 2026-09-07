package cdk_preflight

import rego.v1

_pf_s3ltk_fix := "Use each tag key at most once per lifecycle rule"

_pf_s3ltk_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

violation contains make_diag_full("pf-s3-lifecycle-tag-key-duplicate", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.TagFilters", [rule.index]),
	sprintf("tag key '%v' appears twice in the same filter; S3 ANDs the filter tags and rejects a repeated key", [key]),
	_pf_s3ltk_fix, _pf_s3ltk_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	tags := object.get(rule.value, "TagFilters", [])
	is_array(tags)
	some i, j
	tags[i]
	tags[j]
	i < j
	is_object(tags[i])
	is_object(tags[j])
	key := object.get(tags[i], "Key", "")
	key != ""
	key == object.get(tags[j], "Key", "")
}
