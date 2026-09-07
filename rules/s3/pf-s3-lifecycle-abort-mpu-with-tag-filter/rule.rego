package cdk_preflight

import rego.v1

_pf_s3lab_fix := "Move AbortIncompleteMultipartUpload into a rule that filters by prefix only"

_pf_s3lab_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

violation contains make_diag_full("pf-s3-lifecycle-abort-mpu-with-tag-filter", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.AbortIncompleteMultipartUpload", [rule.index]),
	"AbortIncompleteMultipartUpload is set on a rule that filters by tag; S3 supports the abort action only on prefix-filtered rules",
	_pf_s3lab_fix, _pf_s3lab_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	object.get(rule.value, "AbortIncompleteMultipartUpload", "__pf_absent") != "__pf_absent"
	tags := object.get(rule.value, "TagFilters", [])
	is_array(tags)
	count(tags) > 0
}
