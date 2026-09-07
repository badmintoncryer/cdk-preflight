package cdk_preflight

import rego.v1

_pf_s3los_fix := "Set ObjectSizeGreaterThan below ObjectSizeLessThan so the size range is not empty"

_pf_s3los_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

violation contains make_diag_full("pf-s3-lifecycle-object-size-order", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeGreaterThan", [rule.index]),
	sprintf("ObjectSizeGreaterThan (%v) is not smaller than ObjectSizeLessThan (%v); the rule would match no object", [gt, lt]),
	_pf_s3los_fix, _pf_s3los_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	rawg := object.get(rule.value, "ObjectSizeGreaterThan", null)
	rawg != null # to_number(null) is 0
	rawl := object.get(rule.value, "ObjectSizeLessThan", null)
	rawl != null
	gt := to_number(rawg)
	lt := to_number(rawl)
	gt >= lt
}
