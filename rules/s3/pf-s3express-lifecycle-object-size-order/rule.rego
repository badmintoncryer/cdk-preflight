package cdk_preflight

import rego.v1

_pf_s3xlsz_fix := "Set ObjectSizeGreaterThan below ObjectSizeLessThan so the size range is not empty"

_pf_s3xlsz_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3express-directorybucket-rule.html"

violation contains make_diag_full("pf-s3express-lifecycle-object-size-order", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ObjectSizeGreaterThan", [r.index]),
	sprintf("ObjectSizeGreaterThan (%v) is not smaller than ObjectSizeLessThan (%v); the rule would match no object", [gt, lt]),
	_pf_s3xlsz_fix, _pf_s3xlsz_url) if {
	some name in resources_of_type("AWS::S3Express::DirectoryBucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	rawg := object.get(r.value, "ObjectSizeGreaterThan", null)
	rawg != null # to_number(null) is 0
	rawl := object.get(r.value, "ObjectSizeLessThan", null)
	rawl != null
	gt := to_number(rawg)
	lt := to_number(rawl)
	gt >= lt
}
