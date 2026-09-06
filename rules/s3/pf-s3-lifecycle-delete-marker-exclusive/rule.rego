package cdk_preflight

import rego.v1

_pf_s3ldx_fix := "Put ExpiredObjectDeleteMarker in its own untagged rule"

_pf_s3ldx_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

violation contains make_diag_full("pf-s3-lifecycle-delete-marker-exclusive", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ExpiredObjectDeleteMarker", [rule.index]),
	sprintf("ExpiredObjectDeleteMarker is set together with %v; S3 rejects that combination", [k]),
	_pf_s3ldx_fix, _pf_s3ldx_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	object.get(rule.value, "ExpiredObjectDeleteMarker", false) == true
	some k in ["ExpirationInDays", "ExpirationDate", "TagFilters"]
	object.get(rule.value, k, "__pf_absent") != "__pf_absent"
}
