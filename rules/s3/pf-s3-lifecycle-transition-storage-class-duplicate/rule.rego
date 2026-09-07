package cdk_preflight

import rego.v1

_pf_s3lsc_fix := "Keep one transition per storage class, or split the rule"

_pf_s3lsc_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html"

violation contains make_diag_full("pf-s3-lifecycle-transition-storage-class-duplicate", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [rule.index]),
	sprintf("the rule transitions to '%v' more than once; a storage class may appear only once per rule", [sc]),
	_pf_s3lsc_fix, _pf_s3lsc_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	trans := object.get(rule.value, "Transitions", [])
	is_array(trans)
	some i, j
	trans[i]
	trans[j]
	i < j
	is_object(trans[i])
	is_object(trans[j])
	sc := object.get(trans[i], "StorageClass", "")
	sc != ""
	sc == object.get(trans[j], "StorageClass", "")
}
