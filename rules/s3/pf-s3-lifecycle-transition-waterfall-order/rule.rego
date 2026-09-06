package cdk_preflight

import rego.v1

_pf_s3lwf_fix := "Order the transitions STANDARD -> STANDARD_IA -> INTELLIGENT_TIERING -> ONEZONE_IA -> GLACIER_IR -> GLACIER -> DEEP_ARCHIVE"

_pf_s3lwf_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html"

violation contains make_diag_full("pf-s3-lifecycle-transition-waterfall-order", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [rule.index]),
	sprintf("the rule transitions to '%v' at %v days and then to '%v' at %v days; S3 transitions follow a waterfall and never move back up", [sc1, d1, sc2, d2]),
	_pf_s3lwf_fix, _pf_s3lwf_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	trans := object.get(rule.value, "Transitions", [])
	is_array(trans)
	some t1 in trans
	some t2 in trans
	is_object(t1)
	is_object(t2)
	sc1 := object.get(t1, "StorageClass", "")
	sc2 := object.get(t2, "StorageClass", "")
	raw1 := object.get(t1, "TransitionInDays", null)
	raw1 != null
	raw2 := object.get(t2, "TransitionInDays", null)
	raw2 != null
	d1 := to_number(raw1)
	d2 := to_number(raw2)
	d1 < d2
	_pf_s3lib_rank[sc2] <= _pf_s3lib_rank[sc1]
}
