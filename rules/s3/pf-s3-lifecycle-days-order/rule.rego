package cdk_preflight

import rego.v1

_pf_s3ord_fix := "Order the lifecycle days so archive transitions come at least 30 days after IA transitions and expiration comes after every transition"

_pf_s3ord_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html"

violation contains make_diag_full("pf-s3-lifecycle-days-order", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [r.index]),
	sprintf("Transition to %s at %v days is less than 30 days after the %s transition at %v days; S3 requires objects to stay at least 30 days in IA storage", [sc2, d2, sc1, d1]),
	_pf_s3ord_fix, _pf_s3ord_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	trans := object.get(r.value, "Transitions", [])
	is_array(trans)
	some t1 in trans
	is_object(t1)
	sc1 := object.get(t1, "StorageClass", "")
	sc1 in {"STANDARD_IA", "ONEZONE_IA"}
	raw1 := object.get(t1, "TransitionInDays", null)
	raw1 != null # to_number(null) は 0 になる
	d1 := to_number(raw1)
	some t2 in trans
	is_object(t2)
	sc2 := object.get(t2, "StorageClass", "")
	sc2 in {"GLACIER", "DEEP_ARCHIVE"}
	raw2 := object.get(t2, "TransitionInDays", null)
	raw2 != null
	d2 := to_number(raw2)
	d2 < d1 + 30
}

violation contains make_diag_full("pf-s3-lifecycle-days-order", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ExpirationInDays", [r.index]),
	sprintf("ExpirationInDays (%v) must be greater than TransitionInDays (%v); S3 rejects lifecycle rules that expire objects before or when they transition", [e, d]),
	_pf_s3ord_fix, _pf_s3ord_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(r.value)
	rawe := object.get(r.value, "ExpirationInDays", null)
	rawe != null # to_number(null) は 0 になる
	e := to_number(rawe)
	trans := object.get(r.value, "Transitions", [])
	is_array(trans)
	some t in trans
	is_object(t)
	rawd := object.get(t, "TransitionInDays", null)
	rawd != null
	d := to_number(rawd)
	e <= d
}
