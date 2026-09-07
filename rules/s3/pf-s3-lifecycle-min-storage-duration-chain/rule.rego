package cdk_preflight

import rego.v1

_pf_s3lmd_fix := "Leave at least the minimum storage duration (90 days for GLACIER_IR and GLACIER) between the two transitions"

_pf_s3lmd_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html"

violation contains make_diag_full("pf-s3-lifecycle-min-storage-duration-chain", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [rule.index]),
	sprintf("the transition to '%v' at %v days leaves '%v' after only %v days, but '%v' bills a %v day minimum storage duration", [sc2, d2, sc1, d2 - d1, sc1, mind]),
	_pf_s3lmd_fix, _pf_s3lmd_url) if {
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
	mind := _pf_s3lib_mindur[sc1]
	_pf_s3lib_rank[sc2] > _pf_s3lib_rank[sc1]
	raw1 := object.get(t1, "TransitionInDays", null)
	raw1 != null
	raw2 := object.get(t2, "TransitionInDays", null)
	raw2 != null
	d1 := to_number(raw1)
	d2 := to_number(raw2)
	d2 - d1 < mind
}
