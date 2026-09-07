package cdk_preflight

import rego.v1

_pf_s3ldm_fix := "Express every action in the rule with days, or every action with dates"

_pf_s3ldm_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

_pf_s3ldm_days(rv) if {
	object.get(rv, "ExpirationInDays", "__pf_absent") != "__pf_absent"
}

_pf_s3ldm_days(rv) if {
	tl := object.get(rv, "Transitions", [])
	is_array(tl)
	some t in tl
	is_object(t)
	object.get(t, "TransitionInDays", "__pf_absent") != "__pf_absent"
}

_pf_s3ldm_date(rv) if {
	object.get(rv, "ExpirationDate", "__pf_absent") != "__pf_absent"
}

_pf_s3ldm_date(rv) if {
	tl := object.get(rv, "Transitions", [])
	is_array(tl)
	some t in tl
	is_object(t)
	object.get(t, "TransitionDate", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-s3-lifecycle-date-days-mix", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d", [rule.index]),
	"the rule mixes day-based and date-based actions; every action in one rule must use the same time unit",
	_pf_s3ldm_fix, _pf_s3ldm_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	_pf_s3ldm_days(rule.value)
	_pf_s3ldm_date(rule.value)
}
