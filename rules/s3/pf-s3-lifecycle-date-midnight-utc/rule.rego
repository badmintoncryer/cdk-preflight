package cdk_preflight

import rego.v1

_pf_s3lmn_fix := "Round the date to midnight UTC, e.g. 2030-01-01T00:00:00Z"

_pf_s3lmn_url := "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html"

_pf_s3lmn_bad(d) if {
	is_string(d)
	not endswith(d, "T00:00:00Z")
	not endswith(d, "T00:00:00.000Z")
}

violation contains make_diag_full("pf-s3-lifecycle-date-midnight-utc", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.ExpirationDate", [rule.index]),
	sprintf("ExpirationDate '%v' is not midnight UTC; S3 accepts lifecycle dates only at 00:00:00Z", [d]),
	_pf_s3lmn_fix, _pf_s3lmn_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	d := object.get(rule.value, "ExpirationDate", null)
	_pf_s3lmn_bad(d)
}

violation contains make_diag_full("pf-s3-lifecycle-date-midnight-utc", "ERROR", name,
	sprintf("Properties.LifecycleConfiguration.Rules.%d.Transitions", [rule.index]),
	sprintf("TransitionDate '%v' is not midnight UTC; S3 accepts lifecycle dates only at 00:00:00Z", [d]),
	_pf_s3lmn_fix, _pf_s3lmn_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.LifecycleConfiguration.Rules")
	is_object(rule.value)
	tl := object.get(rule.value, "Transitions", [])
	is_array(tl)
	some t in tl
	is_object(t)
	d := object.get(t, "TransitionDate", null)
	_pf_s3lmn_bad(d)
}
