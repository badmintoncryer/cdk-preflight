package cdk_preflight

import rego.v1

_pf_s3rm15_fix := "Set the ReplicationTime and Metrics thresholds to 15 minutes"

_pf_s3rm15_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationtime.html"

violation contains make_diag_full("pf-s3-replication-rtc-minutes-15", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.%v", [rule.index, spot[0]]),
	sprintf("%v.%v.Minutes is %v; S3 accepts only 15", [spot[0], spot[1], m]),
	_pf_s3rm15_fix, _pf_s3rm15_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	d := object.get(rule.value, "Destination", {})
	is_object(d)
	some spot in [["ReplicationTime", "Time"], ["Metrics", "EventThreshold"]]
	outer := object.get(d, spot[0], {})
	is_object(outer)
	inner := object.get(outer, spot[1], {})
	is_object(inner)
	raw := object.get(inner, "Minutes", null)
	raw != null
	m := to_number(raw)
	m != 15
}
