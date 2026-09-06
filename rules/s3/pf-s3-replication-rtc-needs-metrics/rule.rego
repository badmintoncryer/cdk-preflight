package cdk_preflight

import rego.v1

_pf_s3rrm_fix := "Set Destination.ReplicationTime and Destination.Metrics together"

_pf_s3rrm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationtime.html"

violation contains make_diag_full("pf-s3-replication-rtc-needs-metrics", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Destination.%v", [rule.index, present]),
	sprintf("Destination sets %v without %v; Replication Time Control requires both blocks", [present, missing]),
	_pf_s3rrm_fix, _pf_s3rrm_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	d := object.get(rule.value, "Destination", {})
	is_object(d)
	some pair in [["ReplicationTime", "Metrics"], ["Metrics", "ReplicationTime"]]
	present := pair[0]
	missing := pair[1]
	object.get(d, present, "__pf_absent") != "__pf_absent"
	object.get(d, missing, "__pf_absent") == "__pf_absent"
}
