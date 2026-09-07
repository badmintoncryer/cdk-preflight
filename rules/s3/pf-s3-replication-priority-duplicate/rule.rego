package cdk_preflight

import rego.v1

_pf_s3rpd_fix := "Give every replication rule its own Priority"

_pf_s3rpd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationrule.html"

violation contains make_diag_full("pf-s3-replication-priority-duplicate", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Priority", [r2.index]),
	sprintf("priority %v is already used by rule %d; replication priorities must be unique", [p, r1.index]),
	_pf_s3rpd_fix, _pf_s3rpd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r1 in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	some r2 in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	r1.index < r2.index
	is_object(r1.value)
	is_object(r2.value)
	raw := object.get(r1.value, "Priority", null)
	raw != null
	p := to_number(raw)
	other := object.get(r2.value, "Priority", null)
	other != null
	p == to_number(other)
}
