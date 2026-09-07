package cdk_preflight

import rego.v1

_pf_s3rmx_fix := "Drop the rule-level Prefix and express it as Filter.Prefix"

_pf_s3rmx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationrule.html"

violation contains make_diag_full("pf-s3-replication-v1-v2-mixed", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.Prefix", [rule.index]),
	"the rule sets both the V1 Prefix and the V2 Filter; S3 accepts one schema version per rule",
	_pf_s3rmx_fix, _pf_s3rmx_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	object.get(rule.value, "Prefix", "__pf_absent") != "__pf_absent"
	object.get(rule.value, "Filter", "__pf_absent") != "__pf_absent"
}
