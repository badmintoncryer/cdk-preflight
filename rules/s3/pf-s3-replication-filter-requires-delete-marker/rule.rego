package cdk_preflight

import rego.v1

_pf_s3rfd_fix := "Add Priority and DeleteMarkerReplication to every replication rule that uses Filter"

_pf_s3rfd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationrule.html"

violation contains make_diag_full("pf-s3-replication-filter-requires-delete-marker", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.%v", [rule.index, k]),
	sprintf("the rule uses Filter (schema V2) but omits %v; V2 rules must carry both Priority and DeleteMarkerReplication", [k]),
	_pf_s3rfd_fix, _pf_s3rfd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	object.get(rule.value, "Filter", "__pf_absent") != "__pf_absent"
	some k in ["Priority", "DeleteMarkerReplication"]
	object.get(rule.value, k, "__pf_absent") == "__pf_absent"
}
