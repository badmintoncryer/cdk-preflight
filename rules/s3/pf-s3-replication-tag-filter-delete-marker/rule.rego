package cdk_preflight

import rego.v1

_pf_s3rtd_fix := "Set DeleteMarkerReplication.Status to Disabled on rules whose filter includes a tag"

_pf_s3rtd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-replicationrule.html"

_pf_s3rtd_tagged(f) if {
	object.get(f, "TagFilter", "__pf_absent") != "__pf_absent"
}

_pf_s3rtd_tagged(f) if {
	a := object.get(f, "And", {})
	is_object(a)
	object.get(a, "TagFilters", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-s3-replication-tag-filter-delete-marker", "ERROR", name,
	sprintf("Properties.ReplicationConfiguration.Rules.%d.DeleteMarkerReplication.Status", [rule.index]),
	"the rule filters by tag, so DeleteMarkerReplication.Status must be Disabled; S3 does not replicate delete markers for tag-based rules",
	_pf_s3rtd_fix, _pf_s3rtd_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some rule in flatten_list(name, "Properties.ReplicationConfiguration.Rules")
	is_object(rule.value)
	f := object.get(rule.value, "Filter", {})
	is_object(f)
	_pf_s3rtd_tagged(f)
	d := object.get(rule.value, "DeleteMarkerReplication", {})
	is_object(d)
	object.get(d, "Status", "") == "Enabled"
}
