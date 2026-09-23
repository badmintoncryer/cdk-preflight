package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-eventsub-sourceids-need-sourcetype", "ERROR", name,
	"Properties.SourceIds",
	"SourceIds is set without SourceType (\"If SourceType is null, SourceId must also be null.\")",
	"Set SourceType (e.g. db-cluster), or drop SourceIds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-eventsubscription.html") if {
	some name in resources_of_type("AWS::DocDB::EventSubscription")
	ids := _pf_docdb_get(name, "SourceIds")
	is_array(ids)
	count(ids) > 0
	not _pf_docdb_has(name, "SourceType")
}
