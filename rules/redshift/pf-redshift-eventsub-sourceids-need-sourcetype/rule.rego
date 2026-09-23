package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-eventsub-sourceids-need-sourcetype", "ERROR", name,
	"Properties.SourceIds",
	"SourceIds is set without SourceType; CreateEventSubscription rejects it (\"If SourceType is null, SourceId must also be null.\")",
	"Set SourceType (cluster, cluster-parameter-group, cluster-security-group, cluster-snapshot or scheduled-action), or drop SourceIds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-eventsubscription.html") if {
	some name in resources_of_type("AWS::Redshift::EventSubscription")
	ids := _pf_redshiftlib_get(name, "SourceIds")
	is_array(ids)
	count(ids) > 0
	not _pf_redshiftlib_has(name, "SourceType")
}
