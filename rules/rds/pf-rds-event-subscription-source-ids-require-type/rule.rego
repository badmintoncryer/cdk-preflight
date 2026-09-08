package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-event-subscription-source-ids-require-type", "ERROR", name,
	"Properties.SourceIds",
	"SourceIds is set without SourceType (\"If SourceType is null, SourceId must also be null.\")",
	"Set SourceType, or drop SourceIds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-eventsubscription.html") if {
	some name in resources_of_type("AWS::RDS::EventSubscription")
	_pf_rds_has(name, "SourceIds")
	not _pf_rds_has(name, "SourceType")
}
