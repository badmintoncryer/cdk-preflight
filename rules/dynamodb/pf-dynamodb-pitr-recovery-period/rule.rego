package cdk_preflight

import rego.v1

_pf_ddbprp_disabled(p) if object.get(p, "PointInTimeRecoveryEnabled", null) == false

_pf_ddbprp_disabled(p) if object.get(p, "PointInTimeRecoveryEnabled", "__pf_absent") == "__pf_absent"

violation contains make_diag_full("pf-dynamodb-pitr-recovery-period", "ERROR", name,
	"Properties.PointInTimeRecoverySpecification.RecoveryPeriodInDays",
	"RecoveryPeriodInDays is set while point-in-time recovery is off; UpdateContinuousBackups fails with \"Cannot specify RecoveryPeriodInDays when disabling point-in-time recovery\"",
	"Set PointInTimeRecoveryEnabled to true, or drop RecoveryPeriodInDays",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-pointintimerecoveryspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	p := resolve(name, "Properties.PointInTimeRecoverySpecification")
	is_object(p)
	_pf_ddbprp_disabled(p)
	object.get(p, "RecoveryPeriodInDays", "__pf_absent") != "__pf_absent"
}
