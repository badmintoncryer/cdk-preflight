package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-monitoring-role-required", "ERROR", name,
	"Properties.MonitoringInterval",
	sprintf("MonitoringInterval %v needs MonitoringRoleArn (\"A MonitoringRoleARN value is required if you specify a MonitoringInterval value other than 0.\")", [n]),
	"Set MonitoringRoleArn, or MonitoringInterval to 0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	n := to_number(resolve(name, "Properties.MonitoringInterval"))
	n != 0
	_pf_rds_has(name, "MonitoringInterval")
	not _pf_rds_has(name, "MonitoringRoleArn")
}

violation contains make_diag_full("pf-rds-monitoring-role-required", "ERROR", name,
	"Properties.MonitoringInterval",
	sprintf("MonitoringInterval %v needs MonitoringRoleArn (\"A MonitoringRoleARN value is required if you specify a MonitoringInterval value other than 0.\")", [n]),
	"Set MonitoringRoleArn, or MonitoringInterval to 0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	n := to_number(resolve(name, "Properties.MonitoringInterval"))
	n != 0
	_pf_rds_has(name, "MonitoringInterval")
	not _pf_rds_has(name, "MonitoringRoleArn")
}
