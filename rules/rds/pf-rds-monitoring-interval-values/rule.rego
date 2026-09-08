package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-monitoring-interval-values", "ERROR", name,
	"Properties.MonitoringInterval",
	sprintf("MonitoringInterval %v is not one of 0/1/5/10/15/30/60 (\"Invalid monitoring interval, please enter a value in [0, 1, 5, 10, 15, 30, 60]\")", [n]),
	"Use 0, 1, 5, 10, 15, 30 or 60",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	n := to_number(resolve(name, "Properties.MonitoringInterval"))
	not n in {0, 1, 5, 10, 15, 30, 60}
}

violation contains make_diag_full("pf-rds-monitoring-interval-values", "ERROR", name,
	"Properties.MonitoringInterval",
	sprintf("MonitoringInterval %v is not one of 0/1/5/10/15/30/60 (\"Invalid monitoring interval, please enter a value in [0, 1, 5, 10, 15, 30, 60]\")", [n]),
	"Use 0, 1, 5, 10, 15, 30 or 60",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	n := to_number(resolve(name, "Properties.MonitoringInterval"))
	not n in {0, 1, 5, 10, 15, 30, 60}
}
