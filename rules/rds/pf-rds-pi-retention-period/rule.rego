package cdk_preflight

import rego.v1

_pf_rdspi_ok(n) if n == 7

_pf_rdspi_ok(n) if n == 731

_pf_rdspi_ok(n) if {
	k := round(n / 31)
	k >= 1
	k <= 23
	n == k * 31
}

violation contains make_diag_full("pf-rds-pi-retention-period", "ERROR", name,
	"Properties.PerformanceInsightsRetentionPeriod",
	sprintf("PerformanceInsightsRetentionPeriod %v is not a valid retention (\"Invalid Performance Insights retention period. Valid values are: [7, 31, 62, ... 731]\")", [n]),
	"Use 7, 731, or a multiple of 31 (31-713)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	n := to_number(resolve(name, "Properties.PerformanceInsightsRetentionPeriod"))
	not _pf_rdspi_ok(n)
}
