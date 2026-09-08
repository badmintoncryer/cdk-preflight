package cdk_preflight

import rego.v1

_pf_rdspien_off(name) if not _pf_rds_has(name, "EnablePerformanceInsights")

_pf_rdspien_off(name) if _pf_rds_false(name, "EnablePerformanceInsights")

violation contains make_diag_full("pf-rds-pi-retention-requires-enable", "ERROR", name,
	"Properties.PerformanceInsightsRetentionPeriod",
	"PerformanceInsightsRetentionPeriod is set without EnablePerformanceInsights: true (\"To enable Performance Insights, EnablePerformanceInsights must be set to 'true'\")",
	"Set EnablePerformanceInsights: true, or drop the retention period",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_has(name, "PerformanceInsightsRetentionPeriod")
	_pf_rdspien_off(name)
}
