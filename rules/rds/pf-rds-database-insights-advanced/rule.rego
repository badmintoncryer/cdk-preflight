package cdk_preflight

import rego.v1

_pf_rdsadv_bad(name) if not _pf_rds_true(name, "PerformanceInsightsEnabled")

_pf_rdsadv_bad(name) if not _pf_rds_has(name, "PerformanceInsightsRetentionPeriod")

_pf_rdsadv_bad(name) if {
	n := to_number(resolve(name, "Properties.PerformanceInsightsRetentionPeriod"))
	n < 31
}

violation contains make_diag_full("pf-rds-database-insights-advanced", "ERROR", name,
	"Properties.DatabaseInsightsMode",
	"DatabaseInsightsMode: advanced without Performance Insights enabled and a retention period of at least 31 days (\"You can't enable the Advanced mode of Database Insights until you enable Performance Insights and set the retention period for Performance Insights to at least 31 days.\")",
	"Set PerformanceInsightsEnabled: true and PerformanceInsightsRetentionPeriod >= 31",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	resolve(name, "Properties.DatabaseInsightsMode") == "advanced"
	_pf_rdsadv_bad(name)
}
