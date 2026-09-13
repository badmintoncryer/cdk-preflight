package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-api-enhanced-metrics-values", "ERROR", name,
	"Properties.EnhancedMetricsConfig.DataSourceLevelMetricsBehavior",
	sprintf("DataSourceLevelMetricsBehavior '%s' is not FULL_REQUEST_DATA_SOURCE_METRICS or PER_DATA_SOURCE_METRICS; the API create rejects the value", [v]),
	"Use FULL_REQUEST_DATA_SOURCE_METRICS or PER_DATA_SOURCE_METRICS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-graphqlapi-enhancedmetricsconfig.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	v := resolve(name, "Properties.EnhancedMetricsConfig.DataSourceLevelMetricsBehavior")
	is_string(v)
	not v in {"FULL_REQUEST_DATA_SOURCE_METRICS", "PER_DATA_SOURCE_METRICS"}
}
