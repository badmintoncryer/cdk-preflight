package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-cache-health-metrics-value", "ERROR", name,
	"Properties.HealthMetricsConfig",
	sprintf("HealthMetricsConfig '%s' is not one of ENABLED, DISABLED; the cache create rejects the value", [v]),
	"Use one of ENABLED, DISABLED",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateApiCache.html") if {
	some name in resources_of_type("AWS::AppSync::ApiCache")
	v := resolve(name, "Properties.HealthMetricsConfig")
	is_string(v)
	not v in {"ENABLED", "DISABLED"}
}
