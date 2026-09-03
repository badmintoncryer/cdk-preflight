package cdk_preflight

import rego.v1

# Equality is rejected too (benched): the requirement is strictly less.
violation contains make_diag_full("pf-elbv2-hc-timeout-interval", "ERROR", name,
	"Properties.HealthCheckTimeoutSeconds",
	sprintf("HealthCheckTimeoutSeconds %v is not smaller than HealthCheckIntervalSeconds %v (\"Health check timeout '%v' must be smaller than the interval '%v'\")", [t, i, t, i]),
	"Keep the timeout strictly below the interval",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	t := to_number(resolve(name, "Properties.HealthCheckTimeoutSeconds"))
	i := to_number(resolve(name, "Properties.HealthCheckIntervalSeconds"))
	t >= i
}
