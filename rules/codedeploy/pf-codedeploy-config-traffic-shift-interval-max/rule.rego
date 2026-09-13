package cdk_preflight

import rego.v1

# The cap is on the whole shift, not on one wait. A canary waits once, so its
# ceiling is the interval itself. A linear configuration waits
# floor(100 / LinearPercentage) times, so the interval that fits shrinks as the
# step does - measured 2026-09-14 us-east-1: 2880x99%, 1440x50%, 960x33%,
# 288x10% and 28x1% are accepted and one minute more on any of them is not.
_pf_cdtsi_shifts(pct) := floor(100 / pct)

violation contains make_diag_full("pf-codedeploy-config-traffic-shift-interval-max", "ERROR", name,
	"Properties.TrafficRoutingConfig.TimeBasedCanary.CanaryInterval",
	sprintf("CanaryInterval is %v minutes; the deployment configuration create fails with \"Canary interval must be between 1 and 2880 minutes (2 days)\"", [civ]),
	"Wait at most 2880 minutes (2 days) before shifting the rest of the traffic",
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/limits.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	civ := _pf_codedeploylib_num(resolve(name, "Properties.TrafficRoutingConfig.TimeBasedCanary.CanaryInterval"))
	civ > 2880
}

violation contains make_diag_full("pf-codedeploy-config-traffic-shift-interval-max", "ERROR", name,
	"Properties.TrafficRoutingConfig.TimeBasedLinear.LinearInterval",
	sprintf("Shifting %v percent every %v minutes takes %v minutes end to end; the deployment configuration create fails with \"Total Traffic shifting intervals must be positive integers up to 2880 minutes (2 days)\"", [pct, liv, total]),
	"Keep LinearInterval x floor(100 / LinearPercentage) at or below 2880 minutes (2 days)",
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/limits.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	liv := _pf_codedeploylib_num(resolve(name, "Properties.TrafficRoutingConfig.TimeBasedLinear.LinearInterval"))
	pct := _pf_codedeploylib_num(resolve(name, "Properties.TrafficRoutingConfig.TimeBasedLinear.LinearPercentage"))
	pct > 0
	total := liv * _pf_cdtsi_shifts(pct)
	total > 2880
}
