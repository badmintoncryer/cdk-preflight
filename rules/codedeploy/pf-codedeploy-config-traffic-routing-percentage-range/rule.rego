package cdk_preflight

import rego.v1

# One check covers both blocks: the canary and the linear percentage go through
# the same validation and come back with the same message.
_pf_cdtrpct_bad(p) if p > 99

_pf_cdtrpct_bad(p) if p < 1

violation contains make_diag_full("pf-codedeploy-config-traffic-routing-percentage-range", "ERROR", name,
	sprintf("Properties.TrafficRoutingConfig.%v", [blk]),
	sprintf("%v is %v; the deployment configuration create fails with \"Valid traffic routing percentage is from 1 to 99\"", [blk, p]),
	"Shift between 1 and 99 percent of the traffic per step (100 percent at once is Type AllAtOnce)",
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/limits.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	some blk in ["TimeBasedCanary.CanaryPercentage", "TimeBasedLinear.LinearPercentage"]
	p := _pf_codedeploylib_num(resolve(name, sprintf("Properties.TrafficRoutingConfig.%v", [blk])))
	_pf_cdtrpct_bad(p)
}
