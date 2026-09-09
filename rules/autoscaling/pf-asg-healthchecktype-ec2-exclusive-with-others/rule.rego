package cdk_preflight

import rego.v1

_pf_asghce_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-healthchecktype-ec2-exclusive-with-others", "ERROR", name,
	"Properties.HealthCheckType",
	sprintf("HealthCheckType '%s' lists EC2 alongside another check; EC2 is implied by every other type and the group create fails with \"Specifying EC2 in addition to other health check types is not supported\"", [v]),
	"Drop EC2 from the list; the remaining types already include it", _pf_asghce_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	v := resolve(name, "Properties.HealthCheckType")
	_pf_aslib_lit(v)
	parts := [x | some x in split(v, ","); x != ""]
	count(parts) > 1
	some p in parts
	p == "EC2"
}
