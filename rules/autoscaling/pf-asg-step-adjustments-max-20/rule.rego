package cdk_preflight

import rego.v1

_pf_asgstmx_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-adjustments-max-20", "ERROR", name,
	"Properties.StepAdjustments",
	sprintf("the policy has %d StepAdjustments; the fixed quota is 20 and the policy create fails with \"Your policies can have at most 20 StepAdjustments\"", [n]),
	"Merge steps so at most 20 remain, or split the policy in two", _pf_asgstmx_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := count(_pf_aslib_steps(name))
	n > 20
}
