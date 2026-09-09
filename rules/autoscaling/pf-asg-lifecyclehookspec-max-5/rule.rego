package cdk_preflight

import rego.v1

_pf_asgihm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-lifecyclehookspec-max-5", "ERROR", name,
	"Properties.LifecycleHookSpecificationList",
	sprintf("the group declares %d inline lifecycle hooks; CreateAutoScalingGroup takes at most 5 (the 50-per-group quota applies to hooks added one at a time afterwards) and the create fails with \"You cannot specify more than 5 hooks\"", [n]),
	"Keep five hooks inline and add the rest as AWS::AutoScaling::LifecycleHook resources", _pf_asgihm_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := count(_pf_aslib_hooks(name))
	n > 5
}
