package cdk_preflight

import rego.v1

_pf_asgoim40_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-overrides-instancetype-max-40", "ERROR", name,
	"Properties.MixedInstancesPolicy.LaunchTemplate.Overrides",
	sprintf("the mixed instances policy lists %d overrides; the group create fails with \"The number of LaunchTemplateOverrides must be fewer than 40\" (measured: 40 deploys, 41 does not)", [n]),
	"Keep at most 40 overrides, or switch to InstanceRequirements", _pf_asgoim40_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := count(_pf_aslib_overrides(name))
	n > 40
}
