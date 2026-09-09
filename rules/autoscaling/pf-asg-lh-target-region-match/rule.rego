package cdk_preflight

import rego.v1

_pf_asglhrm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

violation contains make_diag_full("pf-asg-lh-target-region-match", "ERROR", name,
	"Properties.NotificationTargetARN",
	sprintf("the notification target is in %s but the group deploys to %s; Auto Scaling can only reach a target in its own region and the hook create fails with \"Unable to publish test message to notification target\"", [r, data.cdk_preflight.deploy_region]),
	"Use a topic or queue in the same region as the Auto Scaling group", _pf_asglhrm_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	v := resolve(name, "Properties.NotificationTargetARN")
	_pf_aslib_arn_service(v) in ["sns", "sqs"]
	r := _pf_aslib_arn_region(v)
	r != data.cdk_preflight.deploy_region
}
