package cdk_preflight

import rego.v1

_pf_asgncr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-notification-topic-cross-region-rejected", "ERROR", name,
	sprintf("Properties.NotificationConfigurations.%d.TopicARN", [i]),
	sprintf("the notification topic is in %s but the group deploys to %s; Auto Scaling publishes only to a topic in its own region and the group create fails with \"Invalid parameter: TopicArn\"", [r, data.cdk_preflight.deploy_region]),
	"Use an SNS topic in the same region as the group", _pf_asgncr_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, _ in _pf_aslib_arr(name, ["NotificationConfigurations"])
	v := resolve(name, sprintf("Properties.NotificationConfigurations.%d.TopicARN", [i]))
	_pf_aslib_arn_service(v) == "sns"
	r := _pf_aslib_arn_region(v)
	r != data.cdk_preflight.deploy_region
}
