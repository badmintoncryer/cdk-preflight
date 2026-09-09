package cdk_preflight

import rego.v1

_pf_asgnte_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgnte_ok := {
	"autoscaling:EC2_INSTANCE_LAUNCH", "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
	"autoscaling:EC2_INSTANCE_TERMINATE", "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
	"autoscaling:TEST_NOTIFICATION",
}

violation contains make_diag_full("pf-asg-notification-type-enum", "ERROR", name,
	sprintf("Properties.NotificationConfigurations.%d.NotificationTypes.%d", [i, j]),
	sprintf("'%s' is not an Auto Scaling notification type; the group create fails with \"\\\"%s\\\" is not a valid Notification Type\"", [v, v]),
	"Use one of the five autoscaling: notification types", _pf_asgnte_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, c in _pf_aslib_arr(name, ["NotificationConfigurations"])
	is_object(c)
	ts := object.get(c, "NotificationTypes", null)
	is_array(ts)
	some j, v in ts
	_pf_aslib_lit(v)
	not v in _pf_asgnte_ok
}
