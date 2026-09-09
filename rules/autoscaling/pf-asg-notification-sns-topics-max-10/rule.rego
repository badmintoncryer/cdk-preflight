package cdk_preflight

import rego.v1

_pf_asgnst_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgnst_topics(name) := {t |
	some i, _ in _pf_aslib_arr(name, ["NotificationConfigurations"])
	t := resolve(name, sprintf("Properties.NotificationConfigurations.%d.TopicARN", [i]))
}

violation contains make_diag_full("pf-asg-notification-sns-topics-max-10", "ERROR", name,
	"Properties.NotificationConfigurations",
	sprintf("the group notifies %d distinct SNS topics; the limit is 10 and the group create fails with \"can't have more than 10 topics\"", [n]),
	"Fan out from a single topic instead of attaching more than ten", _pf_asgnst_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := count(_pf_asgnst_topics(name))
	n > 10
}
