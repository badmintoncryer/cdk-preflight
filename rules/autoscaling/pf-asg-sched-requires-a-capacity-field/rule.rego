package cdk_preflight

import rego.v1

_pf_asgscap_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-requires-a-capacity-field", "ERROR", name,
	"Properties.DesiredCapacity",
	"the scheduled action changes nothing: MinSize, MaxSize and DesiredCapacity are all unset, and the create fails with \"At least one of max size, min size, or desired capacity must be specified\"",
	"Set at least one of MinSize, MaxSize or DesiredCapacity", _pf_asgscap_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	_pf_aslib_absent(name, "MinSize")
	_pf_aslib_absent(name, "MaxSize")
	_pf_aslib_absent(name, "DesiredCapacity")
}
