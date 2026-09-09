package cdk_preflight

import rego.v1

_pf_asgscsu_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-starttime-unique-per-group", "ERROR", name,
	"Properties.StartTime",
	sprintf("scheduled action %s already starts at %s on the same group; the second create fails with \"Scheduled action with this scheduled start time already exists\"", [other, t]),
	"Give the two actions different start times", _pf_asgscsu_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	some other in resources_of_type("AWS::AutoScaling::ScheduledAction")
	other < name
	t := resolve(name, "Properties.StartTime")
	is_string(t)
	resolve(other, "Properties.StartTime") == t
	g := resolve(name, "Properties.AutoScalingGroupName")
	resolve(other, "Properties.AutoScalingGroupName") == g
}
