package cdk_preflight

import rego.v1

_pf_asgsco_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

_pf_asgsco_fix := "Order the three fields so MinSize <= DesiredCapacity <= MaxSize"

violation contains make_diag_full("pf-asg-sched-capacity-fields-ordering", "ERROR", name,
	"Properties.DesiredCapacity",
	sprintf("DesiredCapacity %v is above MaxSize %v; the scheduled action create fails with \"Desired capacity must be less than or equal to max size\"", [d, mx]),
	_pf_asgsco_fix, _pf_asgsco_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	d := _pf_aslib_num(name, "Properties.DesiredCapacity")
	mx := _pf_aslib_num(name, "Properties.MaxSize")
	d > mx
}

violation contains make_diag_full("pf-asg-sched-capacity-fields-ordering", "ERROR", name,
	"Properties.DesiredCapacity",
	sprintf("DesiredCapacity %v is below MinSize %v; the scheduled action create fails with \"Desired capacity must be greater than or equal to min size\"", [d, mn]),
	_pf_asgsco_fix, _pf_asgsco_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	d := _pf_aslib_num(name, "Properties.DesiredCapacity")
	mn := _pf_aslib_num(name, "Properties.MinSize")
	d < mn
}

violation contains make_diag_full("pf-asg-sched-capacity-fields-ordering", "ERROR", name,
	"Properties.MinSize",
	sprintf("MinSize %v is above MaxSize %v; the scheduled action create fails with \"Min size must be less than or equal to max size\"", [mn, mx]),
	_pf_asgsco_fix, _pf_asgsco_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	mn := _pf_aslib_num(name, "Properties.MinSize")
	mx := _pf_aslib_num(name, "Properties.MaxSize")
	mn > mx
}
