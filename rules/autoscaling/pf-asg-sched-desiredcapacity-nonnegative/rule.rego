package cdk_preflight

import rego.v1

_pf_asgscdc_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-desiredcapacity-nonnegative", "ERROR", name,
	"Properties.DesiredCapacity",
	sprintf("DesiredCapacity %v is negative; the scheduled action create fails with \"Desired capacity must be non-negative\"", [n]),
	"Use a DesiredCapacity of 0 or more", _pf_asgscdc_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	n := _pf_aslib_num(name, "Properties.DesiredCapacity")
	n < 0
}
