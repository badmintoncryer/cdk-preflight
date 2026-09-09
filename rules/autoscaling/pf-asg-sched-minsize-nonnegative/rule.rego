package cdk_preflight

import rego.v1

_pf_asgscmn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-minsize-nonnegative", "ERROR", name,
	"Properties.MinSize",
	sprintf("MinSize %v is negative; the scheduled action create fails with \"Min size must be non-negative\"", [n]),
	"Use a MinSize of 0 or more", _pf_asgscmn_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	n := _pf_aslib_num(name, "Properties.MinSize")
	n < 0
}
