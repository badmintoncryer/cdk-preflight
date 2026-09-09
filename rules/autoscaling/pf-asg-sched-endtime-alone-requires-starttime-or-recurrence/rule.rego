package cdk_preflight

import rego.v1

_pf_asgscea_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-endtime-alone-requires-starttime-or-recurrence", "ERROR", name,
	"Properties.EndTime",
	"EndTime is set but neither StartTime nor Recurrence is; the scheduled action create fails with \"Scheduled start time must be specified for non-recurrent future group action\"",
	"Add StartTime, or make the action recurring with Recurrence", _pf_asgscea_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	not _pf_aslib_absent(name, "EndTime")
	_pf_aslib_absent(name, "StartTime")
	_pf_aslib_absent(name, "Recurrence")
}
