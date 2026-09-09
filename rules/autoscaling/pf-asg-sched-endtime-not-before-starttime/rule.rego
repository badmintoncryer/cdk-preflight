package cdk_preflight

import rego.v1

_pf_asgsces_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

# ISO8601 の同一書式どうしは辞書順比較が時刻順と一致する
_pf_asgsces_ts(name, key) := v if {
	v := resolve(name, sprintf("Properties.%s", [key]))
	_pf_aslib_lit(v)
	regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T", v)
}

violation contains make_diag_full("pf-asg-sched-endtime-not-before-starttime", "ERROR", name,
	"Properties.EndTime",
	sprintf("EndTime %s is before StartTime %s; the scheduled action create fails with \"Given end time must be after start time\"", [e, s]),
	"Move EndTime after StartTime", _pf_asgsces_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	s := _pf_asgsces_ts(name, "StartTime")
	e := _pf_asgsces_ts(name, "EndTime")
	e < s
}
