package cdk_preflight

import rego.v1

_pf_asgscep_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

# ponytail: 時計ビルトインが無いため下限は固定 (2026-09-09)。詳細は pf-asg-sched-starttime-not-past と同じ。
violation contains make_diag_full("pf-asg-sched-endtime-not-past", "ERROR", name,
	"Properties.EndTime",
	sprintf("EndTime %s is in the past; the scheduled action create fails with \"Given end time is in the past\"", [v]),
	"Use a future EndTime", _pf_asgscep_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.EndTime")
	_pf_aslib_lit(v)
	regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T", v)
	substring(v, 0, 10) < "2026-09-09"
}
