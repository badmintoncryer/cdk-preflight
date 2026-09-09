package cdk_preflight

import rego.v1

_pf_asgscsp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

# ponytail: engine に時計ビルトインが無いので、このルールが書かれた日 (2026-09-09) より前の
# 日付しか捕まえない。誤検知はゼロだが、直近の過去日は見逃す。
violation contains make_diag_full("pf-asg-sched-starttime-not-past", "ERROR", name,
	"Properties.StartTime",
	sprintf("StartTime %s is in the past; the scheduled action create fails with \"Given start time is in the past\"", [v]),
	"Use a future StartTime, or drop it and use Recurrence", _pf_asgscsp_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.StartTime")
	_pf_aslib_lit(v)
	regex.match("^[0-9]{4}-[0-9]{2}-[0-9]{2}T", v)
	substring(v, 0, 10) < "2026-09-09"
}
