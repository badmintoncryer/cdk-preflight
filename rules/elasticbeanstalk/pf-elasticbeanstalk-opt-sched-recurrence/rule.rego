package cdk_preflight

import rego.v1

_pf_eb_opt_sched_recurrence_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-recurrence", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Recurrence '%s' has %d fields; a scheduled action takes a five-field cron expression (minute hour day-of-month month day-of-week) and Elastic Beanstalk rejects anything else", [o.s, n]),
	"Use exactly five cron fields; there is no seconds or year field", _pf_eb_opt_sched_recurrence_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:scheduledaction|Recurrence"
	o.s != ""
	n := _pf_eblib_cron_fields(o.s)
	n != 5
}
