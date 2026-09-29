package cdk_preflight

import rego.v1

_pf_eb_opt_logs_retention_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-logs-retention", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RetentionInDays is %v; CloudWatch Logs retention takes one of a fixed set of day counts (1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653)", [n]),
	"Use one of the retention values CloudWatch Logs supports", _pf_eb_opt_logs_retention_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "RetentionInDays"
	startswith(o.ns, "aws:elasticbeanstalk:cloudwatch:logs")
	n := _pf_eblib_num(o.s)
	not _pf_eblib_ret_ok(n)
}
