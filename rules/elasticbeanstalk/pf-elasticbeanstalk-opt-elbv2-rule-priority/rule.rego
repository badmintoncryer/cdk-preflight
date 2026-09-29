package cdk_preflight

import rego.v1

_pf_eb_opt_elbv2_rule_priority_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-rule-priority", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Rule priority is %v, which is below the accepted range of 1 to 1000; Elastic Beanstalk rejects the setting", [n]),
	"Use a Priority in the range 1 to 1000", _pf_eb_opt_elbv2_rule_priority_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "Priority"
	startswith(o.ns, "aws:elbv2:listenerrule:")
	n := _pf_eblib_num(o.s)
	n < 1
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-rule-priority", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Rule priority is %v, which is above the accepted range of 1 to 1000; Elastic Beanstalk rejects the setting", [n]),
	"Use a Priority in the range 1 to 1000", _pf_eb_opt_elbv2_rule_priority_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "Priority"
	startswith(o.ns, "aws:elbv2:listenerrule:")
	n := _pf_eblib_num(o.s)
	n > 1000
}
