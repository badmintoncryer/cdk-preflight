package cdk_preflight

import rego.v1

_pf_eb_opt_deploy_range_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-deploy-range", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is %s, which is %s the accepted range of %s; Elastic Beanstalk rejects the setting", [o.ns, o.nm, o.s, side, _pf_eblib_rtext(rg)]),
	sprintf("Use a value in the range %s", [_pf_eblib_rtext(rg)]), _pf_eb_opt_deploy_range_url) if {
	o := _pf_eblib_opt[_]
	rg := _pf_eblib_r_deploy[o.k]
	n := _pf_eblib_num(o.s)
	side := _pf_eblib_side(n, rg)
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-deploy-range", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is %v, which is below the accepted range of 1 to %v (100 for BatchSizeType Percentage, 10000 for Fixed); Elastic Beanstalk rejects the setting", [o.ns, o.nm, n, hi]),
	"BatchSize is a percentage (1 to 100) under Percentage and a count (1 to 10000) under Fixed", _pf_eb_opt_deploy_range_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:command|BatchSize"
	n := _pf_eblib_num(o.s)
	hi := _pf_eblib_batch_hi(o.rn)
	n < 1
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-deploy-range", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is %v, which is above the accepted range of 1 to %v (100 for BatchSizeType Percentage, 10000 for Fixed); Elastic Beanstalk rejects the setting", [o.ns, o.nm, n, hi]),
	"BatchSize is a percentage (1 to 100) under Percentage and a count (1 to 10000) under Fixed", _pf_eb_opt_deploy_range_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:command|BatchSize"
	n := _pf_eblib_num(o.s)
	hi := _pf_eblib_batch_hi(o.rn)
	n > hi
}
