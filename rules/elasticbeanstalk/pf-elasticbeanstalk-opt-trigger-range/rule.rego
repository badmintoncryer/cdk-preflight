package cdk_preflight

import rego.v1

_pf_eb_opt_trigger_range_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-trigger-range", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is %s, which is %s the accepted range of %s; Elastic Beanstalk rejects the setting", [o.ns, o.nm, o.s, side, _pf_eblib_rtext(rg)]),
	sprintf("Use a value in the range %s", [_pf_eblib_rtext(rg)]), _pf_eb_opt_trigger_range_url) if {
	o := _pf_eblib_opt[_]
	rg := _pf_eblib_r_trigger[o.k]
	n := _pf_eblib_num(o.s)
	side := _pf_eblib_side(n, rg)
}
