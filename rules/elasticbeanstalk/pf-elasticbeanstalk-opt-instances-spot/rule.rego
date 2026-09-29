package cdk_preflight

import rego.v1

_pf_eb_opt_instances_spot_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-instances-spot", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is %s, which is %s the accepted range of %s; Elastic Beanstalk rejects the setting", [o.ns, o.nm, o.s, side, _pf_eblib_rtext(rg)]),
	sprintf("Use a value in the range %s", [_pf_eblib_rtext(rg)]), _pf_eb_opt_instances_spot_url) if {
	o := _pf_eblib_opt[_]
	rg := _pf_eblib_r_spot[o.k]
	n := _pf_eblib_num(o.s)
	side := _pf_eblib_side(n, rg)
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-instances-spot", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("SpotFleetOnDemandBase is %v but MaxSize is %v; the on-demand base cannot exceed the maximum group size (a MaxSize that is not set defaults to 4)", [base, mx]),
	"Lower SpotFleetOnDemandBase or raise MaxSize", _pf_eb_opt_instances_spot_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:ec2:instances|SpotFleetOnDemandBase"
	_pf_eblib_standalone(o.rn)
	_pf_eblib_clean(o.rn)
	_pf_eblib_on(o.rn, "aws:ec2:instances|EnableSpot")
	count(_pf_eblib_vals(o.rn, "aws:ec2:instances|SpotFleetOnDemandBase")) == 1
	base := _pf_eblib_num(o.s)
	mx := _pf_eblib_maxsize(o.rn)
	base > mx
}
