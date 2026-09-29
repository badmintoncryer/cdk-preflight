package cdk_preflight

import rego.v1

_pf_eb_opt_asg_min_max_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

_pf_eb_opt_asg_min_max_bad(rn) if {
	_pf_eblib_clean(rn)
	_pf_eblib_minsize(rn) > _pf_eblib_maxsize(rn)
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-asg-min-max", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("MinSize is %v but MaxSize is %v (MinSize defaults to 1 and MaxSize to 4 when not set); the minimum group size cannot exceed the maximum", [mn, mx]),
	"Set MinSize to a value no larger than MaxSize", _pf_eb_opt_asg_min_max_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:asg|MinSize"
	_pf_eb_opt_asg_min_max_bad(o.rn)
	mn := _pf_eblib_minsize(o.rn)
	mx := _pf_eblib_maxsize(o.rn)
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-asg-min-max", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("MinSize is %v but MaxSize is %v (MinSize defaults to 1 and MaxSize to 4 when not set); the minimum group size cannot exceed the maximum", [mn, mx]),
	"Set MinSize to a value no larger than MaxSize", _pf_eb_opt_asg_min_max_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:asg|MaxSize"
	count(_pf_eblib_vals(o.rn, "aws:autoscaling:asg|MinSize")) == 0
	_pf_eb_opt_asg_min_max_bad(o.rn)
	mn := _pf_eblib_minsize(o.rn)
	mx := _pf_eblib_maxsize(o.rn)
}
