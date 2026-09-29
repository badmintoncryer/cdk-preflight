package cdk_preflight

import rego.v1

_pf_eb_opt_sched_min_max_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-min-max", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Scheduled action '%s' has MinSize %v above MaxSize %v; the minimum size cannot exceed the maximum", [o.res, mn, mx]),
	"Set MinSize to a value no larger than MaxSize", _pf_eb_opt_sched_min_max_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res != "__pf_absent"
	trim_space(o.res) != ""
	_pf_eblib_clean(o.rn)
	o.nm == "MinSize"
	count(_pf_eblib_savals(o.rn, o.res, "MinSize")) == 1
	mn := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "MinSize")[0])
	count(_pf_eblib_savals(o.rn, o.res, "MaxSize")) == 1
	mx := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "MaxSize")[0])
	mn > mx
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-min-max", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Scheduled action '%s' has DesiredCapacity %v above MaxSize %v; the desired capacity must fit between MinSize and MaxSize", [o.res, d, mx]),
	"Set DesiredCapacity between MinSize and MaxSize", _pf_eb_opt_sched_min_max_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res != "__pf_absent"
	trim_space(o.res) != ""
	_pf_eblib_clean(o.rn)
	o.nm == "DesiredCapacity"
	count(_pf_eblib_savals(o.rn, o.res, "DesiredCapacity")) == 1
	d := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "DesiredCapacity")[0])
	count(_pf_eblib_savals(o.rn, o.res, "MaxSize")) == 1
	mx := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "MaxSize")[0])
	d > mx
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-min-max", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Scheduled action '%s' has DesiredCapacity %v below MinSize %v; the desired capacity must fit between MinSize and MaxSize", [o.res, d, mn]),
	"Set DesiredCapacity between MinSize and MaxSize", _pf_eb_opt_sched_min_max_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res != "__pf_absent"
	trim_space(o.res) != ""
	_pf_eblib_clean(o.rn)
	o.nm == "DesiredCapacity"
	count(_pf_eblib_savals(o.rn, o.res, "DesiredCapacity")) == 1
	d := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "DesiredCapacity")[0])
	count(_pf_eblib_savals(o.rn, o.res, "MinSize")) == 1
	mn := _pf_eblib_num(_pf_eblib_savals(o.rn, o.res, "MinSize")[0])
	d < mn
}
