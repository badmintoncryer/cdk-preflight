package cdk_preflight

import rego.v1

_pf_eb_opt_rolling_min_in_service_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-rolling-min-in-service", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("MinInstancesInService is %v but MaxSize is %v (a MaxSize that is not set defaults to 4); with rolling updates enabled the minimum in-service count must be lower than the maximum group size", [mis, mx]),
	"Lower MinInstancesInService below MaxSize or raise MaxSize", _pf_eb_opt_rolling_min_in_service_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:updatepolicy:rollingupdate|MinInstancesInService"
	_pf_eblib_clean(o.rn)
	_pf_eblib_on(o.rn, "aws:autoscaling:updatepolicy:rollingupdate|RollingUpdateEnabled")
	count(_pf_eblib_vals(o.rn, "aws:autoscaling:updatepolicy:rollingupdate|MinInstancesInService")) == 1
	mis := _pf_eblib_num(o.s)
	mx := _pf_eblib_maxsize(o.rn)
	mis >= mx
}
