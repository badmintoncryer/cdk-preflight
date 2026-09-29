package cdk_preflight

import rego.v1

_pf_eb_opt_sched_resource_name_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-resource-name", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"A scheduled action option has no ResourceName; each scheduled action is a group of options that share a ResourceName, and Elastic Beanstalk rejects an option without one",
	"Set ResourceName on every aws:autoscaling:scheduledaction option to the name of the scheduled action", _pf_eb_opt_sched_resource_name_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res == "__pf_absent"
	o.i == min({x.i | x := _pf_eblib_opt[_]; x.rn == o.rn; x.ns == _pf_eblib_sa; x.res == "__pf_absent"})
}
