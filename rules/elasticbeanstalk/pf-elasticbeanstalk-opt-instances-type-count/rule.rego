package cdk_preflight

import rego.v1

_pf_eb_opt_instances_type_count_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-instances-type-count", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("InstanceTypes lists %d types; Elastic Beanstalk accepts 1 to 40 instance types and rejects more", [count(ts)]),
	"List at most 40 instance types", _pf_eb_opt_instances_type_count_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:ec2:instances|InstanceTypes"
	ts := _pf_eblib_types(o.s)
	count(ts) > 40
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-instances-type-count", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"InstanceTypes lists the same instance type more than once; Elastic Beanstalk rejects duplicates",
	"List each instance type once", _pf_eb_opt_instances_type_count_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:ec2:instances|InstanceTypes"
	ts := _pf_eblib_types(o.s)
	count(ts) != count({t | t := ts[_]})
}
