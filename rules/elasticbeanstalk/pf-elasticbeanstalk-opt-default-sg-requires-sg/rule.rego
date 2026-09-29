package cdk_preflight

import rego.v1

_pf_eb_opt_default_sg_requires_sg_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-default-sg-requires-sg", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"DisableDefaultEC2SecurityGroup is true but SecurityGroups lists no security group; the instances would have none and Elastic Beanstalk rejects the setting",
	"Set SecurityGroups to at least one security group, or leave DisableDefaultEC2SecurityGroup off", _pf_eb_opt_default_sg_requires_sg_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|DisableDefaultEC2SecurityGroup"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	_pf_eblib_on(o.rn, "aws:autoscaling:launchconfiguration|DisableDefaultEC2SecurityGroup")
	not _pf_eblib_filled(o.rn, "aws:autoscaling:launchconfiguration|SecurityGroups")
}
