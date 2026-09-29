package cdk_preflight

import rego.v1

_pf_eb_opt_boolean_value_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-boolean-value", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is '%s'; Elastic Beanstalk validates it as a Boolean and rejects the setting (\"Not a Boolean\")", [o.ns, o.nm, o.s]),
	"Use true or false", _pf_eb_opt_boolean_value_url) if {
	o := _pf_eblib_opt[_]
	_pf_eblib_bool[o.k]
	o.s != ""
	not _pf_eblib_isbool(o.s)
}
