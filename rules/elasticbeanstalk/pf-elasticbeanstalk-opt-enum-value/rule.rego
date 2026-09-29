package cdk_preflight

import rego.v1

_pf_eb_opt_enum_value_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-enum-value", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is '%s', which is not one of %s; Elastic Beanstalk rejects the setting", [o.ns, o.nm, o.s, concat(", ", list)]),
	sprintf("Use one of %s", [concat(", ", list)]), _pf_eb_opt_enum_value_url) if {
	o := _pf_eblib_opt[_]
	list := _pf_eblib_enum[o.k]
	o.s != ""
	not _pf_eblib_enum_ok(o, list)
}
