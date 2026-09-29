package cdk_preflight

import rego.v1

_pf_eb_opt_regex_catalog_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-regex-catalog", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s / %s is '%s', which does not match the format Elastic Beanstalk accepts (%s); the setting is rejected", [o.ns, o.nm, o.s, rx]),
	"Use a value in the documented format", _pf_eb_opt_regex_catalog_url) if {
	o := _pf_eblib_opt[_]
	rx := _pf_eblib_rx[o.k]
	o.s != ""
	not _pf_eblib_rx_ok(o, rx)
}
