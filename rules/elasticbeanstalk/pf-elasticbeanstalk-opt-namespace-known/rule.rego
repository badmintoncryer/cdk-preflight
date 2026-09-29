package cdk_preflight

import rego.v1

_pf_eb_opt_namespace_known_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-namespace-known", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Namespace", [o.i]),
	sprintf("OptionSettings namespace %s is not a known Elastic Beanstalk namespace; ValidateConfigurationSettings rejects it (\"Unknown configuration setting\")", [o.ns]),
	"Check the namespace against the Elastic Beanstalk configuration options list", _pf_eb_opt_namespace_known_url) if {
	o := _pf_eblib_opt[_]
	_pf_eblib_std_platform(o.rn)
	_pf_eblib_standalone(o.rn)
	not _pf_eblib_ns_ok(o.ns)
}
