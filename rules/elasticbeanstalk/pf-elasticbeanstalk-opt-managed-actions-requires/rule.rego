package cdk_preflight

import rego.v1

_pf_eb_opt_managed_actions_requires_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-managed-actions-requires", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"ManagedActionsEnabled is true but PreferredStartTime is not set; Elastic Beanstalk needs both PreferredStartTime and UpdateLevel to schedule managed platform updates",
	"Set PreferredStartTime", _pf_eb_opt_managed_actions_requires_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:managedactions|ManagedActionsEnabled"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	_pf_eblib_on(o.rn, "aws:elasticbeanstalk:managedactions|ManagedActionsEnabled")
	not _pf_eblib_filled(o.rn, "aws:elasticbeanstalk:managedactions|PreferredStartTime")
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-managed-actions-requires", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"ManagedActionsEnabled is true but UpdateLevel is not set; Elastic Beanstalk needs both PreferredStartTime and UpdateLevel to schedule managed platform updates",
	"Set UpdateLevel", _pf_eb_opt_managed_actions_requires_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:managedactions|ManagedActionsEnabled"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	_pf_eblib_on(o.rn, "aws:elasticbeanstalk:managedactions|ManagedActionsEnabled")
	not _pf_eblib_filled(o.rn, "aws:elasticbeanstalk:managedactions:platformupdate|UpdateLevel")
}
