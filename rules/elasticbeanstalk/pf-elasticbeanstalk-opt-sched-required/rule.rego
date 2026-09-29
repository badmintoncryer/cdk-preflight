package cdk_preflight

import rego.v1

_pf_eb_opt_sched_required_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-required", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Scheduled action '%s' has no %s; a scheduled action needs both MinSize and MaxSize", [o.res, concat(" or ", missing)]),
	"Add MinSize and MaxSize to the scheduled action", _pf_eb_opt_sched_required_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res != "__pf_absent"
	trim_space(o.res) != ""
	o.i == _pf_eblib_sa_first(o.rn, o.res)
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	missing := [nm | some nm in ["MinSize", "MaxSize"]; count(_pf_eblib_savals(o.rn, o.res, nm)) == 0]
	count(missing) > 0
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-sched-required", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Scheduled action '%s' has neither StartTime nor Recurrence; it needs at least one of them to know when to run", [o.res]),
	"Add a Recurrence (cron) or a StartTime to the scheduled action", _pf_eb_opt_sched_required_url) if {
	o := _pf_eblib_opt[_]
	o.ns == _pf_eblib_sa
	o.res != "__pf_absent"
	trim_space(o.res) != ""
	o.i == _pf_eblib_sa_first(o.rn, o.res)
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	count(_pf_eblib_savals(o.rn, o.res, "StartTime")) == 0
	count(_pf_eblib_savals(o.rn, o.res, "Recurrence")) == 0
}
