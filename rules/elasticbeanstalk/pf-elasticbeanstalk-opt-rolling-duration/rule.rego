package cdk_preflight

import rego.v1

_pf_eb_opt_rolling_duration_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-rolling-duration", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Timeout is %s (%d seconds); the rolling update timeout is an ISO 8601 duration of PT5M to PT1H", [o.s, secs]),
	"Use a Timeout between PT5M and PT1H", _pf_eb_opt_rolling_duration_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:updatepolicy:rollingupdate|Timeout"
	secs := _pf_eblib_iso_secs(o.s)
	secs < _pf_eblib_dur_timeout_lo
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rolling-duration", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Timeout is %s (%d seconds); the rolling update timeout is an ISO 8601 duration of PT5M to PT1H", [o.s, secs]),
	"Use a Timeout between PT5M and PT1H", _pf_eb_opt_rolling_duration_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:updatepolicy:rollingupdate|Timeout"
	secs := _pf_eblib_iso_secs(o.s)
	secs > _pf_eblib_dur_max
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rolling-duration", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("PauseTime is %s (%d seconds); the rolling update pause time is an ISO 8601 duration of at most PT1H", [o.s, secs]),
	"Use a PauseTime of PT1H or less", _pf_eb_opt_rolling_duration_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:updatepolicy:rollingupdate|PauseTime"
	secs := _pf_eblib_iso_secs(o.s)
	secs > _pf_eblib_dur_max
}
