package cdk_preflight

import rego.v1

_pf_mc_job_props_enum_values_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

_pf_mcjpe_intervals := {
	"SECONDS_10", "SECONDS_12", "SECONDS_15", "SECONDS_20", "SECONDS_30",
	"SECONDS_60", "SECONDS_120", "SECONDS_180", "SECONDS_240", "SECONDS_300",
	"SECONDS_360", "SECONDS_420", "SECONDS_480", "SECONDS_540", "SECONDS_600",
}

_pf_mcjpe_modes := {"DISABLED", "ENABLED", "PREFERRED"}

violation contains make_diag_full("pf-mediaconvert-job-props-enum-values", "ERROR", rn, "Properties.StatusUpdateInterval",
	sprintf("StatusUpdateInterval is %s; it must be one of the SECONDS_10 ... SECONDS_600 values the service lists", [v]),
	"Use SECONDS_10, 12, 15, 20, 30, 60, 120, 180, 240, 300, 360, 420, 480, 540 or 600", _pf_mc_job_props_enum_values_url) if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	p := input.resources[rn].properties
	is_object(p)
	v := p.StatusUpdateInterval
	is_string(v)
	not v in _pf_mcjpe_intervals
}

violation contains make_diag_full("pf-mediaconvert-job-props-enum-values", "ERROR", rn, "Properties.AccelerationSettings.Mode",
	sprintf("AccelerationSettings.Mode is %s; it must be DISABLED, ENABLED or PREFERRED", [v]),
	"Use DISABLED, ENABLED or PREFERRED", _pf_mc_job_props_enum_values_url) if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	p := input.resources[rn].properties
	is_object(p)
	acc := p.AccelerationSettings
	_pf_mclib_lit(acc)
	v := acc.Mode
	is_string(v)
	not v in _pf_mcjpe_modes
}
