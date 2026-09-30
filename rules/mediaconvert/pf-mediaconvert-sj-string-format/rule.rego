package cdk_preflight

import rego.v1

_pf_mc_sj_string_format_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

violation contains make_diag_full("pf-mediaconvert-sj-string-format", "ERROR", grp.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.OutputGroupSettings.HlsGroupSettings.Destination", [grp.i]),
	sprintf("HlsGroupSettings.Destination is '%s'; it must be an s3:// URL", [d]),
	"Use a destination of the form s3://bucket/prefix/", _pf_mc_sj_string_format_url) if {
	some grp in _pf_mclib_groups
	hls := grp.gs.HlsGroupSettings
	_pf_mclib_lit(hls)
	d := hls.Destination
	is_string(d)
	not startswith(d, "s3://")
}
