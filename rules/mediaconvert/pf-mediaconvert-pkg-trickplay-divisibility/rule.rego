package cdk_preflight

import rego.v1

_pf_mc_pkg_trickplay_divisibility_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

_pf_mctpd_ts contains {"rn": grp.rn, "i": grp.i, "ts": ts} if {
	some grp in _pf_mclib_groups
	dash := grp.gs.DashIsoGroupSettings
	_pf_mclib_lit(dash)
	ts := dash.ImageBasedTrickPlaySettings
	_pf_mclib_lit(ts)
}

violation contains make_diag_full("pf-mediaconvert-pkg-trickplay-divisibility", "ERROR", t.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.OutputGroupSettings.DashIsoGroupSettings.ImageBasedTrickPlaySettings.ThumbnailWidth", [t.i]),
	sprintf("ImageBasedTrickPlaySettings.ThumbnailWidth is %v; it must be a multiple of 8", [w]),
	"Round ThumbnailWidth to a multiple of 8", _pf_mc_pkg_trickplay_divisibility_url) if {
	some t in _pf_mctpd_ts
	w := t.ts.ThumbnailWidth
	is_number(w)
	w % 8 != 0
}

violation contains make_diag_full("pf-mediaconvert-pkg-trickplay-divisibility", "ERROR", t.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.OutputGroupSettings.DashIsoGroupSettings.ImageBasedTrickPlaySettings.ThumbnailHeight", [t.i]),
	sprintf("ImageBasedTrickPlaySettings.ThumbnailHeight is %v; it must be a multiple of 2", [h]),
	"Round ThumbnailHeight to a multiple of 2", _pf_mc_pkg_trickplay_divisibility_url) if {
	some t in _pf_mctpd_ts
	h := t.ts.ThumbnailHeight
	is_number(h)
	h % 2 != 0
}
