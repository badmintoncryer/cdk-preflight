package cdk_preflight

import rego.v1

_pf_mc_pkg_mp4_ctts_cslg_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-pkg-mp4-ctts-cslg", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.Mp4Settings.CslgAtom",
	"Mp4Settings.CttsVersion is 1 but CslgAtom is EXCLUDE; version 1 of the ctts atom requires CslgAtom INCLUDE",
	"Set CslgAtom to INCLUDE, or set CttsVersion to 0", _pf_mc_pkg_mp4_ctts_cslg_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_container(rn) == "MP4"
	m := _pf_mclib_cont(rn).Mp4Settings
	_pf_mclib_lit(m)
	m.CttsVersion == 1
	m.CslgAtom == "EXCLUDE"
}
