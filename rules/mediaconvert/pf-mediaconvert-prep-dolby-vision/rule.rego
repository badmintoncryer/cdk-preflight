package cdk_preflight

import rego.v1

_pf_mc_prep_dolby_vision_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-prep-dolby-vision", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.DolbyVision.Profile",
	"DolbyVision is set but Profile is missing; Profile is required",
	"Set DolbyVision.Profile (for example PROFILE_5 or PROFILE_8_1)", _pf_mc_prep_dolby_vision_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	dv := _pf_mclib_vp(rn).DolbyVision
	_pf_mclib_lit(dv)
	object.get(dv, "Profile", "__pf_absent") == "__pf_absent"
}
