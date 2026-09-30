package cdk_preflight

import rego.v1

_pf_mc_codec_xavc_profile_block_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-codec-xavc-profile-block", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.XavcSettings.Profile",
	"XavcSettings.Profile is XAVC_HD_INTRA_CBG but XavcHdIntraCbgProfileSettings is missing",
	"Add XavcHdIntraCbgProfileSettings to XavcSettings, or change Profile", _pf_mc_codec_xavc_profile_block_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cs := _pf_mclib_vcs(rn)
	cs.Codec == "XAVC"
	x := cs.XavcSettings
	_pf_mclib_lit(x)
	x.Profile == "XAVC_HD_INTRA_CBG"
	object.get(x, "XavcHdIntraCbgProfileSettings", "__pf_absent") == "__pf_absent"
}
