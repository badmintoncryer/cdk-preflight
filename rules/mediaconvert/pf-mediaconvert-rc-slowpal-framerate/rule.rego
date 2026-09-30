package cdk_preflight

import rego.v1

_pf_mc_rc_slowpal_framerate_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcsp_h264(rn) := st if {
	cs := _pf_mclib_vcs(rn)
	cs.Codec == "H_264"
	st := cs.H264Settings
	_pf_mclib_lit(st)
	st.SlowPal == "ENABLED"
}

violation contains make_diag_full("pf-mediaconvert-rc-slowpal-framerate", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.H264Settings.FramerateControl",
	sprintf("H264Settings.SlowPal is ENABLED but FramerateControl is %s; SlowPal requires FramerateControl SPECIFIED with FramerateNumerator 25", [fc]),
	"Set FramerateControl to SPECIFIED with FramerateNumerator 25 and a FramerateDenominator, or set SlowPal to DISABLED", _pf_mc_rc_slowpal_framerate_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	st := _pf_mcsp_h264(rn)
	fc := object.get(st, "FramerateControl", "INITIALIZE_FROM_SOURCE")
	is_string(fc)
	fc != "SPECIFIED"
}

violation contains make_diag_full("pf-mediaconvert-rc-slowpal-framerate", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.H264Settings.FramerateNumerator",
	sprintf("H264Settings.SlowPal is ENABLED but FramerateNumerator is %v; SlowPal requires a framerate of 25", [n]),
	"Set FramerateNumerator to 25, or set SlowPal to DISABLED", _pf_mc_rc_slowpal_framerate_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	st := _pf_mcsp_h264(rn)
	st.FramerateControl == "SPECIFIED"
	n := st.FramerateNumerator
	is_number(n)
	n != 25
}
