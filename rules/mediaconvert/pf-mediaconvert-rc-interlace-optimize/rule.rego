package cdk_preflight

import rego.v1

_pf_mc_rc_interlace_optimize_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcio_h264(rn) := st if {
	cs := _pf_mclib_vcs(rn)
	cs.Codec == "H_264"
	st := cs.H264Settings
	_pf_mclib_lit(st)
	st.ScanTypeConversionMode == "INTERLACED_OPTIMIZE"
}

violation contains make_diag_full("pf-mediaconvert-rc-interlace-optimize", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.H264Settings.ScanTypeConversionMode",
	"H264Settings.ScanTypeConversionMode is INTERLACED_OPTIMIZE but InterlaceMode is PROGRESSIVE (the default); optimized interlacing does not apply to progressive outputs",
	"Set InterlaceMode to an interlaced value (for example TOP_FIELD), or remove ScanTypeConversionMode", _pf_mc_rc_interlace_optimize_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	st := _pf_mcio_h264(rn)
	object.get(st, "InterlaceMode", "PROGRESSIVE") == "PROGRESSIVE"
}

violation contains make_diag_full("pf-mediaconvert-rc-interlace-optimize", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.H264Settings.Telecine",
	"H264Settings.ScanTypeConversionMode is INTERLACED_OPTIMIZE but Telecine is HARD; optimized interlacing needs Telecine NONE or SOFT",
	"Set Telecine to NONE or SOFT, or set ScanTypeConversionMode to INTERLACED", _pf_mc_rc_interlace_optimize_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	st := _pf_mcio_h264(rn)
	st.Telecine == "HARD"
}
