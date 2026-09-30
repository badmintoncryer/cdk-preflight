package cdk_preflight

import rego.v1

_pf_mc_rc_qvbr_maxbitrate_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-rc-qvbr-maxbitrate", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Av1Settings.MaxBitrate",
	"Av1Settings.RateControlMode is QVBR but MaxBitrate is not set; AV1 QVBR requires MaxBitrate",
	"Set Av1Settings.MaxBitrate", _pf_mc_rc_qvbr_maxbitrate_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cs := _pf_mclib_vcs(rn)
	cs.Codec == "AV1"
	av := cs.Av1Settings
	_pf_mclib_lit(av)
	av.RateControlMode == "QVBR"
	object.get(av, "MaxBitrate", "__pf_absent") == "__pf_absent"
}
