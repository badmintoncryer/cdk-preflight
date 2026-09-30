package cdk_preflight

import rego.v1

_pf_mc_cont_res_max_by_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

violation contains make_diag_full("pf-mediaconvert-cont-res-max-by-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.Width",
	sprintf("VideoDescription.Width is %v with the MPEG2 codec; MPEG2 output is limited to a width of 1920", [w]),
	"Set Width to 1920 or less, or use another video codec", _pf_mc_cont_res_max_by_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_codec(rn) == "MPEG2"
	w := _pf_mclib_vd(rn).Width
	is_number(w)
	w > 1920
}
