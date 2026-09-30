package cdk_preflight

import rego.v1

_pf_mc_cont_mxf_profile_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

violation contains make_diag_full("pf-mediaconvert-cont-mxf-profile-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("MxfSettings.Profile is D_10 but the video codec is %s; a D_10 MXF output needs the MPEG2 video codec", [codec]),
	"Set the video codec to MPEG2, or choose another MXF profile", _pf_mc_cont_mxf_profile_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_container(rn) == "MXF"
	mx := _pf_mclib_cont(rn).MxfSettings
	_pf_mclib_lit(mx)
	mx.Profile == "D_10"
	codec := _pf_mclib_codec(rn)
	codec != "MPEG2"
}
