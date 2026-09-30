package cdk_preflight

import rego.v1

_pf_mc_cont_webm_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

_pf_mccontwebmco_bad := ["H_264"]

violation contains make_diag_full("pf-mediaconvert-cont-webm-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("Output container WEBM does not accept video codec %s (WebM takes VP8 and VP9); the service rejects the container/codec combination", [codec]),
	"Change the container or the video codec to a supported combination", _pf_mc_cont_webm_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_container(rn) == "WEBM"
	codec := _pf_mclib_codec(rn)
	codec in _pf_mccontwebmco_bad
}
