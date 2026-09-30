package cdk_preflight

import rego.v1

_pf_mc_cont_misc_single_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

_pf_mcmisc_bad := {
	["F4V", "H_265"],
	["ISMV", "H_265"],
}

violation contains make_diag_full("pf-mediaconvert-cont-misc-single-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("Output container %s does not accept video codec %s (F4V takes H_264 and MPEG2, ISMV takes H_264); the service rejects the container/codec combination", [cont, codec]),
	"Change the container or the video codec to a supported combination", _pf_mc_cont_misc_single_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cont := _pf_mclib_container(rn)
	codec := _pf_mclib_codec(rn)
	_pf_mcmisc_bad[[cont, codec]]
}
