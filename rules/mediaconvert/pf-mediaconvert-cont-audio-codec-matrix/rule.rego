package cdk_preflight

import rego.v1

_pf_mc_cont_audio_codec_matrix_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

_pf_mcacm_bad := {
	["WEBM", "AAC"],
	["MP4", "VORBIS"],
}

violation contains make_diag_full("pf-mediaconvert-cont-audio-codec-matrix", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.Codec", [a.i]),
	sprintf("Output container %s does not accept audio codec %s; the service rejects the container/codec combination", [cont, codec]),
	"Change the container or the audio codec to a supported combination", _pf_mc_cont_audio_codec_matrix_url) if {
	some a in _pf_mclib_ads
	cont := _pf_mclib_container(a.rn)
	cs := a.ad.CodecSettings
	_pf_mclib_lit(cs)
	codec := cs.Codec
	_pf_mcacm_bad[[cont, codec]]
}
