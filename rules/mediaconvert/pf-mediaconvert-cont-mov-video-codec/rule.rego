package cdk_preflight

import rego.v1

_pf_mc_cont_mov_video_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

_pf_mccontmovvid_bad := ["VP9"]

violation contains make_diag_full("pf-mediaconvert-cont-mov-video-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("Output container MOV does not accept video codec %s (MOV takes H_264, MPEG2 and PRORES); the service rejects the container/codec combination", [codec]),
	"Change the container or the video codec to a supported combination", _pf_mc_cont_mov_video_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_container(rn) == "MOV"
	codec := _pf_mclib_codec(rn)
	codec in _pf_mccontmovvid_bad
}
