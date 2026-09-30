package cdk_preflight

import rego.v1

_pf_mc_cont_mp4_video_codec_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/supported-containers-codecs-details.html"

_pf_mccontmp4vid_bad := ["PRORES", "MPEG2"]

violation contains make_diag_full("pf-mediaconvert-cont-mp4-video-codec", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("Output container MP4 does not accept video codec %s (MP4 takes AV1, H_264 and H_265); the service rejects the container/codec combination", [codec]),
	"Change the container or the video codec to a supported combination", _pf_mc_cont_mp4_video_codec_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	_pf_mclib_container(rn) == "MP4"
	codec := _pf_mclib_codec(rn)
	codec in _pf_mccontmp4vid_bad
}
