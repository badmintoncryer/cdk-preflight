package cdk_preflight

import rego.v1

_pf_mc_sj_enum_value_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcsje_codecs := {
	"AV1", "AVC_INTRA", "FRAME_CAPTURE", "GIF", "H_264", "H_265", "MPEG2",
	"PASSTHROUGH", "PRORES", "UNCOMPRESSED", "VC3", "VP8", "VP9", "XAVC",
}

_pf_mcsje_containers := {
	"F4V", "GIF", "ISMV", "M2TS", "M3U8", "CMFC", "MOV", "MP4", "MPD", "MXF", "OGG", "WEBM", "RAW", "Y4M",
}

violation contains make_diag_full("pf-mediaconvert-sj-enum-value", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings.Codec",
	sprintf("VideoDescription.CodecSettings.Codec is %s; the service accepts only its listed video codecs", [c]),
	"Use one of AV1, AVC_INTRA, FRAME_CAPTURE, GIF, H_264, H_265, MPEG2, PASSTHROUGH, PRORES, UNCOMPRESSED, VC3, VP8, VP9, XAVC", _pf_mc_sj_enum_value_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	c := _pf_mclib_codec(rn)
	not c in _pf_mcsje_codecs
}

violation contains make_diag_full("pf-mediaconvert-sj-enum-value", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.Container",
	sprintf("ContainerSettings.Container is %s; the service accepts only its listed containers", [c]),
	"Use one of F4V, GIF, ISMV, M2TS, M3U8, CMFC, MOV, MP4, MPD, MXF, OGG, WEBM, RAW, Y4M", _pf_mc_sj_enum_value_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	c := _pf_mclib_container(rn)
	not c in _pf_mcsje_containers
}
