package cdk_preflight

import rego.v1

_pf_mc_codec_video_settings_block_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcvsb_block := {
	"H_265": "H265Settings",
	"AV1": "Av1Settings",
}

violation contains make_diag_full("pf-mediaconvert-codec-video-settings-block", "ERROR", rn, "Properties.SettingsJson.VideoDescription.CodecSettings",
	sprintf("VideoDescription.CodecSettings.Codec is %s but %s is missing; the service requires the settings block that matches the codec", [codec, blk]),
	sprintf("Add %s to VideoDescription.CodecSettings, or change Codec", [blk]), _pf_mc_codec_video_settings_block_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cs := _pf_mclib_vcs(rn)
	codec := cs.Codec
	is_string(codec)
	blk := _pf_mcvsb_block[codec]
	object.get(cs, blk, "__pf_absent") == "__pf_absent"
}
