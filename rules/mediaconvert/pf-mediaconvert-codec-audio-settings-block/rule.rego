package cdk_preflight

import rego.v1

_pf_mc_codec_audio_settings_block_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mccasb_block := {
	"AC3": "Ac3Settings",
	"MP3": "Mp3Settings",
}

violation contains make_diag_full("pf-mediaconvert-codec-audio-settings-block", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings", [a.i]),
	sprintf("AudioDescription codec is %s but %s is missing; the service requires the settings block that matches the codec", [codec, blk]),
	sprintf("Add %s to CodecSettings, or change Codec", [blk]), _pf_mc_codec_audio_settings_block_url) if {
	some a in _pf_mclib_ads
	cs := a.ad.CodecSettings
	_pf_mclib_lit(cs)
	codec := cs.Codec
	is_string(codec)
	blk := _pf_mccasb_block[codec]
	object.get(cs, blk, "__pf_absent") == "__pf_absent"
}
