package cdk_preflight

import rego.v1

_pf_mc_aud_mp3_vbr_quality_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-aud-mp3-vbr-quality", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.Mp3Settings.VbrQuality", [a.i]),
	"Mp3Settings.RateControlMode is VBR but VbrQuality is not set; VbrQuality is required for VBR",
	"Set VbrQuality, or use RateControlMode CBR", _pf_mc_aud_mp3_vbr_quality_url) if {
	some a in _pf_mclib_ads
	cs := a.ad.CodecSettings
	_pf_mclib_lit(cs)
	cs.Codec == "MP3"
	st := cs.Mp3Settings
	_pf_mclib_lit(st)
	st.RateControlMode == "VBR"
	object.get(st, "VbrQuality", "__pf_absent") == "__pf_absent"
}
