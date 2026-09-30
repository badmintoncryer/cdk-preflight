package cdk_preflight

import rego.v1

_pf_mc_aud_aac_vbr_combo_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/aac-support.html"

_pf_mcav_vbr contains a if {
	some a in _pf_mclib_aac
	a.aac.RateControlMode == "VBR"
}

violation contains make_diag_full("pf-mediaconvert-aud-aac-vbr-combo", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.AacSettings.VbrQuality", [a.i]),
	"AacSettings.RateControlMode is VBR but VbrQuality is not set; VbrQuality is required for VBR",
	"Set VbrQuality (LOW, MEDIUM_LOW, MEDIUM_HIGH or HIGH), or use RateControlMode CBR", _pf_mc_aud_aac_vbr_combo_url) if {
	some a in _pf_mcav_vbr
	object.get(a.aac, "VbrQuality", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-mediaconvert-aud-aac-vbr-combo", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.AacSettings.CodecProfile", [a.i]),
	sprintf("AacSettings.RateControlMode is VBR but CodecProfile is %s; VBR is only available with the LC profile", [p]),
	"Set CodecProfile to LC, or use RateControlMode CBR", _pf_mc_aud_aac_vbr_combo_url) if {
	some a in _pf_mcav_vbr
	p := object.get(a.aac, "CodecProfile", "LC")
	is_string(p)
	p != "LC"
}
