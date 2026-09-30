package cdk_preflight

import rego.v1

_pf_mc_aud_remix_mapping_exclusive_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-aud-remix-mapping-exclusive", "ERROR", r.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.RemixSettings.ChannelMapping.OutputChannels.%d", [r.i, j]),
	"An OutputChannels entry sets both InputChannels and InputChannelsFineTune; use only one of them",
	"Remove either InputChannels or InputChannelsFineTune from the entry", _pf_mc_aud_remix_mapping_exclusive_url) if {
	some r in _pf_mclib_remix
	cm := r.rs.ChannelMapping
	_pf_mclib_lit(cm)
	oc := cm.OutputChannels
	is_array(oc)
	some j, o in oc
	_pf_mclib_lit(o)
	is_array(o.InputChannels)
	is_array(o.InputChannelsFineTune)
}
