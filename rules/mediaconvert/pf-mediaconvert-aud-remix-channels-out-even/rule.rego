package cdk_preflight

import rego.v1

_pf_mc_aud_remix_channels_out_even_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-aud-remix-channels-out-even", "ERROR", r.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.RemixSettings.ChannelsOut", [r.i]),
	sprintf("RemixSettings.ChannelsOut is %v; it must be 1 or an even number", [n]),
	"Set ChannelsOut to 1 or an even number", _pf_mc_aud_remix_channels_out_even_url) if {
	some r in _pf_mclib_remix
	n := r.rs.ChannelsOut
	is_number(n)
	n > 1
	n % 2 == 1
}
