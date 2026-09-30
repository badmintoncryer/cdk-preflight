package cdk_preflight

import rego.v1

_pf_mc_pkg_group_type_block_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

_pf_mcgt_block := {
	"HLS_GROUP_SETTINGS": "HlsGroupSettings",
	"DASH_ISO_GROUP_SETTINGS": "DashIsoGroupSettings",
}

violation contains make_diag_full("pf-mediaconvert-pkg-group-type-block", "ERROR", grp.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.OutputGroupSettings", [grp.i]),
	sprintf("OutputGroupSettings.Type is %s but %s is missing; the group needs the settings block that matches its Type", [t, blk]),
	sprintf("Add %s to OutputGroupSettings, or change Type", [blk]), _pf_mc_pkg_group_type_block_url) if {
	some grp in _pf_mclib_groups
	t := grp.gs.Type
	is_string(t)
	blk := _pf_mcgt_block[t]
	object.get(grp.gs, blk, "__pf_absent") == "__pf_absent"
}
