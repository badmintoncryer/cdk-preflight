package cdk_preflight

import rego.v1

_pf_mc_pkg_group_container_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/outputs-file-group.html"

# パッケージ系グループが受け付けるコンテナは 1 つだけ（拒否文が "set container to X" と名指しする）
_pf_mcgc_only := {
	"HLS_GROUP_SETTINGS": "M3U8",
	"CMAF_GROUP_SETTINGS": "CMFC",
	"DASH_ISO_GROUP_SETTINGS": "MPD",
	"MS_SMOOTH_GROUP_SETTINGS": "ISMV",
}

# FILE グループの拒否文が並べる有効コンテナに無い、パッケージ系のコンテナ
_pf_mcgc_not_in_file := {"M3U8", "CMFC", "MPD", "ISMV"}

_pf_mcgc_out contains {"rn": grp.rn, "i": grp.i, "j": j, "t": t, "c": c} if {
	some grp in _pf_mclib_groups
	t := grp.gs.Type
	is_string(t)
	outs := grp.g.Outputs
	is_array(outs)
	some j, o in outs
	_pf_mclib_lit(o)
	cs := o.ContainerSettings
	_pf_mclib_lit(cs)
	c := cs.Container
	is_string(c)
}

violation contains make_diag_full("pf-mediaconvert-pkg-group-container", "ERROR", o.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.Outputs.%d.ContainerSettings.Container", [o.i, o.j]),
	sprintf("Output group type %s only accepts the %s container, but the output uses %s", [o.t, want, o.c]),
	sprintf("Set the output ContainerSettings.Container to %s", [want]), _pf_mc_pkg_group_container_url) if {
	some o in _pf_mcgc_out
	want := _pf_mcgc_only[o.t]
	o.c != want
}

violation contains make_diag_full("pf-mediaconvert-pkg-group-container", "ERROR", o.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.Outputs.%d.ContainerSettings.Container", [o.i, o.j]),
	sprintf("A FILE output group does not accept the %s container; that container belongs to a packaging output group", [o.c]),
	"Use a file container such as MP4, MOV or M2TS, or switch the group to the matching packaging type", _pf_mc_pkg_group_container_url) if {
	some o in _pf_mcgc_out
	o.t == "FILE_GROUP_SETTINGS"
	o.c in _pf_mcgc_not_in_file
}
