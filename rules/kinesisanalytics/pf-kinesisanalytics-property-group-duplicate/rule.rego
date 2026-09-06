package cdk_preflight

import rego.v1

_pf_kinpg contains [name, i, id] if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	ep := _pf_kinlib_obj(_pf_kinlib_appcfg(name), "EnvironmentProperties")
	gs := object.get(ep, "PropertyGroups", null)
	is_array(gs)
	some i, g in gs
	is_object(g)
	id := object.get(g, "PropertyGroupId", null)
	is_string(id)
}

violation contains make_diag_full("pf-kinesisanalytics-property-group-duplicate", "ERROR", name,
	sprintf("Properties.ApplicationConfiguration.EnvironmentProperties.PropertyGroups.%v.PropertyGroupId", [i]),
	sprintf("PropertyGroupId '%v' is already used by group %v; CreateApplication fails with \"Found a duplicate PropertyGroupId : '%v'.\"", [id, j, id]),
	"Give every property group a distinct PropertyGroupId",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_EnvironmentProperties.html") if {
	some [name, i, id] in _pf_kinpg
	some [other, j, id2] in _pf_kinpg
	other == name
	id2 == id
	j < i
}
