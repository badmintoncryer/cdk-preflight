package cdk_preflight

import rego.v1

_pf_ssmmg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-maintenancewindowtarget.html"

_pf_ssmmg_fix := "Match Targets to ResourceType: INSTANCE with Key InstanceIds (alone) or tag:<key> / tag-key; RESOURCE_GROUP with Key resource-groups:Name"

_pf_ssmmg_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_ssmmg_keys(name) := [k | some e in flatten_list(name, "Properties.Targets"); k := resolve(name, sprintf("Properties.Targets.%d.Key", [e.index])); is_string(k)]

_pf_ssmmg_instance_key(k) if k == "InstanceIds"

_pf_ssmmg_instance_key(k) if k == "tag-key"

_pf_ssmmg_instance_key(k) if startswith(k, "tag:")

violation contains make_diag_full("pf-ssm-maintenance-window-target", "ERROR", name,
	"Properties.Targets",
	sprintf("target key '%s' is not valid for ResourceType INSTANCE (use InstanceIds, tag:<key> or tag-key); RegisterTargetWithMaintenanceWindow fails with \"Target Type does not match with the provided target.\"", [k]),
	_pf_ssmmg_fix, _pf_ssmmg_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTarget")
	resolve(name, "Properties.ResourceType") == "INSTANCE"
	some k in _pf_ssmmg_keys(name)
	not _pf_ssmmg_instance_key(k)
}

violation contains make_diag_full("pf-ssm-maintenance-window-target", "ERROR", name,
	"Properties.Targets",
	"an InstanceIds target must be the only target; RegisterTargetWithMaintenanceWindow fails with \"Targets must be specified in one of the following formats: 1) 1 target with Key=InstanceIds ... or 2) Up to 5 targets, each of which can be either Key=tag:<key> or Key=tag-key\"",
	_pf_ssmmg_fix, _pf_ssmmg_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTarget")
	resolve(name, "Properties.ResourceType") == "INSTANCE"
	keys := _pf_ssmmg_keys(name)
	"InstanceIds" in keys
	count(keys) > 1
}

violation contains make_diag_full("pf-ssm-maintenance-window-target", "ERROR", name,
	"Properties.Targets",
	sprintf("target key '%s' is not valid for ResourceType RESOURCE_GROUP (use resource-groups:Name); RegisterTargetWithMaintenanceWindow fails with \"Target Type does not match with the provided target.\"", [k]),
	_pf_ssmmg_fix, _pf_ssmmg_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTarget")
	resolve(name, "Properties.ResourceType") == "RESOURCE_GROUP"
	some k in _pf_ssmmg_keys(name)
	not startswith(k, "resource-groups:")
}

violation contains make_diag_full("pf-ssm-maintenance-window-target", "ERROR", name,
	"Properties.Targets",
	"ResourceType RESOURCE_GROUP needs a resource-groups:Name target; RegisterTargetWithMaintenanceWindow fails with \"Targets must be specified in one of the following formats\"",
	_pf_ssmmg_fix, _pf_ssmmg_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTarget")
	resolve(name, "Properties.ResourceType") == "RESOURCE_GROUP"
	keys := _pf_ssmmg_keys(name)
	count(keys) > 0
	not "resource-groups:Name" in keys
}
