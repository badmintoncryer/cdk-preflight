package cdk_preflight

import rego.v1

# The filter Type says which halves of the tag are matched; the half that is not
# matched must not be supplied. Applies to every place a tag filter can sit: the
# two flat lists and the two tag sets.
_pf_cdtfc_flat(name) := [{"path": sprintf("Properties.%s.%d", [k, it.index]), "value": it.value} |
	some k in ["Ec2TagFilters", "OnPremisesInstanceTagFilters"]
	some it in flatten_list(name, sprintf("Properties.%s", [k]))
]

_pf_cdtfc_set(name, prop, list, group) := [{"path": sprintf("Properties.%s.%s.%d.%s.%d", [prop, list, g.index, group, it.index]), "value": it.value} |
	some g in flatten_list(name, sprintf("Properties.%s.%s", [prop, list]))
	some it in flatten_list(name, sprintf("Properties.%s.%s.%d.%s", [prop, list, g.index, group]))
]

_pf_cdtfc_items(name) := array.concat(
	_pf_cdtfc_flat(name),
	array.concat(
		_pf_cdtfc_set(name, "Ec2TagSet", "Ec2TagSetList", "Ec2TagGroup"),
		_pf_cdtfc_set(name, "OnPremisesTagSet", "OnPremisesTagSetList", "OnPremisesTagGroup"),
	),
)

violation contains make_diag_full("pf-codedeploy-dg-tag-filter-type-value-consistency", "ERROR", name,
	it.path,
	"the tag filter Type is KEY_ONLY but a Value is supplied; the deployment group create fails with \"Values must not be provided for key-only filters.\"",
	"Drop Value, or use KEY_AND_VALUE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-ec2tagfilter.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	some it in _pf_cdtfc_items(name)
	is_object(it.value)
	object.get(it.value, "Type", null) == "KEY_ONLY"
	_pf_codedeploylib_has(it.value, "Value")
}

violation contains make_diag_full("pf-codedeploy-dg-tag-filter-type-value-consistency", "ERROR", name,
	it.path,
	"the tag filter Type is VALUE_ONLY but a Key is supplied; the deployment group create fails with \"Keys must not be provided for value-only filters.\"",
	"Drop Key, or use KEY_AND_VALUE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-ec2tagfilter.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	some it in _pf_cdtfc_items(name)
	is_object(it.value)
	object.get(it.value, "Type", null) == "VALUE_ONLY"
	_pf_codedeploylib_has(it.value, "Key")
}
