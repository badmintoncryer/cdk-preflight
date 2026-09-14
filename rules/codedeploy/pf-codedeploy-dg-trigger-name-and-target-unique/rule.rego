package cdk_preflight

import rego.v1

_pf_cdtu_vals(name, key) := [v |
	some it in flatten_list(name, "Properties.TriggerConfigurations")
	v := resolve(name, sprintf("Properties.TriggerConfigurations.%d.%s", [it.index, key]))
]

_pf_cdtu_dup(name, key) := [v |
	vs := _pf_cdtu_vals(name, key)
	some v in vs
	count([y | some y in vs; y == v]) > 1
]

violation contains make_diag_full("pf-codedeploy-dg-trigger-name-and-target-unique", "ERROR", name,
	"Properties.TriggerConfigurations",
	sprintf("two triggers share the name \"%s\"; the deployment group create fails with \"Duplicate Trigger target name detected\"", [v]),
	"Give every trigger its own TriggerName",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-triggerconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	some v in _pf_cdtu_dup(name, "TriggerName")
}

violation contains make_diag_full("pf-codedeploy-dg-trigger-name-and-target-unique", "ERROR", name,
	"Properties.TriggerConfigurations",
	"two triggers point at the same topic; the deployment group create fails with \"Duplicate Trigger target arn detected\"",
	"Point every trigger at its own topic, and put all the events one topic needs on a single trigger",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-triggerconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	some _ in _pf_cdtu_dup(name, "TriggerTargetArn")
}
