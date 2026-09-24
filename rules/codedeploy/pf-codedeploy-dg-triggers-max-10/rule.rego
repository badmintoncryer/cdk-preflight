package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codedeploy-dg-triggers-max-10", "ERROR", name,
	"Properties.TriggerConfigurations",
	sprintf("the deployment group declares %d notification triggers; the create fails with \"Deployment Groups cannot contain more than 10 TriggerTargets.\"", [n]),
	"Declare at most 10 triggers on the deployment group",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-triggerconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_countable_list(name, "Properties.TriggerConfigurations")
	n := count(flatten_list(name, "Properties.TriggerConfigurations"))
	n > 10
}
