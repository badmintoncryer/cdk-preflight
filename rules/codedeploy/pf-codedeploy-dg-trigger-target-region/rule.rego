package cdk_preflight

import rego.v1

# CodeDeploy resolves the trigger topic in its own Region only: a topic ARN whose
# Region field is another one is refused out of hand, whether or not the topic
# really exists there. Needs data.cdk_preflight.deploy_region, so the rule is
# silent unless the engine was given a concrete region.
violation contains make_diag_full("pf-codedeploy-dg-trigger-target-region", "ERROR", name,
	sprintf("Properties.TriggerConfigurations.%d.TriggerTargetArn", [it.index]),
	sprintf("the trigger topic is in %s but the deployment group deploys to %s; the create fails with \"Topic ARN ... is not valid\"", [r, region]),
	"Point the trigger at a topic in the deployment group's own Region (build the ARN with ${AWS::Region})",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-triggerconfig.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some it in flatten_list(name, "Properties.TriggerConfigurations")
	arn := resolve(name, sprintf("Properties.TriggerConfigurations.%d.TriggerTargetArn", [it.index]))
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "sns"
	r := parts[3]
	r != ""
	r != region
}
