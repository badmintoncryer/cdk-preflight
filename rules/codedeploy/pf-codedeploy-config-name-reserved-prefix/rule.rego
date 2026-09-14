package cdk_preflight

import rego.v1

# The prefix is reserved for the predefined configurations. Only the dot makes
# it reserved: "CodeDeployDefaultFoo" is accepted, and the match is case
# sensitive ("codedeploydefault." is accepted too).
violation contains make_diag_full("pf-codedeploy-config-name-reserved-prefix", "ERROR", name,
	"Properties.DeploymentConfigName",
	sprintf("DeploymentConfigName '%v' uses the reserved CodeDeployDefault. prefix; the deployment configuration create fails with \"The prefix CodeDeployDefault. is reserved for predefined configuration names\"", [n]),
	"Name the custom deployment configuration something that does not start with \"CodeDeployDefault.\"",
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentConfig")
	n := resolve(name, "Properties.DeploymentConfigName")
	_pf_codedeploylib_lit(n)
	startswith(n, "CodeDeployDefault.")
}
