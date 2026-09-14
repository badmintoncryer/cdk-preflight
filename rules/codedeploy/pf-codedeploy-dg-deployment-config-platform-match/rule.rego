package cdk_preflight

import rego.v1

# A deployment configuration carries its own compute platform, and the service
# refuses one that does not match the application's. Two ways to know it from the
# template: a predefined CodeDeployDefault.* name spells the platform out, and a
# custom configuration in the same template carries ComputePlatform. Any other
# literal names a configuration created elsewhere, and the rule stays quiet.
_pf_cdpm_predef(n) := "Lambda" if startswith(n, "CodeDeployDefault.Lambda")

_pf_cdpm_predef(n) := "ECS" if startswith(n, "CodeDeployDefault.ECS")

_pf_cdpm_predef(n) := "Server" if {
	startswith(n, "CodeDeployDefault.")
	not startswith(n, "CodeDeployDefault.Lambda")
	not startswith(n, "CodeDeployDefault.ECS")
}

_pf_cdpm_cfg(name) := p if {
	c := resolve(name, "Properties.DeploymentConfigName")
	input.resources[c].resourceType == "AWS::CodeDeploy::DeploymentConfig"
	p := _pf_codedeploylib_platform(c)
}

_pf_cdpm_cfg(name) := p if {
	c := resolve(name, "Properties.DeploymentConfigName")
	_pf_codedeploylib_lit(c)
	p := _pf_cdpm_predef(c)
}

violation contains make_diag_full("pf-codedeploy-dg-deployment-config-platform-match", "ERROR", name,
	"Properties.DeploymentConfigName",
	sprintf("The deployment configuration is for the %v compute platform but the application is %v; the deployment group create fails with \"Compute platform of deployment config ... does not match expected compute platform, correct compute platform should be %v.\"", [cp, ap, ap]),
	sprintf("Name a deployment configuration whose compute platform is %v", [ap]),
	"https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	ap := _pf_codedeploylib_dg_platform(name)
	cp := _pf_cdpm_cfg(name)
	cp != ap
}
