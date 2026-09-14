package cdk_preflight

import rego.v1

# The wait before the original instances are terminated is capped at two days.
# _pf_codedeploylib_num keeps a Ref or an absent key out of the comparison -
# to_number(resolve(...)) would read an absent key as 0.
violation contains make_diag_full("pf-codedeploy-dg-termination-wait-max", "ERROR", name,
	"Properties.BlueGreenDeploymentConfiguration.TerminateBlueInstancesOnDeploymentSuccess.TerminationWaitTimeInMinutes",
	sprintf("TerminationWaitTimeInMinutes is %d; the deployment group create fails with \"Timeout for instance termination cannot be more than 2 days\"", [w]),
	"Wait at most 2880 minutes before terminating the original instances",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-blueinstanceterminationoption.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	bg := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "BlueGreenDeploymentConfiguration")
	t := _pf_codedeploylib_obj(bg, "TerminateBlueInstancesOnDeploymentSuccess")
	w := _pf_codedeploylib_num(object.get(t, "TerminationWaitTimeInMinutes", null))
	w > 2880
}
