package cdk_preflight

import rego.v1

# TargetGroupInfo.Name is the target group's NAME, and a target group name is at
# most 32 characters. Writing its ARN there is the same mistake seen from the
# service side: the ARN is over 32 characters, so it is refused by this one check.
# Measured with and without DeploymentStyle - the length is checked either way.
violation contains make_diag_full("pf-codedeploy-dg-target-group-name-max-32", "ERROR", name,
	sprintf("Properties.LoadBalancerInfo.TargetGroupInfoList.%d.Name", [it.index]),
	sprintf("the target group name is %d characters; the deployment group create fails with \"The target group name ... specified in targetGroupInfoList exceeds the maximum allowed length of 32 characters.\"", [count(n)]),
	"Name the target group (at most 32 characters), not its ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-targetgroupinfo.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	some it in flatten_list(name, "Properties.LoadBalancerInfo.TargetGroupInfoList")
	is_object(it.value)
	n := object.get(it.value, "Name", null)
	_pf_codedeploylib_lit(n)
	count(n) > 32
}
