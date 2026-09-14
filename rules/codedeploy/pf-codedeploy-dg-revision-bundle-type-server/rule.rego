package cdk_preflight

import rego.v1

# The Deployment property makes CloudFormation start a deployment, and on the
# EC2/On-Premises platform the revision bundle has to be an archive. YAML and
# JSON are the AppSpec forms of the Lambda and ECS platforms and are refused
# here. lower() keeps the rule off a spelling the service might still take.
violation contains make_diag_full("pf-codedeploy-dg-revision-bundle-type-server", "ERROR", name,
	"Properties.Deployment.Revision.S3Location.BundleType",
	sprintf("the deployment group is on the EC2/On-Premises platform but its revision bundle type is \"%s\"; the deployment fails with \"BundleType must be either tar, zip or tgz\"", [bt]),
	"Bundle the revision as tar, tgz or zip",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-s3location.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	_pf_codedeploylib_dg_platform(name) == "Server"
	bt := resolve(name, "Properties.Deployment.Revision.S3Location.BundleType")
	_pf_codedeploylib_lit(bt)
	not lower(bt) in ["tar", "tgz", "zip"]
}
