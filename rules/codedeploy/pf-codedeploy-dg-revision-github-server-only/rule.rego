package cdk_preflight

import rego.v1

# CloudFormation creates the deployment group and then starts the deployment the
# Deployment property describes. A GitHub revision is only a thing on the
# EC2/On-Premises platform; on Lambda or ECS the CreateDeployment behind the
# property is refused and the stack rolls back.
_pf_cdrgh_github(name) if resolve(name, "Properties.Deployment.Revision.RevisionType") == "GitHub"

_pf_cdrgh_github(name) if {
	d := _pf_codedeploylib_obj(_pf_codedeploylib_props(name), "Deployment")
	r := _pf_codedeploylib_obj(d, "Revision")
	_pf_codedeploylib_has(r, "GitHubLocation")
}

violation contains make_diag_full("pf-codedeploy-dg-revision-github-server-only", "ERROR", name,
	"Properties.Deployment.Revision",
	sprintf("the deployment group is on the %s compute platform but its Deployment names a GitHub revision; the deployment fails with \"Revision type: GitHub is not supported under compute platform: %s\"", [p, upper(p)]),
	"Deploy the revision from Amazon S3, or move the deployment group to the EC2/On-Premises platform",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codedeploy-deploymentgroup-githublocation.html") if {
	some name in resources_of_type("AWS::CodeDeploy::DeploymentGroup")
	p := _pf_codedeploylib_dg_platform(name)
	p in ["Lambda", "ECS"]
	_pf_cdrgh_github(name)
}
