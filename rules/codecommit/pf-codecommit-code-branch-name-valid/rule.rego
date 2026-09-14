package cdk_preflight

import rego.v1

# Code is applied by the CloudFormation handler, not by CreateRepository,
# so nothing upstream sees the branch name.
violation contains make_diag_full("pf-codecommit-code-branch-name-valid", "ERROR", name,
	"Properties.Code.BranchName",
	sprintf("Code.BranchName %v is not a valid Git ref name, so the initial commit the handler makes cannot name a branch", [b]),
	"Use a valid Git branch name: no spaces, no '..', '//' or '@{', none of ~^:?*[\\, no leading or trailing '/' or '.', and no '.lock' suffix",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codecommit-repository-code.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	b := resolve(name, "Properties.Code.BranchName")
	_pf_cclib_bad_ref(b)
}
