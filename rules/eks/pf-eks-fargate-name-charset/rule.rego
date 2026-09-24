package cdk_preflight

import rego.v1

# The service names Unicode letters here, not just ASCII ("the set of Unicode
# letters, digits, hyphens and underscores"), so a non-ASCII name stays silent.
violation contains make_diag_full("pf-eks-fargate-name-charset", "ERROR", name,
	"Properties.FargateProfileName",
	sprintf("FargateProfileName %v holds a character outside letters, digits, '-' and '_' (\"The Fargate profile name parameter contains invalid characters\")", [n]),
	"Use letters, digits, hyphens and underscores, starting with a letter or digit",
	"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateFargateProfile.html") if {
	some name in resources_of_type("AWS::EKS::FargateProfile")
	n := resolve(name, "Properties.FargateProfileName")
	_pf_ekslib_lit(n)
	not regex.match(`^[\p{L}\p{N}][\p{L}\p{N}_-]*$`, n)
}
