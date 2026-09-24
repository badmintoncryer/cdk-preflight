package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-fargate-selectors-max-five", "ERROR", name,
	"Properties.Selectors",
	sprintf("the profile lists %v selectors (\"Request contains more than 5 Selectors\")", [n]),
	"Keep at most five selectors per Fargate profile and split the rest into another profile",
	"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateFargateProfile.html") if {
	some name in resources_of_type("AWS::EKS::FargateProfile")
	n := count(flatten_list(name, "Properties.Selectors"))
	n > 5
}
