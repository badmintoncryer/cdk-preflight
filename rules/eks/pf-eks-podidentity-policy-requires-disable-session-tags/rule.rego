package cdk_preflight

import rego.v1

# DisableSessionTags defaults to false, so leaving it out is the same request
# as writing false and draws the same message.
violation contains make_diag_full("pf-eks-podidentity-policy-requires-disable-session-tags", "ERROR", name,
	"Properties.DisableSessionTags",
	"Policy is set but DisableSessionTags is not true (\"When policy is specified, disableSessionTags must be set to true\")",
	"Set DisableSessionTags to true alongside Policy, or drop Policy and scope the role instead",
	"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreatePodIdentityAssociation.html") if {
	some name in resources_of_type("AWS::EKS::PodIdentityAssociation")
	_pf_ekslib_has(name, "Policy")
	not _pf_ekslib_get(name, "DisableSessionTags") == true
}
