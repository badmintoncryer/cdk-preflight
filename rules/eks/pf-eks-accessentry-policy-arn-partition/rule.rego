package cdk_preflight

import rego.v1

# The service reports a policy that cannot be found rather than naming the
# partition, so this one reads as a typo in the policy name. _pf_iamlib_partition
# is undefined when no region is injected, which skips the rule.
violation contains make_diag_full("pf-eks-accessentry-policy-arn-partition", "ERROR", name,
	sprintf("Properties.AccessPolicies.%v.PolicyArn", [ap.index]),
	sprintf("PolicyArn %v names partition %v but the stack deploys to %v (\"The specified policyArn could not be found.\")", [arn, parts[1], want]),
	"Write the ARN with the deploy partition, or build it from AWS::Partition",
	"https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	some ap in flatten_list(name, "Properties.AccessPolicies")
	arn := _pf_ekslib_oget(ap.value, "PolicyArn")
	_pf_ekslib_lit(arn)
	regex.match(`^arn:[^:]+:eks::aws:cluster-access-policy/.+$`, arn)
	parts := split(arn, ":")
	want := _pf_iamlib_partition
	parts[1] != want
}
