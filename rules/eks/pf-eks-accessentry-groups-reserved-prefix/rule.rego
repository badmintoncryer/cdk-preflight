package cdk_preflight

import rego.v1

# Same closed list as the username rule, measured the same way: the
# service rejects system:, eks:, aws:, amazon: and iam: and accepts the rest.
violation contains make_diag_full("pf-eks-accessentry-groups-reserved-prefix", "ERROR", name,
	sprintf("Properties.KubernetesGroups.%v", [g.index]),
	sprintf("Kubernetes group %v starts with %v, which EKS reserves (\"The kubernetes group name %v is invalid, it cannot start with %v\")", [g.value, pfx, g.value, pfx]),
	"Bind the principal to a group name of your own",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	some g in flatten_list(name, "Properties.KubernetesGroups")
	_pf_ekslib_lit(g.value)
	some pfx in _pf_ekslib_reserved_prefixes
	startswith(g.value, pfx)
}
