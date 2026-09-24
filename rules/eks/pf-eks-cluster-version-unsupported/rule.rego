package cdk_preflight

import rego.v1

# Two shapes draw the same refusal (measured 2026-09-25 against
# CreateCluster): a patch-level string such as 1.36.0, and a minor EKS has
# retired. 1.29 was refused and 1.30 reached the next check, so the floor is
# 1.30 - it only ever moves up, so the rule goes stale quietly, never wrong.
violation contains make_diag_full("pf-eks-cluster-version-unsupported", "ERROR", name,
	"Properties.Version",
	sprintf("Version %v is not a bare Kubernetes minor version (\"unsupported Kubernetes version %v\")", [v, v]),
	"Write the minor version only, such as 1.34 - EKS picks the patch release",
	"https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	v := resolve(name, "Properties.Version")
	_pf_ekslib_lit(v)
	not regex.match(`^1\.[0-9]+$`, v)
}

violation contains make_diag_full("pf-eks-cluster-version-unsupported", "ERROR", name,
	"Properties.Version",
	sprintf("EKS no longer creates clusters on Kubernetes %v (\"unsupported Kubernetes version %v\")", [v, v]),
	"Move to a version EKS still offers (1.30 was the oldest on 2026-09-25)",
	"https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	v := resolve(name, "Properties.Version")
	_pf_ekslib_lit(v)
	regex.match(`^1\.[0-9]+$`, v)
	minor := to_number(split(v, ".")[1])
	minor < 30
}
