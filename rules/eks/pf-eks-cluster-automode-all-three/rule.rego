package cdk_preflight

import rego.v1

# An absent flag is the same request as false, so writing only one of the
# three is the shape that bites. A flag left as a Ref makes the set
# undefined and the rule silent.
violation contains make_diag_full("pf-eks-cluster-automode-all-three", "ERROR", name,
	"Properties.ComputeConfig",
	"ComputeConfig.Enabled, KubernetesNetworkConfig.ElasticLoadBalancing.Enabled and StorageConfig.BlockStorage.Enabled disagree (\"For EKS Auto Mode, please ensure that all required configs, including computeConfig, kubernetesNetworkConfig, and blockStorage are all either fully enabled or fully disabled.\")",
	"Set all three Enabled flags to true for Auto Mode, or leave all three off",
	"https://docs.aws.amazon.com/eks/latest/userguide/automode-get-started-cli.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	vals := {_pf_ekslib_flag(name, ["ComputeConfig", "Enabled"]),
		_pf_ekslib_flag(name, ["KubernetesNetworkConfig", "ElasticLoadBalancing", "Enabled"]),
		_pf_ekslib_flag(name, ["StorageConfig", "BlockStorage", "Enabled"])}
	count(vals) == 2
}
