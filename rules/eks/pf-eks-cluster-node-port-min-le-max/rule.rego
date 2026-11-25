package cdk_preflight

import rego.v1

_pf_eknpo_num(o, k) := n if {
	v := _pf_ekslib_oget(o, k)
	not is_boolean(v)
	v != null
	n := _pf_tonum(v)
}

violation contains make_diag_full("pf-eks-cluster-node-port-min-le-max", "ERROR", name,
	"Properties.KubeApiServerConfig.ServiceNodePortRange",
	sprintf("ServiceNodePortRange MinPort %v is above MaxPort %v; CreateCluster fails with \"kubeApiServerConfig.serviceNodePortRange minPort (%v) must be less than or equal to maxPort (%v)\"", [mn, mx, mn, mx]),
	"Swap the values so that MinPort <= MaxPort",
	"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-parameters.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	cfg := _pf_ekslib_get(name, "KubeApiServerConfig")
	r := _pf_ekslib_oget(cfg, "ServiceNodePortRange")
	mn := _pf_eknpo_num(r, "MinPort")
	mx := _pf_eknpo_num(r, "MaxPort")
	mn > mx
}
