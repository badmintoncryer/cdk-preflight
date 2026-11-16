package cdk_preflight

import rego.v1

_pf_eknpr_num(o, k) := n if {
	v := _pf_ekslib_oget(o, k)
	not is_boolean(v)
	v != null
	n := to_number(v)
}

_pf_eknpr_out(n) if n < 10260

_pf_eknpr_out(n) if n > 32767

violation contains make_diag_full("pf-eks-cluster-node-port-range", "ERROR", name,
	sprintf("Properties.KubeApiServerConfig.ServiceNodePortRange.%s", [k]),
	sprintf("ServiceNodePortRange %s %v is outside 10260-32767; CreateCluster fails with \"kubeApiServerConfig.serviceNodePortRange minPort (...) is below minimum allowed value (10260)\"", [k, n]),
	"Keep MinPort and MaxPort between 10260 and 32767",
	"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-parameters.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	cfg := _pf_ekslib_get(name, "KubeApiServerConfig")
	r := _pf_ekslib_oget(cfg, "ServiceNodePortRange")
	some k in ["MinPort", "MaxPort"]
	n := _pf_eknpr_num(r, k)
	_pf_eknpr_out(n)
}
