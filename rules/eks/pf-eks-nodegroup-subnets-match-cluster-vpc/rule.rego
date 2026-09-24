package cdk_preflight

import rego.v1

# Both sides are only knowable when the cluster and the subnets live in the
# same template: an imported cluster leaves ClusterName a literal and an
# imported subnet id is a literal too, and the rule then stays silent.
# flatten_list keeps the __ref of a Ref element but drops its __kind, so the
# logical id has to be read out of the element rather than resolved.
_pf_ngvpc_ref(v) := r if {
	r := object.get(v, "__ref", "__pf_absent")
	r != "__pf_absent"
}

_pf_ngvpc_of_subnet(v) := vpc if {
	s := _pf_ngvpc_ref(v)
	s in resources_of_type("AWS::EC2::Subnet")
	vpc := resolve(s, "Properties.VpcId")
}

_pf_ngvpc_cluster_vpc(name) := vpc if {
	cl := resolve(name, "Properties.ClusterName")
	cl in resources_of_type("AWS::EKS::Cluster")
	some cs in flatten_list(cl, "Properties.ResourcesVpcConfig.SubnetIds")
	vpc := _pf_ngvpc_of_subnet(cs.value)
}

violation contains make_diag_full("pf-eks-nodegroup-subnets-match-cluster-vpc", "ERROR", name,
	sprintf("Properties.Subnets.%v", [s.index]),
	sprintf("subnet %v is in VPC %v but the cluster is in VPC %v (\"Subnets specified must belong to the VPC\")", [_pf_ngvpc_ref(s.value), nv, cv]),
	"List subnets of the cluster's own VPC in Properties.Subnets",
	"https://docs.aws.amazon.com/eks/latest/userguide/network-reqs.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	cv := _pf_ngvpc_cluster_vpc(name)
	some s in flatten_list(name, "Properties.Subnets")
	nv := _pf_ngvpc_of_subnet(s.value)
	nv != cv
}
