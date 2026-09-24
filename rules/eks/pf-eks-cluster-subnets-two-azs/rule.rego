package cdk_preflight

import rego.v1

# One message covers both shapes (measured 2026-09-25): one subnet, and two
# subnets sharing an AZ. Cross-resource: silent when a subnet is imported.
violation contains make_diag_full("pf-eks-cluster-subnets-two-azs", "ERROR", name,
	"Properties.ResourcesVpcConfig.SubnetIds",
	"the cluster is given a single subnet (\"Subnets specified must be in at least two different AZs\")",
	"Give the cluster subnets in two different availability zones",
	"https://docs.aws.amazon.com/eks/latest/userguide/network-reqs.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	is_array(object.get(_pf_ekslib_props(name), ["ResourcesVpcConfig", "SubnetIds"], null))
	ids := flatten_list(name, "Properties.ResourcesVpcConfig.SubnetIds")
	ids != []
	count(ids) < 2
}

violation contains make_diag_full("pf-eks-cluster-subnets-two-azs", "ERROR", name,
	"Properties.ResourcesVpcConfig.SubnetIds",
	sprintf("every subnet given to the cluster sits in the same availability zone %v (\"Subnets specified must be in at least two different AZs\")", [az]),
	"Give the cluster subnets in two different availability zones",
	"https://docs.aws.amazon.com/eks/latest/userguide/network-reqs.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	ids := flatten_list(name, "Properties.ResourcesVpcConfig.SubnetIds")
	count(ids) >= 2
	azs := {a | some v in ids; a := _pf_ekssn_az(object.get(v.value, "__ref", ""))}
	count(azs) == 1
	count([v | some v in ids; _pf_ekssn_az(object.get(v.value, "__ref", ""))]) == count(ids)
	some az in azs
}

# Tagged so an AvailabilityZoneId is never compared with an AvailabilityZone
# name: the same name maps to a different zone in every account.
_pf_ekssn_az(sn) := ["id", v] if {
	sn in resources_of_type("AWS::EC2::Subnet")
	v := _pf_ekslib_get(sn, "AvailabilityZoneId")
	is_string(v)
}

_pf_ekssn_az(sn) := ["name", v] if {
	sn in resources_of_type("AWS::EC2::Subnet")
	not _pf_ekslib_has(sn, "AvailabilityZoneId")
	v := _pf_ekslib_get(sn, "AvailabilityZone")
	is_string(v)
}
