package cdk_preflight

import rego.v1

# "1.33" -> 33. EKS versions are always major 1 and the minor is never
# zero-padded, so to_number is safe here.
_pf_ngver_minor(v) := m if {
	_pf_ekslib_lit(v)
	parts := split(v, ".")
	count(parts) == 2
	parts[0] == "1"
	m := to_number(parts[1])
}

_pf_ngver_cluster(name) := c if {
	c := resolve(name, "Properties.ClusterName")
	c in resources_of_type("AWS::EKS::Cluster")
}

violation contains make_diag_full("pf-eks-nodegroup-version-matches-cluster", "ERROR", name,
	"Properties.Version",
	sprintf("node group version 1.%v is outside the four minors cluster %v (1.%v) supports (\"Cluster Kubernetes version 1.%v supports the following Nodegroup Kubernetes versions: [1.%v, 1.%v, 1.%v, 1.%v]\")", [nm, cl, cm, cm, cm, cm - 1, cm - 2, cm - 3]),
	"Set Version to the cluster's minor or one of the three below it, or leave it out to inherit the cluster's",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-nodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	nm := _pf_ngver_minor(resolve(name, "Properties.Version"))
	cl := _pf_ngver_cluster(name)
	cm := _pf_ngver_minor(resolve(cl, "Properties.Version"))
	_pf_ngver_outside(nm, cm)
}

_pf_ngver_outside(nm, cm) if nm > cm

_pf_ngver_outside(nm, cm) if nm < cm - 3
