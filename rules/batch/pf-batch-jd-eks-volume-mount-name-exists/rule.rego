package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-eks-volume-mount-name-exists", "ERROR", name,
	"Properties.EksProperties.PodProperties.Containers",
	sprintf("the volume mount %v does not match any volume of the pod", [n]),
	"Declare the volume in PodProperties.Volumes, or fix the mount name",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EksContainer.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	vs := {n | some v in flatten_list(name, "Properties.EksProperties.PodProperties.Volumes"); n := object.get(v.value, "Name", null)}
	some c in _pf_batch_eks_containers(name)
	bad := [n | some m in object.get(c.value, "VolumeMounts", []); n := object.get(m, "Name", null); _pf_batch_lit(n); not n in vs]
	count(bad) > 0
	n := bad[0]
}
