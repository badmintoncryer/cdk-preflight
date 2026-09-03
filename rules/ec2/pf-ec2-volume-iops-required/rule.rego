package cdk_preflight

import rego.v1

# pf-ec2-volume-iops validates Iops values; this rule covers the
# conditional requirement (absence) that the schema cannot express.
_pf_ec2vir_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ec2-volume-iops-required", "ERROR", name,
	"Properties.Iops",
	sprintf("%s volumes require Iops; EC2 rejects the CreateVolume call with \"The parameter iops must be specified for %s volumes.\"", [vt, vt]),
	"Set Iops (io1: 100-64000, io2: 100-256000)",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html") if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	vt in {"io1", "io2"}
	_pf_ec2vir_absent(name, "Iops")
}
