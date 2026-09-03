package cdk_preflight

import rego.v1

_pf_ec2vke_bad(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "Encrypted", "__pf_absent") == "__pf_absent"
}

_pf_ec2vke_bad(name) if resolve(name, "Properties.Encrypted") == false

violation contains make_diag_full("pf-ec2-volume-kms-encrypted", "ERROR", name,
	"Properties.KmsKeyId",
	"KmsKeyId is set but Encrypted is not true; EC2 rejects the volume with \"The parameter [KmsKeyId] requires the parameter Encrypted to be set.\"",
	"Set Encrypted: true alongside KmsKeyId",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html") if {
	some name in resources_of_type("AWS::EC2::Volume")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "KmsKeyId", "__pf_absent") != "__pf_absent"
	_pf_ec2vke_bad(name)
}
