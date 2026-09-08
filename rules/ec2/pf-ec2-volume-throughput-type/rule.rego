package cdk_preflight

import rego.v1

_pf_ec2vt_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-volume.html"

violation contains make_diag_full("pf-ec2-volume-throughput-type", "ERROR", name,
	"Properties.Throughput",
	sprintf("Throughput is set on a '%s' volume (\"The throughput parameter is not supported for %s volumes.\")", [vt, vt]),
	"Drop Throughput, or set VolumeType to gp3",
	_pf_ec2vt_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	not _pf_ec2lib_absent(name, "Throughput")
	vt := resolve(name, "Properties.VolumeType")
	is_string(vt)
	vt != "gp3"
}
