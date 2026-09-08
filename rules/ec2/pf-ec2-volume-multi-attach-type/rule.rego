package cdk_preflight

import rego.v1

_pf_ec2vma_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-volume.html"

violation contains make_diag_full("pf-ec2-volume-multi-attach-type", "ERROR", name,
	"Properties.MultiAttachEnabled",
	sprintf("MultiAttachEnabled is set on a '%s' volume; only io1 and io2 support Multi-Attach", [vt]),
	"Drop MultiAttachEnabled, or use io1/io2 with a provisioned Iops value",
	_pf_ec2vma_url) if {
	some name in resources_of_type("AWS::EC2::Volume")
	coerce_to_bool(resolve(name, "Properties.MultiAttachEnabled")) == true
	vt := resolve(name, "Properties.VolumeType")
	is_string(vt)
	not vt in {"io1", "io2"}
}
