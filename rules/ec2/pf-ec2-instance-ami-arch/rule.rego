package cdk_preflight

import rego.v1

_pf_ec2iaa_url := "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html"

# Graviton naming convention: a "g" among the letters after the
# generation digit (t4g, c7gn, im4gn, g5g), plus the pre-convention a1.
# mac* families are excluded from judgment entirely.
_pf_ec2iaa_arm_fam(fam) if regex.match(`^[a-z]+[0-9]+[a-z0-9]*g[a-z0-9]*$`, fam)

_pf_ec2iaa_arm_fam(fam) if fam == "a1"

_pf_ec2iaa_fam(name) := fam if {
	it := resolve(name, "Properties.InstanceType")
	is_string(it)
	fam := split(it, ".")[0]
	not startswith(fam, "mac")
}

# {{resolve:ssm:...}} strings surface as {"__dynamic": "dynamic
# reference: {{resolve:ssm:<path>}}"} marker objects (measured
# 2026-09-03); the reference text is read from the marker.
_pf_ec2iaa_img(name) := d if {
	props := input.resources[name].properties
	is_object(props)
	raw := object.get(props, "ImageId", "__pf_absent")
	is_object(raw)
	d := object.get(raw, "__dynamic", "")
	is_string(d)
	contains(d, "{{resolve:ssm:")
}

violation contains make_diag_full("pf-ec2-instance-ami-arch", "ERROR", name,
	"Properties.ImageId",
	sprintf("Instance type '%s' is x86_64 but the AMI parameter path names arm64; the launch fails with an architecture mismatch", [resolve(name, "Properties.InstanceType")]),
	"Use an arm64 (Graviton) instance type or the x86_64 AMI path",
	_pf_ec2iaa_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	fam := _pf_ec2iaa_fam(name)
	not _pf_ec2iaa_arm_fam(fam)
	img := _pf_ec2iaa_img(name)
	contains(img, "arm64")
}

violation contains make_diag_full("pf-ec2-instance-ami-arch", "ERROR", name,
	"Properties.ImageId",
	sprintf("Instance type '%s' is arm64 (Graviton) but the AMI parameter path names x86_64; the launch fails with an architecture mismatch", [resolve(name, "Properties.InstanceType")]),
	"Use an x86_64 instance type or the arm64 AMI path",
	_pf_ec2iaa_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	fam := _pf_ec2iaa_fam(name)
	_pf_ec2iaa_arm_fam(fam)
	img := _pf_ec2iaa_img(name)
	contains(img, "x86_64")
}
