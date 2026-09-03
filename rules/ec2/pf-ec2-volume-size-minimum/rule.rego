package cdk_preflight

import rego.v1

# Only minimums: the historical 16384 GiB maximum no longer holds
# (a 17000 GiB gp3 deployed clean on 2026-09-03).
_pf_ec2vsm_min := {"io1": 4, "io2": 4, "st1": 125, "sc1": 125}

violation contains make_diag_full("pf-ec2-volume-size-minimum", "ERROR", name,
	"Properties.Size",
	sprintf("Size %v GiB is below the %v GiB minimum for %s volumes (\"%s volumes must be at least %v GiB in size.\")", [s, mn, vt, vt, mn]),
	"Raise Size to the volume type minimum",
	"https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html") if {
	some name in resources_of_type("AWS::EC2::Volume")
	vt := resolve(name, "Properties.VolumeType")
	mn := _pf_ec2vsm_min[vt]
	s := to_number(resolve(name, "Properties.Size"))
	s < mn
}
