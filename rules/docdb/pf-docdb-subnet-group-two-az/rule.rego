package cdk_preflight

import rego.v1

# Judged only when every subnet is a same-template AWS::EC2::Subnet with a literal
# AvailabilityZone; Fn::Select/Fn::GetAZs zones and imported subnet ids stay silent.
_pf_docdb2az_ref(v) := v if is_string(v)

_pf_docdb2az_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

_pf_docdb2az_az(v) := az if {
	sub := _pf_docdb2az_ref(v)
	sub in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sub, "Properties.AvailabilityZone")
	is_string(az)
	not input.resources[az]
}

_pf_docdb2az_azs(name) := [az |
	some s in flatten_list(name, "Properties.SubnetIds")
	az := _pf_docdb2az_az(s.value)
]

violation contains make_diag_full("pf-docdb-subnet-group-two-az", "ERROR", name,
	"Properties.SubnetIds",
	sprintf("All %v subnets of the DB subnet group sit in %s; DocumentDB needs at least 2 Availability Zones (\"The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement ... Add subnets to cover at least 2 AZs.\")", [count(subs), az]),
	"Add a subnet from a second Availability Zone",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbsubnetgroup.html") if {
	some name in resources_of_type("AWS::DocDB::DBSubnetGroup")
	subs := flatten_list(name, "Properties.SubnetIds")
	count(subs) > 0
	azs := _pf_docdb2az_azs(name)
	count(azs) == count(subs)
	distinct := {x | some x in azs}
	count(distinct) == 1
	some az in distinct
}
