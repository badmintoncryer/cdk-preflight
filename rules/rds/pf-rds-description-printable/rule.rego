package cdk_preflight

import rego.v1

_pf_rdsdesc_bad contains [name, path, v] if {
	some name in resources_of_type("AWS::RDS::DBSubnetGroup")
	v := resolve(name, "Properties.DBSubnetGroupDescription")
	is_string(v)
	not regex.match(`^[\x20-\x7e]*$`, v)
	path := "Properties.DBSubnetGroupDescription"
}

_pf_rdsdesc_bad contains [name, path, v] if {
	some name in resources_of_type("AWS::RDS::DBParameterGroup")
	v := resolve(name, "Properties.Description")
	is_string(v)
	not regex.match(`^[\x20-\x7e]*$`, v)
	path := "Properties.Description"
}

violation contains make_diag_full("pf-rds-description-printable", "ERROR", name,
	path,
	sprintf("Description '%s' is rejected: RDS treats any non-ASCII character as a non-printable control character", [v]),
	"Write the description in printable ASCII",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSubnetGroup.html") if {
	some [name, path, v] in _pf_rdsdesc_bad
}
