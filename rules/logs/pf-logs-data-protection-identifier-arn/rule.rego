package cdk_preflight

import rego.v1

# Custom data identifiers are named in Configuration.CustomDataIdentifier and referenced by that name.
_pf_lgdpi_custom(obj) := {n |
	some c in object.get(object.get(obj, "Configuration", {}), "CustomDataIdentifier", [])
	is_object(c)
	n := object.get(c, "Name", null)
	is_string(n)
}

violation contains make_diag_full("pf-logs-data-protection-identifier-arn", "ERROR", name,
	"Properties.DataProtectionPolicy",
	sprintf("DataIdentifier '%s' is not an ARN; PutDataProtectionPolicy fails with \"%s is not a valid Data Identifier\"", [id, id]),
	"Use the managed identifier ARN (arn:aws:dataprotection::aws:data-identifier/EmailAddress)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-start.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	obj := _pf_lglib_dpp(name)
	stmts := object.get(obj, "Statement", null)
	is_array(stmts)
	some st in stmts
	is_object(st)
	ids := object.get(st, "DataIdentifier", null)
	is_array(ids)
	some id in ids
	is_string(id)
	not startswith(id, "arn:")
	not id in _pf_lgdpi_custom(obj)
}
