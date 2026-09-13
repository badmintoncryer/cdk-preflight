package cdk_preflight

import rego.v1

# TargetDatabase makes the database a resource link; a link has no storage of
# its own, so the two are rejected together.
violation contains make_diag_full("pf-glue-database-resource-link-exclusive", "ERROR", name,
	"Properties.DatabaseInput.LocationUri",
	"The database sets both TargetDatabase and LocationUri; CreateDatabase fails with \"Resource path and resource link cannot exist together in a database!\"",
	"Drop LocationUri from the resource link, or drop TargetDatabase and keep the database local",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_DatabaseInput.html") if {
	some name in resources_of_type("AWS::Glue::Database")
	di := _pf_gluelib_get(name, "DatabaseInput")
	is_object(di)
	is_object(object.get(di, "TargetDatabase", null))
	object.get(di, "LocationUri", "__pf_absent") != "__pf_absent"
}
