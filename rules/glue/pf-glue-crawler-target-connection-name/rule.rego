package cdk_preflight

import rego.v1

# Both target kinds are rejected with the same message; JDBC_CONNECTION and
# MONGODB connections are the only way the crawler can reach the store.
violation contains make_diag_full("pf-glue-crawler-target-connection-name", "ERROR", name,
	sprintf("Properties.Targets.%s.%d.ConnectionName", [k, i]),
	sprintf("A %s entry has no ConnectionName; CreateCrawler fails with \"Connection name cannot be equal to null or empty.\"", [k]),
	"Set ConnectionName to an AWS::Glue::Connection of the matching type (JDBC for JdbcTargets, MONGODB for MongoDBTargets)",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateCrawler.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	some k in ["JdbcTargets", "MongoDBTargets"]
	arr := object.get(_pf_gluelib_targets(name), k, [])
	is_array(arr)
	some i, t in arr
	is_object(t)
	object.get(t, "ConnectionName", "__pf_absent") == "__pf_absent"
}
