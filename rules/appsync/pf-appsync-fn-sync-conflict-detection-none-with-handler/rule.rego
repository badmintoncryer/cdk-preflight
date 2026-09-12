package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-fn-sync-conflict-detection-none-with-handler", "ERROR", name,
	"Properties.SyncConfig.ConflictHandler",
	sprintf("SyncConfig.ConflictDetection is NONE but ConflictHandler is '%s'; the function create rejects a conflict handler when conflict detection is off", [sc.ConflictHandler]),
	"Set ConflictDetection: VERSION, or drop ConflictHandler",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	sc := resolve(name, "Properties.SyncConfig")
	is_object(sc)
	sc.ConflictDetection == "NONE"
	object.get(sc, "ConflictHandler", "NONE") != "NONE"
}
