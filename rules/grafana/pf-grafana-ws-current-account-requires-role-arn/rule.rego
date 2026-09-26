package cdk_preflight

import rego.v1

# RoleArn is optional in the schema and required by the service under either of
# two conditions. The whole 2x2 matrix was measured on 2026-09-26: only
# ORGANIZATION + SERVICE_MANAGED creates without a RoleArn.
#
# The two conditions are separate rule bodies rather than a negated helper, and
# the diagnostic is byte-identical in both so that the violation set collapses to
# one entry on a workspace where both hold.
violation contains make_diag_full("pf-grafana-ws-current-account-requires-role-arn", "ERROR", name,
	"Properties.RoleArn",
	"RoleArn is absent although it is required: AccountAccessType is CURRENT_ACCOUNT or PermissionType is CUSTOMER_MANAGED; CreateWorkspace fails with \"When the accountAccessType is CURRENT_ACCOUNT a Workspace Role ARN should be provided.\" (or the same sentence naming permissionType CUSTOMER_MANAGED)",
	"Give the workspace a RoleArn, or combine AccountAccessType ORGANIZATION with PermissionType SERVICE_MANAGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	resolve(name, "Properties.AccountAccessType") == "CURRENT_ACCOUNT"
	object.get(_pf_grafana_props(name), "RoleArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-grafana-ws-current-account-requires-role-arn", "ERROR", name,
	"Properties.RoleArn",
	"RoleArn is absent although it is required: AccountAccessType is CURRENT_ACCOUNT or PermissionType is CUSTOMER_MANAGED; CreateWorkspace fails with \"When the accountAccessType is CURRENT_ACCOUNT a Workspace Role ARN should be provided.\" (or the same sentence naming permissionType CUSTOMER_MANAGED)",
	"Give the workspace a RoleArn, or combine AccountAccessType ORGANIZATION with PermissionType SERVICE_MANAGED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	resolve(name, "Properties.PermissionType") == "CUSTOMER_MANAGED"
	object.get(_pf_grafana_props(name), "RoleArn", "__pf_absent") == "__pf_absent"
}
