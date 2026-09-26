package cdk_preflight

import rego.v1

# The schema marks OrganizationalUnits optional and CloudFormation is happy
# without it; the service refuses the create. An empty list is accepted (measured
# 2026-09-26: ORGANIZATION with [] reached ACTIVE), so only absence is reported —
# hence the sentinel rather than a count.
violation contains make_diag_full("pf-grafana-ws-organization-access-requires-ous", "ERROR", name,
	"Properties.OrganizationalUnits",
	"AccountAccessType is ORGANIZATION but OrganizationalUnits is absent; CreateWorkspace fails with \"When the accountAccessType is ORGANIZATION a list of Organizational Units should be provided.\"",
	"List the organizational units the workspace may reach, or set AccountAccessType to CURRENT_ACCOUNT",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	resolve(name, "Properties.AccountAccessType") == "ORGANIZATION"
	object.get(_pf_grafana_props(name), "OrganizationalUnits", "__pf_absent") == "__pf_absent"
}
