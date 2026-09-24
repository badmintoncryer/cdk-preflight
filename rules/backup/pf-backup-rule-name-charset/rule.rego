package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-rule-name-charset", "ERROR", name,
	sprintf("Properties.BackupPlan.BackupPlanRule.%d.RuleName", [r.index]),
	sprintf("RuleName %v contains characters other than alphanumerics, '-', '_' and '.'", [n]),
	"Rename the rule using alphanumerics and '-_.' only (no spaces)",
	"https://docs.aws.amazon.com/aws-backup/latest/devguide/API_BackupRuleInput.html") if {
	some name in resources_of_type("AWS::Backup::BackupPlan")
	some r in _pf_bklib_plan_rules(name)
	n := _pf_bklib_str(r.value, "RuleName")
	not _pf_bklib_dot_dash_name(n)
}
