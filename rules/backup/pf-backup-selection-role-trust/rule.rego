package cdk_preflight

import rego.v1

# AWS Backup assumes the selection's IamRoleArn to list and back up the selected
# resources, and CreateBackupSelection rejects a role whose trust policy does not
# name backup.amazonaws.com, which rolls the stack back after the plan and vault
# were created.
violation contains make_diag_full("pf-backup-selection-role-trust", "ERROR", name,
	"Properties.BackupSelection.IamRoleArn",
	sprintf("The selection uses role '%s', whose trust policy does not let backup.amazonaws.com assume it; CreateBackupSelection rejects it", [role]),
	sprintf("Add backup.amazonaws.com to the Service principals of %s's AssumeRolePolicyDocument", [role]),
	"https://docs.aws.amazon.com/aws-backup/latest/devguide/iam-service-roles.html") if {
	some name in resources_of_type("AWS::Backup::BackupSelection")
	sel := input.resources[name].properties.BackupSelection
	is_object(sel)
	role := _pf_iamlib_role_without_service(object.get(sel, "IamRoleArn", null), "backup.amazonaws.com")
}
