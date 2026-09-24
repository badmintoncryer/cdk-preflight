package cdk_preflight

import rego.v1

# deploy_region は enforce モードで具体的なリージョンが分かっているときだけ定義される。
# マルチリージョンキー (mrk-) はレプリカが同じキー ID で各リージョンに居るので除外する
# （先例: pf-cloudtrail-trail-kms-key-region / pf-agentcore-kms-key-region）。

violation contains make_diag_full("pf-backup-vault-encryption-key-region", "ERROR", name,
	"Properties.EncryptionKeyArn",
	sprintf("The KMS key lives in '%s' but the stack deploys to '%s'; AWS Backup cannot encrypt a vault with a key from another region", [keyRegion, region]),
	"Reference a KMS key in the deploy region, or drop EncryptionKeyArn to use the AWS managed key",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-backupvault.html") if {
	some name in resources_of_type("AWS::Backup::BackupVault")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.EncryptionKeyArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kms"
	keyRegion := parts[3]
	keyRegion != ""
	keyRegion != region
	not startswith(parts[5], "key/mrk-")
}
