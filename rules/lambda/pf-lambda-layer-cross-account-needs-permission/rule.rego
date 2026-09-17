package cdk_preflight

import rego.v1

# A function can attach a layer version that its own account owns, one that
# AWS publishes for every account, or one whose owner shared it through
# AddLayerVersionPermission. That share is invisible in the consumer's template
# (only the owner can write the LayerVersionPermission), so a literal ARN of
# another account may or may not deploy: the rule reports it as a WARN, never
# as an error (issue #238). The deploy account is data.cdk_preflight.deploy_account,
# so the rule is silent unless the app has a concrete account (enforce mode);
# the engine substitutes ${AWS::AccountId} with that same account before the
# rule runs, so a Fn::Sub over the pseudo parameter reads as the account's own.
_pf_llcp_fix := "Ask the layer's owner to share it with AddLayerVersionPermission, or publish the layer in the deploy account"

_pf_llcp_url := "https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html"

# Accounts AWS publishes layers from, with lambda:GetLayerVersion granted to
# every principal: Lambda Insights, the AppConfig and Parameters-and-Secrets
# extensions, and the aws-otel ADOT layers. Generated from aws-cdk-lib 2.267.0
# region-info on 2026-09-17 (test/lambda-layer-publishers.test.ts fails when
# the installed region-info knows an account this table lacks), plus
# 615299751070, the account behind the AWSOpenTelemetryDistro* layers, which
# region-info does not carry yet. One entry per line: the engine caps a Rego
# line at 1024 columns.
_pf_llcp_aws_publishers := {
	"000010852771",
	"012438385374",
	"015030872274",
	"027255383542",
	"033019950311",
	"039592058896",
	"044395824272",
	"066549572091",
	"066940009817",
	"070087711984",
	"080788657173",
	"122132214140",
	"127562683043",
	"129776340158",
	"133256977650",
	"133490724326",
	"145023102084",
	"158895979263",
	"176022468876",
	"177933569100",
	"187925254637",
	"194566237122",
	"198461476570",
	"200266452380",
	"203683718741",
	"282860088358",
	"285320876703",
	"287114880934",
	"287310001119",
	"307021474294",
	"317013901791",
	"325218067255",
	"339249233099",
	"345057560386",
	"352183217350",
	"359756378197",
	"418787028745",
	"421114256042",
	"427196147048",
	"434848589818",
	"439286490199",
	"459530977127",
	"488211338238",
	"489524808438",
	"490737872127",
	"493207061005",
	"519774774795",
	"524103009944",
	"554480029851",
	"559955524753",
	"574348263942",
	"576959938190",
	"580247275435",
	"586093569114",
	"590183865173",
	"590474943231",
	"605207715842",
	"615057806174",
	"615084187847",
	"615299751070",
	"630222743974",
	"646970417810",
	"662846165436",
	"665172237481",
	"706869817123",
	"727646510379",
	"728743619870",
	"732604637566",
	"738900069198",
	"751350123760",
	"758369105281",
	"761018874580",
	"761377655185",
	"768336418462",
	"772501565639",
	"780235371811",
	"826293736237",
	"832021897121",
	"858974508948",
	"879381266642",
	"891564319516",
	"901920570463",
	"933737806257",
	"946466191631",
	"946561847325",
	"946746059096",
	"958113053741",
	"980059726660",
	"997803712105",
}

violation contains make_diag_full("pf-lambda-layer-cross-account-needs-permission", "WARN", name,
	"Properties.Layers",
	sprintf("layer '%v' belongs to account %v, not the deploy account %v; unless its owner has shared it with AddLayerVersionPermission, CreateFunction fails with \"is not authorized to perform: lambda:GetLayerVersion\"", [arn, parts[4], account]),
	_pf_llcp_fix, _pf_llcp_url) if {
	account := data.cdk_preflight.deploy_account
	some name in _pf_lam_fn
	some arn in _pf_lam_list(_pf_lam_get(name, "Layers"))
	parts := _pf_lam_arn(arn)
	parts[2] == "lambda"
	parts[4] != account
	not parts[4] in _pf_llcp_aws_publishers
}
