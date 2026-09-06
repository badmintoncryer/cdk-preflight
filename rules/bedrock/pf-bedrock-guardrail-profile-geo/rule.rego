package cdk_preflight

import rego.v1

# Guardrail profiles are bound to a geography and can only be used from that
# geography's source Regions (guardrails-cross-region-support.html, read
# 2026-09-06); any other pairing fails CreateGuardrail with "Guardrail
# cross-Region profile ID is invalid". Unknown Regions / prefixes are not judged.
_pf_gpge_sources := {
	"us": {"us-east-1", "us-east-2", "us-west-1", "us-west-2"},
	"eu": {"eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2", "il-central-1"},
	"uk": {"eu-west-2"},
	"au": {"ap-southeast-2"},
	"ca": {"ca-central-1"},
	"apac": {"ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7", "ap-east-2", "me-central-1"},
}

# Every Region the table knows about, so a Region outside it is skipped.
_pf_gpge_known := {r | some g, rs in _pf_gpge_sources; some r in rs}

_pf_gpge_geo(arn) := g if {
	is_string(arn)
	parts := split(arn, "guardrail-profile/")
	count(parts) == 2
	g := split(parts[1], ".")[0]
}

_pf_gpge_bad(g, region) if {
	_pf_gpge_known[region]
	srcs := _pf_gpge_sources[g]
	not srcs[region]
}

_pf_gpge_bad(g, region) if {
	g == "us-gov"
	not startswith(region, "us-gov-")
}

violation contains make_diag_full("pf-bedrock-guardrail-profile-geo", "ERROR", name,
	"Properties.CrossRegionConfig.GuardrailProfileArn",
	sprintf("Guardrail profile '%s' is not usable from Region '%s'; CreateGuardrail fails with \"Guardrail cross-Region profile ID is invalid. Specify a guardrail profile ID that's supported in your current AWS Region\"", [g, region]),
	"Use the profile of the deploy Region's geography (us., eu., uk., au., ca., apac. or us-gov.)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region-support.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	region := _pf_bedrocklib_region
	g := _pf_gpge_geo(resolve(name, "Properties.CrossRegionConfig.GuardrailProfileArn"))
	_pf_gpge_bad(g, region)
}
