package cdk_preflight

import rego.v1

_pf_rssppt_levels := {1, 25, 50, 75, 100}

violation contains make_diag_full("pf-redshiftserverless-price-performance-level-enum", "ERROR", name,
	"Properties.PricePerformanceTarget.Level",
	sprintf("PricePerformanceTarget.Level %v is not one of 1, 25, 50, 75 or 100; CreateWorkgroup fails with \"The specified pricePerformanceTargetLevel is invalid. Valid levels are 1, 25, 50, 75, and 100.\"", [l]),
	"Use one of the five levels: 1 (lowest cost), 25, 50, 75 or 100 (highest performance)",
	"https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_PerformanceTarget.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	l := to_number(resolve(name, "Properties.PricePerformanceTarget.Level"))
	not l in _pf_rssppt_levels
}
