package cdk_preflight

import rego.v1

_pf_ssmmc_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CreateMaintenanceWindow.html"

_pf_ssmmc_fix := "Set Cutoff to at most Duration - 1"

_pf_ssmmc_num(v) := v if is_number(v)

_pf_ssmmc_num(v) := to_number(v) if {
	is_string(v)
	regex.match("^[0-9]+$", v)
}

violation contains make_diag_full("pf-ssm-maintenance-window-cutoff", "ERROR", name,
	"Properties.Cutoff",
	sprintf("Cutoff %v is not smaller than Duration %v; CreateMaintenanceWindow fails with \"Cutoff was %v but must be smaller than %v (Duration - 1)\"", [c, d, c, d - 1]),
	_pf_ssmmc_fix, _pf_ssmmc_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindow")
	c := _pf_ssmmc_num(resolve(name, "Properties.Cutoff"))
	d := _pf_ssmmc_num(resolve(name, "Properties.Duration"))
	c >= d
}
