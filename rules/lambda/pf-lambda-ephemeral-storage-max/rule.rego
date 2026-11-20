package cdk_preflight

import rego.v1

# EphemeralStorage.Size tops out at 10240 MB, or 32768 MB for functions that
# set AcceleratorConfig (GPU on Lambda Managed Instances, 2026-11). The engine
# carries the 512 floor but no cap (clean on 10241 with engine 1.12.1 / 1.17.1).
_pf_ephst_cap(name) := 32768 if {
	object.get(input.Resources[name], ["Properties", "AcceleratorConfig"], null) != null
} else := 10240

violation contains make_diag_full("pf-lambda-ephemeral-storage-max", "ERROR", name,
	"Properties.EphemeralStorage.Size",
	sprintf("EphemeralStorage.Size %v is over the %v MB cap for this function; the function create fails", [s, cap]),
	sprintf("Use at most %v MB (32768 MB is allowed only with AcceleratorConfig)", [cap]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	s := _pf_num(name, "Properties.EphemeralStorage.Size")
	cap := _pf_ephst_cap(name)
	s > cap
}
