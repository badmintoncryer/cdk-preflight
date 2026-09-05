package cdk_preflight

import rego.v1

_pf_ssmmt_url := "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_RegisterTaskWithMaintenanceWindow.html"

_pf_ssmmt_fix := "Add Targets (Key WindowTargetIds/InstanceIds) plus MaxConcurrency and MaxErrors, keep only the TaskInvocationParameters block matching TaskType, and set ServiceRoleArn when notifications are configured"

_pf_ssmmt_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_ssmmt_targets(name) := t if {
	t := object.get(_pf_ssmmt_props(name), "Targets", null)
	is_array(t)
	count(t) > 0
}

_pf_ssmmt_has(name, k) if object.get(_pf_ssmmt_props(name), k, "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	"Properties.Targets",
	"RUN_COMMAND tasks need at least one target; RegisterTaskWithMaintenanceWindow fails with \"For Run Command tasks, you must specify at least one resource as the target of the task.\"",
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	resolve(name, "Properties.TaskType") == "RUN_COMMAND"
	_pf_ssmmt_props(name)
	not _pf_ssmmt_targets(name)
}

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s is required when Targets are set; RegisterTaskWithMaintenanceWindow fails with \"Max Errors must be a number of at least 0, or a percentage between 0 and 100 Max Concurrency must be a number greater than 0, or a percentage between 1 and 100\"", [k]),
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	_pf_ssmmt_targets(name)
	some k in ["MaxConcurrency", "MaxErrors"]
	not _pf_ssmmt_has(name, k)
}

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s cannot be set on a task without Targets; RegisterTaskWithMaintenanceWindow fails with \"Maintenance window tasks without targets do not support %s values.\"", [k, k]),
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	_pf_ssmmt_props(name)
	not _pf_ssmmt_targets(name)
	some k in ["MaxConcurrency", "MaxErrors"]
	_pf_ssmmt_has(name, k)
}

_pf_ssmmt_blocks := {
	"RUN_COMMAND": "MaintenanceWindowRunCommandParameters",
	"AUTOMATION": "MaintenanceWindowAutomationParameters",
	"LAMBDA": "MaintenanceWindowLambdaParameters",
	"STEP_FUNCTIONS": "MaintenanceWindowStepFunctionsParameters",
}

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	sprintf("Properties.TaskInvocationParameters.%s", [k]),
	sprintf("%s does not belong to a %s task (use %s); RegisterTaskWithMaintenanceWindow fails with \"Task Invocation Parameters must contain an entry only for the Task Type specified in the Window Task.\"", [k, t, _pf_ssmmt_blocks[t]]),
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	t := resolve(name, "Properties.TaskType")
	_pf_ssmmt_blocks[t]
	tip := object.get(_pf_ssmmt_props(name), "TaskInvocationParameters", null)
	is_object(tip)
	some k, _ in tip
	k != _pf_ssmmt_blocks[t]
}

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	sprintf("Properties.Targets.%d.Key", [i]),
	sprintf("target key '%s' is not WindowTargetIds or InstanceIds; RegisterTaskWithMaintenanceWindow fails with \"%s is an invalid window task target type, use WindowTargetIds or InstanceIds.\"", [k, k]),
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	some i, _ in _pf_ssmmt_targets(name)
	k := resolve(name, sprintf("Properties.Targets.%d.Key", [i]))
	is_string(k)
	not k in ["WindowTargetIds", "InstanceIds"]
}

violation contains make_diag_full("pf-ssm-maintenance-window-task", "ERROR", name,
	"Properties.TaskInvocationParameters.MaintenanceWindowRunCommandParameters.ServiceRoleArn",
	"a NotificationConfig needs a ServiceRoleArn in the Run Command parameters; RegisterTaskWithMaintenanceWindow fails with \"ServiceRoleArn of RunCommandInvocationParameter is required if NotificationConfig is specified\"",
	_pf_ssmmt_fix, _pf_ssmmt_url) if {
	some name in resources_of_type("AWS::SSM::MaintenanceWindowTask")
	rc := object.get(object.get(_pf_ssmmt_props(name), "TaskInvocationParameters", {}), "MaintenanceWindowRunCommandParameters", null)
	is_object(rc)
	object.get(rc, "NotificationConfig", "__pf_absent") != "__pf_absent"
	object.get(rc, "ServiceRoleArn", "__pf_absent") == "__pf_absent"
}
