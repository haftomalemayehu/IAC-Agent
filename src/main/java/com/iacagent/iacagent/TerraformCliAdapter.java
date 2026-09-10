package com.iacagent.iacagent;

public class TerraformCliAdapter {
    private final CommandRunner commandRunner;

    public TerraformCliAdapter(CommandRunner commandRunner) {
        this.commandRunner = commandRunner;
    }

    public CommandResult initBackendFalse(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "init", "-backend=false", "-input=false");
    }

    public CommandResult init(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "init", "-input=false");
    }

    public CommandResult fmtCheck(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "fmt", "-check", "-recursive");
    }

    public CommandResult validate(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "validate", "-json");
    }

    public CommandResult providerSchema(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "providers", "schema", "-json");
    }

    public CommandResult lint(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "tflint", "--recursive");
    }

    public CommandResult security(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "checkov", "-d", ".");
    }

    public CommandResult test(String workingDirectory) {
        return commandRunner.guard(workingDirectory, "terraform", "test", "-json");
    }

    public CommandResult plan(String workingDirectory, String planPath) {
        return commandRunner.guard(workingDirectory, "terraform", "plan", "-input=false", "-lock=false", "-out=" + planPath);
    }

    public CommandResult showPlanJson(String workingDirectory, String planPath) {
        return commandRunner.guard(workingDirectory, "terraform", "show", "-json", planPath);
    }
}
