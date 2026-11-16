from governance.validators import (
    appsec,
    banking,
    changeset,
    cicd,
    code,
    containers,
    kubernetes,
    shell,
    terraform,
    terragrunt,
)
from governance.validators.base import FileSet, Finding, Validator

MODULES = (code, terraform, terragrunt, kubernetes, containers, cicd, shell, changeset, banking, appsec)
BUILTIN: dict[str, Validator] = {v.id: v for module in MODULES for v in module.VALIDATORS}

__all__ = ["BUILTIN", "FileSet", "Finding", "Validator"]
