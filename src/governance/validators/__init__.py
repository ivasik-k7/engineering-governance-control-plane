from governance.validators import appsec, banking, changeset, code, kubernetes, terraform
from governance.validators.base import FileSet, Finding, Validator

BUILTIN: dict[str, Validator] = {
    v.id: v for module in (code, terraform, kubernetes, changeset, banking, appsec) for v in module.VALIDATORS
}

__all__ = ["BUILTIN", "FileSet", "Finding", "Validator"]
