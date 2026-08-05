"""E11 Privilege induction (promptfoo frozen)."""
from __future__ import annotations

import sys

from core.registry import BaseProject, default_cli, register
from core.schema import Sample
from projects._common import build_from_spec


@register("e11")
class E11Project(BaseProject):
    module_name = "e11_privilege_induce"

    def build_samples_for_manifest(self, spec: dict) -> tuple[list[Sample], dict[str, str]]:
        return build_from_spec(self.project_id, spec)


def main(argv=None) -> int:
    return default_cli(E11Project(), argv)


if __name__ == "__main__":
    sys.exit(main())
