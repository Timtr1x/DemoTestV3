"""E6 Weaponized / MITRE."""
from __future__ import annotations

import sys

from core.registry import BaseProject, default_cli, register
from core.schema import Sample
from projects._common import build_from_spec


@register("e6")
class E6Project(BaseProject):
    module_name = "e6_weaponized"

    def build_samples_for_manifest(self, spec: dict) -> tuple[list[Sample], dict[str, str]]:
        return build_from_spec(self.project_id, spec)


def main(argv=None) -> int:
    return default_cli(E6Project(), argv)


if __name__ == "__main__":
    sys.exit(main())
