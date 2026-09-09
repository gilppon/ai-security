from typing import Any

import yaml
from pydantic import ValidationError

from detection.models import AISecRule


class DuplicateKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: DuplicateKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, (str, int, float, bool, type(None))):
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unsupported mapping key",
                key_node.start_mark,
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class RuleParseError(ValueError):
    pass


class AISecRuleParser:
    MAX_RULE_BYTES = 65_536

    def parse(self, source: str) -> AISecRule:
        if not source.strip():
            raise RuleParseError("rule source must not be empty")
        if len(source.encode("utf-8")) > self.MAX_RULE_BYTES:
            raise RuleParseError("rule source exceeds size limit")
        try:
            if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(source)):
                raise RuleParseError("YAML aliases are not allowed")
            payload = yaml.load(source, Loader=DuplicateKeySafeLoader)
        except RuleParseError:
            raise
        except yaml.YAMLError as exc:
            raise RuleParseError("invalid AISec YAML") from exc
        if not isinstance(payload, dict):
            raise RuleParseError("AISec rule must be a mapping")
        try:
            return AISecRule.model_validate(payload)
        except ValidationError as exc:
            raise RuleParseError("AISec rule schema validation failed") from exc
