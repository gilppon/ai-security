import math

from agent_security.tools.schemas import ArgumentType, ToolDefinition
from pydantic import JsonValue


class ToolArgumentValidator:
    def validate(
        self,
        definition: ToolDefinition,
        arguments: dict[str, JsonValue],
    ) -> tuple[str, ...]:
        specs = {item.name: item for item in definition.arguments}
        errors: list[str] = []
        for name in sorted(set(arguments) - set(specs)):
            errors.append(f"UNEXPECTED_ARGUMENT:{name}")
        for name, spec in specs.items():
            if spec.required and name not in arguments:
                errors.append(f"MISSING_ARGUMENT:{name}")
                continue
            if name not in arguments:
                continue
            value = arguments[name]
            if not self._matches_type(value, spec.argument_type):
                errors.append(f"INVALID_ARGUMENT_TYPE:{name}")
                continue
            if isinstance(value, (str, list, dict)) and len(value) > spec.max_length:
                errors.append(f"ARGUMENT_TOO_LARGE:{name}")
            if spec.allowed_values and value not in spec.allowed_values:
                errors.append(f"ARGUMENT_VALUE_DENIED:{name}")
        return tuple(errors)

    @staticmethod
    def _matches_type(value: JsonValue, expected: ArgumentType) -> bool:
        if expected is ArgumentType.STRING:
            return isinstance(value, str)
        if expected is ArgumentType.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)
        if expected is ArgumentType.NUMBER:
            return (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and (not isinstance(value, float) or math.isfinite(value))
            )
        if expected is ArgumentType.BOOLEAN:
            return isinstance(value, bool)
        if expected is ArgumentType.OBJECT:
            return isinstance(value, dict)
        if expected is ArgumentType.ARRAY:
            return isinstance(value, list)
        return False

