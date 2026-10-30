"""Shared typed interfaces for clients, source inference, and broker handlers.

Contracts are registered by trusted application setup, never by tool input.
Generated clients use grant-scoped framework dispatch, either locally for admitted
tools or through an authenticated object broker. Binding an implementation is trusted setup, not proof of its internals.
"""

from __future__ import annotations

import inspect
import secrets
import types
from abc import ABC
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from functools import wraps
from types import MappingProxyType
from typing import (
    Any,
    Generic,
    Protocol,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    is_typeddict,
)

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.object_policy import EnforcementKind, ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceMediatorAdapter,
    ResourceSupport,
)
from langgraph.prebuilt.security.types import _decision_arguments

T = TypeVar("T")
_SCALARS = {str, int, bool, float}
_invocation: ContextVar[ResourceInvocation | None] = ContextVar(
    "typed_resource_invocation", default=None
)
_clients: dict[int, ClientBinding] = {}
_exports: dict[str, ClientBinding] = {}

ResourceAssessment = Callable[[ObjectGrantLine, HostAttestation], ResourceSupport]
ResourcePreflight = Callable[[tuple[ObjectGrantLine, ...], ResourceInvocation], None]
ResourceActivation = Callable[[tuple[ObjectGrantLine, ...], ResourceInvocation], None]
ResourceRelease = Callable[[ResourceInvocation], None]


class ResourceMediator(Protocol):
    """Parent-side lowering assessment and custom request validation.

    `assess` reports whether the backend can enforce a resource permission.
    In `validate`, raise to reject a request; return None to allow it. Arguments are immutable
    validated data. Selector-based APIs also include the grant-bound selector. This hook cannot
    replace the backend, rewrite arguments, or skip framework authorization.
    """

    def assess(
        self, line: ObjectGrantLine, host: HostAttestation
    ) -> ResourceSupport: ...

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None: ...


def current_invocation() -> ResourceInvocation:
    """Return authenticated context inside a typed backend method only."""
    context = _invocation.get()
    if context is None:
        raise PermissionError("no active resource invocation")
    return context


def _native_dictionary(value: Any) -> dict[str, Any]:
    """Snapshot native transport keys before copying, hashing or lookup."""
    if type(value) is not dict:
        raise TypeError("typed data requires a plain dictionary")
    pairs = tuple(value.items())
    result = {}
    for key, item in pairs:
        if type(key) is not str:
            raise TypeError("typed data keys must be plain strings")
        result[key] = item
    return result


def _compile_value_validator(annotation: Any) -> tuple[Any, ...]:
    """Compile trusted type metadata into an immutable runtime validator."""
    if annotation in _SCALARS:
        return ("scalar", annotation)
    if annotation is type(None):
        return ("none",)
    if get_origin(annotation) in (Union, types.UnionType):
        return (
            "union",
            tuple(_compile_value_validator(item) for item in get_args(annotation)),
        )
    if is_typeddict(annotation):
        fields = get_type_hints(annotation)
        return (
            "typed_dict",
            tuple(
                (name, _compile_value_validator(field))
                for name, field in fields.items()
            ),
        )
    raise TypeError("unsupported resource result annotation")


def _check_compiled_value(value: Any, validator: tuple[Any, ...]) -> bool:
    kind = validator[0]
    if kind == "scalar":
        return type(value) is validator[1]
    if kind == "none":
        return value is None
    if kind == "union":
        return any(_check_compiled_value(value, item) for item in validator[1])
    if kind == "typed_dict":
        try:
            snapshot = _native_dictionary(value)
        except TypeError:
            return False
        fields = validator[1]
        return len(snapshot) == len(fields) and all(
            name in snapshot and _check_compiled_value(snapshot[name], field)
            for name, field in fields
        )
    return False


def _supported_result(annotation: Any) -> bool:
    if annotation in _SCALARS or annotation is type(None):
        return True
    if get_origin(annotation) in (Union, types.UnionType):
        return all(_supported_result(item) for item in get_args(annotation))
    if is_typeddict(annotation):
        return all(
            _supported_result(item) for item in get_type_hints(annotation).values()
        )
    return False


@dataclass(frozen=True)
class MethodContract:
    name: str
    signature: inspect.Signature
    parameters: Mapping[str, type]
    result: Any
    result_validator: tuple[Any, ...]

    def arguments(
        self, args: tuple[Any, ...], kwargs: Mapping[str, Any]
    ) -> dict[str, Any]:
        bound = self.signature.bind(*args, **kwargs)
        values = dict(bound.arguments)
        for name, value in values.items():
            if type(value) is not self.parameters[name]:
                raise TypeError(
                    f"{self.name}.{name} requires {self.parameters[name].__name__}"
                )
        return values

    def accepts_result(self, value: Any) -> bool:
        """Validate a result without repeating trusted annotation introspection."""
        return _check_compiled_value(value, self.result_validator)


@dataclass(frozen=True)
class ClientBinding:
    client: Any
    contract: ResourceContract[Any]
    methods: Mapping[str, Callable[..., Any]]
    codes: Mapping[str, types.CodeType]

    def validate(self) -> None:
        for name, function in self.methods.items():
            if (
                vars(type(self.client)).get(name) is not function
                or function.__code__ is not self.codes[name]
            ):
                raise PermissionError("typed resource client method changed")

    def models(self, prefix: str):
        from langgraph.prebuilt.security.manifest_consistency import ManifestOperation

        self.validate()
        return tuple(
            ManifestOperation(
                f"{prefix}.{name}",
                self.contract.class_name,
                name,
                self.contract.resource_parameter,
                tuple(method.parameters).index(self.contract.resource_parameter)
                if self.contract.resource_parameter is not None
                else 0,
                fixed_resource=self.contract._object_id,
                parameters=tuple(method.parameters),
                parameter_types=tuple(
                    kind.__name__ for kind in method.parameters.values()
                ),
                result_type="dict"
                if is_typeddict(method.result)
                else getattr(method.result, "__name__", None),
                lowering=self.contract.lowering,
            )
            for name, method in self.contract.methods.items()
        )


def client_binding(value: Any) -> ClientBinding | None:
    """Resolve a registered instance by identity, without invoking its methods."""
    binding = _clients.get(id(value))
    return binding if binding is not None and binding.client is value else None


def exported_client_models():
    """Known imports for source-only analysis; never import candidate source."""
    # Loading the framework catalog is distinct from executing candidate imports.
    from langgraph.prebuilt.security.mediators import (
        records as _records_module,  # noqa: F401
    )

    return tuple(
        model for name, binding in _exports.items() for model in binding.models(name)
    )


@dataclass(frozen=True, init=False)
class ResourceContract(Generic[T]):
    """Typed resource definition, optionally bound to a parent implementation.

    Bind during construction or with `bind`; both require an explicit support
    assessment through the mediator (or `assess` when no mediator is supplied).
    Omit `resource_parameter` for an object-bound API. Register the binding with
    `ObjectBrokerDispatcher(resources=...)` or `cedar_security(resources=...)`. A custom
    `mediator` adds validation but never replaces grant or type enforcement.
    """

    interface: type[T]
    class_name: str
    object_kind: str
    resource_parameter: str | None
    _object_id: str | None
    _implementation: T | None = field(repr=False, compare=False)
    lowering: str
    methods: Mapping[str, MethodContract]
    _adapter: ResourceMediatorAdapter | None = field(repr=False, compare=False)

    def __init__(
        self,
        interface: type[T],
        *,
        class_name: str,
        object_kind: str,
        resource_parameter: str | None = None,
        lowering: str,
        implementation: T | None = None,
        mediator: ResourceMediator | None = None,
        assess: ResourceAssessment | None = None,
        preflight: ResourcePreflight | None = None,
        activate: ResourceActivation | None = None,
        release: ResourceRelease | None = None,
    ) -> None:
        if interface.__bases__ != (ABC,) or vars(interface).get("__slots__") != ():
            raise TypeError(
                "resource interfaces must directly extend ABC with empty slots"
            )
        if not all(
            part.isidentifier()
            for part in (class_name, object_kind)
            + ((resource_parameter,) if resource_parameter is not None else ())
        ):
            raise ValueError("resource contract names must be identifiers")
        if not lowering or any(not part.isidentifier() for part in lowering.split(".")):
            raise ValueError("lowering must be a dotted identifier")
        methods = {}
        for name, function in vars(interface).items():
            if name in {
                "__module__",
                "__doc__",
                "__slots__",
                "__abstractmethods__",
                "_abc_impl",
                "__annotations__",
                "__firstlineno__",
                "__static_attributes__",
            }:
                continue
            if (
                not inspect.isfunction(function)
                or not getattr(function, "__isabstractmethod__", False)
                or name.startswith("_")
            ):
                raise TypeError(
                    "resource interfaces contain only abstract operation methods"
                )
            parameters = list(inspect.signature(function).parameters.values())
            if not parameters or parameters[0].name != "self":
                raise TypeError("resource methods require self")
            hints = get_type_hints(function)
            signature = inspect.Signature(parameters[1:])
            if any(
                p.kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD
                or p.default is not inspect.Parameter.empty
                or hints.get(p.name) not in _SCALARS
                for p in parameters[1:]
            ):
                raise TypeError(
                    "resource arguments must be required, named, typed scalars"
                )
            if resource_parameter is not None and (
                hints.get(resource_parameter) is not str
                or resource_parameter not in signature.parameters
            ):
                raise TypeError("resource selector must be a string parameter")
            result = hints.get("return")
            if result is None or not _supported_result(result):
                raise TypeError(
                    "resource results require scalar or fixed TypedDict annotations"
                )
            methods[name] = MethodContract(
                name,
                signature,
                MappingProxyType({p.name: hints[p.name] for p in parameters[1:]}),
                result,
                _compile_value_validator(result),
            )
        if not methods:
            raise TypeError("resource interface has no operations")
        for name, value in (
            ("interface", interface),
            ("class_name", class_name),
            ("object_kind", object_kind),
            ("resource_parameter", resource_parameter),
            ("lowering", lowering),
            ("methods", MappingProxyType(methods)),
            ("_adapter", None),
            ("_implementation", implementation),
            (
                "_object_id",
                secrets.token_hex(24) if resource_parameter is None else None,
            ),
        ):
            object.__setattr__(self, name, value)
        if implementation is None:
            if any(
                value is not None
                for value in (mediator, assess, preflight, activate, release)
            ):
                raise ValueError("binding options require an implementation")
        else:
            invoke = self.bind_backend(implementation, mediator=mediator)
            if mediator is not None:
                if assess is not None:
                    raise ValueError(
                        "provide mediator.assess, not a separate assess callback"
                    )
                assessment = getattr(mediator, "assess", None)
            else:
                assessment = assess
            if not callable(assessment):
                raise TypeError(
                    "resource binding requires mediator.assess or an explicit assess callback without a mediator"
                )
            if inspect.iscoroutinefunction(assessment) or inspect.isasyncgenfunction(
                assessment
            ):
                raise TypeError("resource assessment must be synchronous")

            def assess_contract(
                line: ObjectGrantLine, host: HostAttestation
            ) -> ResourceSupport:
                if not self._matches(line):
                    return ResourceSupport(
                        SupportLevel.UNSUPPORTED,
                        "resource line does not match typed contract",
                    )
                support = assessment(line, host)
                if not isinstance(support, ResourceSupport):
                    raise TypeError("assessment must return ResourceSupport")
                return support

            object.__setattr__(
                self,
                "_adapter",
                ResourceMediatorAdapter(
                    self.lowering + (":" + self._object_id if self._object_id else ""),
                    assess_contract,
                    invoke,
                    preflight=preflight,
                    activate=activate,
                    release=release,
                ),
            )

    def _matches(self, line: ObjectGrantLine) -> bool:
        return (
            line.class_name == self.class_name
            and line.lowering == self.lowering
            and line.enforcer
            in (
                {EnforcementKind.BROKER, EnforcementKind.LANGUAGE_SANDBOX}
                if self._object_id
                else {EnforcementKind.BROKER}
            )
            and (self._object_id is None or line.selector == self._object_id)
            and not line.attributes
            and line.operation in self.methods
        )

    @property
    def adapter(self) -> ResourceMediatorAdapter:
        """Parent-only adapter for explicit broker registration."""
        if self._adapter is None:
            raise ValueError("resource contract has no bound implementation")
        return self._adapter

    def bind(
        self,
        *,
        implementation: T,
        assess: ResourceAssessment | None = None,
        mediator: ResourceMediator | None = None,
        preflight: ResourcePreflight | None = None,
        activate: ResourceActivation | None = None,
        release: ResourceRelease | None = None,
    ) -> ResourceContract[T]:
        """Return a new binding; preserve this contract and any existing clients."""
        bound = ResourceContract(
            self.interface,
            class_name=self.class_name,
            object_kind=self.object_kind,
            resource_parameter=self.resource_parameter,
            lowering=self.lowering,
            implementation=implementation,
            mediator=mediator,
            assess=assess,
            preflight=preflight,
            activate=activate,
            release=release,
        )

        bound._preserve_identity(self)
        return bound

    def _preserve_identity(self, source: ResourceContract[T]) -> None:
        object.__setattr__(self, "_object_id", source._object_id)
        if self._adapter is not None and self._object_id:
            object.__setattr__(
                self,
                "_adapter",
                replace(
                    self._adapter, adapter_id=self.lowering + ":" + self._object_id
                ),
            )

    @property
    def reference(self):
        """Return the framework-owned broker address, without exposing a backend."""
        from langgraph.prebuilt.security.mediators.objects import ResourceReference
        from langgraph.prebuilt.security.object_broker import _service

        if self._object_id is None:
            raise ValueError("selector-based contracts have no single object reference")
        return ResourceReference(_service(self.class_name, self._object_id))

    def permission(self, operation: str, requirement: str = "need") -> str:
        """Declare access to this object without managing a selector string."""
        if self._object_id is None:
            raise ValueError(
                "selector-based contracts require explicit manifest selectors"
            )
        if operation not in self.methods or requirement not in {"need", "want"}:
            raise ValueError("invalid object permission")
        return f"{self.class_name} {operation} {self._object_id} {requirement}"

    def class_declaration(self, *, enforced_by: str = "broker") -> str:
        """Generate the matching SLP class declaration from this contract."""
        return (
            f"class {self.class_name} {{\n  operations {' '.join(self.methods)}\n"
            f"  object {self.object_kind}\n  normalizer identity\n  attrs\n"
            f"  enforced_by {enforced_by}\n  lowering {self.lowering}\n}}\n"
        )

    def client(self, *, export: str) -> T:
        """Generate an immutable broker client and register its approved import."""
        if self._adapter is not None:
            # Client closures and inference metadata must not retain a privileged
            # implementation, custom validator, or support/lifecycle callback.
            definition = ResourceContract(
                self.interface,
                class_name=self.class_name,
                object_kind=self.object_kind,
                resource_parameter=self.resource_parameter,
                lowering=self.lowering,
            )
            definition._preserve_identity(self)
            return definition.client(export=export)
        if export in _exports or not all(
            part.isidentifier() for part in export.split(".")
        ):
            raise ValueError("client export must be a unique qualified name")

        def make_method(method: MethodContract):
            @wraps(getattr(self.interface, method.name))
            def invoke(instance, *args, **kwargs):
                from langgraph.prebuilt.security.object_broker import object_request

                binding = client_binding(instance)
                if binding is None:
                    raise PermissionError("unregistered resource client")
                binding.validate()
                values = method.arguments(args, kwargs)
                if self._object_id is not None:
                    from langgraph.prebuilt.security.mediators.objects import (
                        request_object,
                    )

                    result = request_object(
                        self._object_id, export, method.name, values
                    )
                else:
                    selector = values.pop(self.resource_parameter)
                    result = object_request(
                        self.class_name, method.name, selector, values
                    )
                if not method.accepts_result(result):
                    raise TypeError(f"invalid {self.class_name}.{method.name} result")
                return result

            invoke.__isabstractmethod__ = False
            return invoke

        methods = {name: make_method(method) for name, method in self.methods.items()}
        client_type = type(
            f"_{self.interface.__name__}Client",
            (self.interface,),
            {"__slots__": (), **methods},
        )
        client = client_type()
        binding = ClientBinding(
            client,
            self,
            MappingProxyType(methods),
            MappingProxyType(
                {name: method.__code__ for name, method in methods.items()}
            ),
        )
        _clients[id(client)] = binding
        _exports[export] = binding
        return client

    def bind_backend(self, backend: T, *, mediator: ResourceMediator | None = None):
        """Validate all backend methods now and build the broker invocation hook."""
        validate = None if mediator is None else getattr(mediator, "validate", None)
        if mediator is not None and not callable(validate):
            raise TypeError("custom mediator requires a validate method")
        if inspect.iscoroutinefunction(validate) or inspect.isasyncgenfunction(
            validate
        ):
            raise TypeError("custom mediator validation must be synchronous")
        if not isinstance(backend, self.interface):
            raise TypeError("backend must implement the resource interface")
        handlers = {}
        for name, method in self.methods.items():
            handler = getattr(backend, name)
            signature = inspect.signature(handler)
            hints = get_type_hints(handler)
            if (
                tuple(signature.parameters) != tuple(method.parameters)
                or any(
                    hints.get(key) != kind for key, kind in method.parameters.items()
                )
                or hints.get("return") != method.result
                or any(
                    p.default is not inspect.Parameter.empty
                    or p.kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD
                    for p in signature.parameters.values()
                )
            ):
                raise TypeError(
                    f"backend signature does not match {self.class_name}.{name}"
                )
            handlers[name] = handler

        def invoke(
            line: ObjectGrantLine,
            payload: Mapping[str, Any],
            context: ResourceInvocation,
        ):
            if not self._matches(line):
                raise PermissionError("resource line does not match typed contract")
            method = self.methods[line.operation]
            try:
                payload = _decision_arguments(payload)
            except TypeError as exc:
                raise ValueError("invalid typed resource payload") from exc
            if self.resource_parameter in payload:
                raise ValueError("payload cannot replace the authorized resource")
            try:
                values = method.arguments(
                    (),
                    (
                        {self.resource_parameter: line.selector, **payload}
                        if self.resource_parameter is not None
                        else payload
                    ),
                )
            except TypeError as exc:
                raise ValueError("invalid typed resource payload") from exc
            token = _invocation.set(context)
            try:
                if validate is not None:
                    if (
                        validate(line.operation, MappingProxyType(values), context)
                        is not None
                    ):
                        raise TypeError(
                            "custom mediator must return None or raise to reject"
                        )
                result = handlers[line.operation](**values)
                if not method.accepts_result(result):
                    raise TypeError("backend returned an invalid typed result")
                return result
            finally:
                _invocation.reset(token)

        return invoke


def object_bindings(resources):
    """Resolve worker import aliases to parent-owned identities during trusted setup."""
    from langgraph.prebuilt.security.object_broker import _service

    identities = [resource._object_id for resource in resources]
    if None in identities or len(set(identities)) != len(identities):
        raise ValueError("resources must have distinct object identities")
    implementations = [
        id(resource._implementation)
        for resource in resources
        if resource._implementation is not None
    ]
    if len(set(implementations)) != len(implementations):
        raise ValueError(
            "one implementation object cannot have multiple resource identities"
        )
    return {
        "resource:" + export: _service(
            binding.contract.class_name, binding.contract._object_id
        )
        for export, binding in _exports.items()
        if binding.contract._object_id in identities
    }
