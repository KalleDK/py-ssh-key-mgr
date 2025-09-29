import dataclasses
import enum
import inspect
from collections.abc import Callable
from io import BytesIO
from typing import (
    Annotated,
    Any,
    ClassVar,
    Mapping,
    Protocol,
    Self,
    TypeGuard,
    cast,
    dataclass_transform,
    final,
    get_args,
    get_origin,
    overload,
    override,
)

from ssh_key_mgr.putty.ppk.base import (
    NOTSET,
    P_TYPES,
    P_TYPES_T,
    R_TYPES_T,
    UNDERLAYING_TYPES,
    UNDERLAYING_TYPES_T,
    Notset,
    hexbytes,
    is_p_types_t,
    is_r_types_t,
)
from ssh_key_mgr.putty.ppk.stream import BytesField, HexField, IntField, StreamReader, StreamWriter, StrField

_PPK_PROTO_TYPE_INFO = "__ppk_proto_type_info__"


def _is_dataclass(cls: type) -> bool:
    return "__dataclass_params__" in cls.__dict__


def _is_classvar(annotation: type) -> bool:
    origin = get_origin(annotation)
    return origin is ClassVar


def is_packet(cls: type) -> bool:
    return hasattr(cls, _PPK_PROTO_TYPE_INFO)


def get_class_info(cls: "File | type[File]") -> "_ClassInfo":
    return getattr(cls, _PPK_PROTO_TYPE_INFO)


def get_parent_class(cls: "type[File]") -> "type[File] | None":
    if is_packet(cls.__bases__[0]):
        return cls.__bases__[0]
    return None


def make_parser[U, O](overlaying_type: Callable[[U], O]) -> Callable[[U], O]:
    def _parser(x: U) -> O:
        return overlaying_type(x)

    return _parser


def make_serializer[U, O](underlaying_type: Callable[[O], U]) -> Callable[[O], U]:
    def _serializer(x: O) -> U:
        return underlaying_type(x)

    return _serializer


class InvalidHeader(RuntimeError):
    pass


# region Protocols

_UNMARSHAL_METHOD_NAME = "unmarshal_ppk"
_MARSHAL_METHOD_NAME = "marshal_ppk"


@dataclasses.dataclass(frozen=True, kw_only=True, eq=True)
class _Signatures:
    unmarshal_sig: inspect.Signature
    marshal_sig: inspect.Signature
    unmarshal_ann: dict[str, type]
    marshal_ann: dict[str, type]

    def get_obj(self) -> type:
        return self.unmarshal_sig.return_annotation

    @classmethod
    def from_cls(cls, c: type) -> Self:
        unmarshal_sshwire = getattr(c, _UNMARSHAL_METHOD_NAME)
        if not callable(unmarshal_sshwire):
            raise TypeError(f"Class {c.__name__} does not have callable {_UNMARSHAL_METHOD_NAME} method")
        marshal_sshwire = getattr(c, _MARSHAL_METHOD_NAME)
        if not callable(marshal_sshwire):
            raise TypeError(f"Class {c.__name__} does not have callable {_MARSHAL_METHOD_NAME} method")
        return cls(
            unmarshal_sig=inspect.signature(unmarshal_sshwire),
            marshal_sig=inspect.signature(marshal_sshwire),
            unmarshal_ann=inspect.get_annotations(unmarshal_sshwire),
            marshal_ann=inspect.get_annotations(marshal_sshwire),
        )

    def replace_obj(self, obj_t: type[Any]):
        unmarshal_sig = self.unmarshal_sig.replace(return_annotation=obj_t)
        params = [p for p in self.marshal_sig.parameters.values()]
        params[0] = params[0].replace(annotation=obj_t)
        marshal_sig = self.marshal_sig.replace(parameters=params)
        unmarshal_ann = dict(self.unmarshal_ann)
        unmarshal_ann["return"] = obj_t
        marshal_ann = dict(self.marshal_ann)
        marshal_ann["obj"] = obj_t
        return _Signatures(
            unmarshal_sig=unmarshal_sig,
            marshal_sig=marshal_sig,
            unmarshal_ann=unmarshal_ann,
            marshal_ann=marshal_ann,
        )


class FieldProto(Protocol):
    @classmethod
    def unmarshal_ppk(cls, stream: StreamReader, parsed: Mapping[str, Any]) -> Self:
        raise NotImplementedError()

    def marshal_ppk(self, stream: StreamWriter) -> None:
        raise NotImplementedError()


_FIELD_PROTO_SIG = _Signatures.from_cls(FieldProto)


def _is_field_proto_t(annotation: type) -> TypeGuard[type[FieldProto]]:
    try:
        sig = _Signatures.from_cls(annotation)
    except Exception:
        return False

    return sig == _FIELD_PROTO_SIG


class FieldClassProto[O](Protocol):
    @classmethod
    def unmarshal_ppk(cls, stream: StreamReader, parsed: Mapping[str, Any]) -> O:
        raise NotImplementedError()

    @classmethod
    def marshal_ppk(cls, obj: O, stream: StreamWriter) -> None:
        raise NotImplementedError()


_FIELD_CLASS_PROTO_SIG = _Signatures.from_cls(FieldClassProto[Any])


def _is_field_class_proto_t(annotation: type) -> TypeGuard[type[FieldClassProto[Any]]]:
    try:
        sig = _Signatures.from_cls(annotation)
        obj = sig.get_obj()
    except Exception:
        return False

    return sig == _FIELD_CLASS_PROTO_SIG.replace_obj(obj)


# endregion


@dataclasses.dataclass
class FieldInfoBase[O]:
    ppkname: str
    fieldname: str
    is_class_var: bool
    is_discriminator: bool
    const_value: O | Notset

    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        raise NotImplementedError()

    def _marshal_value(self, stream: "StreamWriter", obj: O) -> None:
        raise NotImplementedError()

    @final
    def unmarshal(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        o_value = parsed[self.fieldname] if self.fieldname in parsed else self._unmarshal_value(stream, parsed)

        if self.const_value is not NOTSET and o_value != self.const_value:
            raise InvalidHeader(f"Field {self.fieldname} has constant value {self.const_value}, but got {o_value}")

        return o_value

    @final
    def marshal(self, stream: "StreamWriter", obj: O) -> None:
        o_value = getattr(obj, self.fieldname)
        if self.const_value is not NOTSET and o_value != self.const_value:
            raise ValueError(f"Field {self.fieldname} has constant value {self.const_value}, but got {o_value}")
        return self._marshal_value(stream, o_value)


@dataclasses.dataclass
class FieldFileInfo(FieldInfoBase["File"]):
    file_type: type["File"]

    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> "File":
        return _unmarshal(self.file_type, stream)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: "File") -> None:
        _marshal(obj, stream)


@dataclasses.dataclass
class FieldProtoInfo[O: FieldProto](FieldInfoBase[O]):
    custom_type: type[O]

    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        return self.custom_type.unmarshal_ppk(stream, parsed)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: O) -> None:
        return self.custom_type.marshal_ppk(obj, stream)


@dataclasses.dataclass
class _FieldInfoWithUnderlayingType[U: UNDERLAYING_TYPES_T, M: int | str | bytes, O](FieldInfoBase[O]):
    underlaying_type: type[U]

    def _write_value(self, stream: "StreamWriter", value: M) -> None:
        raise NotImplementedError()

    def _read_value(self, stream: "StreamReader") -> M:
        raise NotImplementedError()


# region FieldInfoBase


@dataclasses.dataclass
class _RFieldInfoBase[U: R_TYPES_T, O](_FieldInfoWithUnderlayingType[U, bytes, O]):
    @override
    def _write_value(self, stream: "StreamWriter", value: bytes) -> None:
        match self.underlaying_type:
            case t if t is hexbytes:
                stream.write_hexbytes(HexField(self.ppkname, value))
            case _:
                raise TypeError(f"Unsupported underlaying type: {self.underlaying_type}")

    @override
    def _read_value(self, stream: "StreamReader") -> bytes:
        match self.underlaying_type:
            case t if t is hexbytes:
                field = stream.read_hexbytes()
            case _:
                raise TypeError(f"Unsupported underlaying type: {self.underlaying_type}")
        if field.name != self.ppkname:
            raise ValueError(f"Expected field name {self.ppkname}, but got {field.name}")
        return field.value


@dataclasses.dataclass
class _PFieldInfoBase[U: P_TYPES_T, O](_FieldInfoWithUnderlayingType[U, U, O]):
    @override
    def _write_value(self, stream: "StreamWriter", value: U) -> None:
        match self.underlaying_type:
            case t if t is int and isinstance(value, int):
                stream.write_int(IntField(self.ppkname, value))
            case t if t is str and isinstance(value, str):
                stream.write_str(StrField(self.ppkname, value))
            case t if t is bytes and isinstance(value, bytes):
                stream.write_bytes(BytesField(self.ppkname, value))
            case _:
                raise TypeError(f"Unsupported underlaying type: {self.underlaying_type}")

    @override
    def _read_value(self, stream: "StreamReader") -> U:
        match self.underlaying_type:
            case t if t is int:
                field = stream.read_int()
            case t if t is str:
                field = stream.read_str()
            case t if t is bytes:
                field = stream.read_bytes()
            case _:
                raise TypeError(f"Unsupported underlaying type: {self.underlaying_type}")
        if field.name != self.ppkname:
            raise ValueError(f"Expected field name {self.ppkname}, but got {field.name}")

        return cast(U, field.value)


# endregion

# region FieldInfo


@dataclasses.dataclass
class RFieldInfo[U: R_TYPES_T](_RFieldInfoBase[U, bytes]):
    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> bytes:
        return self._read_value(stream)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: bytes) -> None:
        self._write_value(stream, obj)


@dataclasses.dataclass
class PFieldInfo[O: P_TYPES_T](_PFieldInfoBase[O, O]):
    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        return self._read_value(stream)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: O) -> None:
        self._write_value(stream, obj)


# endregion

# region FullFieldInfo


@dataclasses.dataclass
class FullRFieldInfo[U: R_TYPES_T, O](_RFieldInfoBase[U, O]):
    parser: Callable[[bytes], O]
    serializer: Callable[[O], bytes]

    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        u_value = self._read_value(stream)
        return self.parser(u_value)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: O) -> None:
        u_value = self.serializer(obj)
        self._write_value(stream, u_value)


@dataclasses.dataclass
class FullPFieldInfo[U: P_TYPES_T, O](_PFieldInfoBase[U, O]):
    parser: Callable[[U], O]
    serializer: Callable[[O], U]

    @override
    def _unmarshal_value(self, stream: "StreamReader", parsed: Mapping[str, Any]) -> O:
        u_value = self._read_value(stream)
        return self.parser(u_value)

    @override
    def _marshal_value(self, stream: "StreamWriter", obj: O) -> None:
        u_value = self.serializer(obj)
        self._write_value(stream, u_value)


# endregion


# region Field


@dataclasses.dataclass
class RField:
    typ: type[R_TYPES_T]
    name: str | None = None
    parser: Callable[[bytes], Any] | None = None
    serializer: Callable[[Any], bytes] | None = None


def is_r_field(obj: Any) -> TypeGuard[RField]:
    return isinstance(obj, RField)


@dataclasses.dataclass
class PField[T: P_TYPES_T]:
    typ: type[T]
    name: str | None = None
    parser: Callable[[T], Any] | None = None
    serializer: Callable[[Any], T] | None = None


def is_p_field(obj: Any) -> TypeGuard[PField[Any]]:
    return isinstance(obj, PField)


@dataclasses.dataclass
class NameField:
    name: str


def is_name_field(obj: Any) -> TypeGuard[NameField]:
    return isinstance(obj, NameField)


# endregion

# region field factory


@overload
def field(
    name: str | None = ...,
    *,
    typ: type[R_TYPES_T],
    parser: Callable[[bytes], Any] | None = ...,
    serializer: Callable[[Any], bytes] | None = ...,
) -> RField: ...


@overload
def field[T: P_TYPES_T](
    name: str | None = ...,
    *,
    typ: type[T],
    parser: Callable[[T], Any] | None = ...,
    serializer: Callable[[Any], T] | None = ...,
) -> PField[Any]: ...


@overload
def field(
    name: str,
) -> NameField: ...


def field(
    name: str | None = None,
    typ: type[UNDERLAYING_TYPES_T] | None = None,
    parser: Callable[[Any], Any] | None = None,
    serializer: Callable[[Any], Any] | None = None,
) -> PField[Any] | RField | NameField:
    if name is None and typ is None:
        raise TypeError("Either name or typ must be provided")
    if name is not None and typ is None:
        return NameField(name)
    if is_p_types_t(typ):
        return PField(name=name, typ=typ, parser=parser, serializer=serializer)
    elif is_r_types_t(typ):
        return RField(name=name, typ=typ, parser=parser, serializer=serializer)
    else:
        raise TypeError(f"Unsupported type {typ} for field. Supported types are: {UNDERLAYING_TYPES}")


# endregion


@dataclasses.dataclass
class _ClassInfo:
    header: bool
    children: dict[Any, type["File"]] = dataclasses.field(default_factory=dict[Any, type["File"]])
    fields: dict[str, FieldInfoBase[Any]] = dataclasses.field(default_factory=dict[str, FieldInfoBase[Any]])
    headers: dict[str, Any] = dataclasses.field(default_factory=dict[str, Any])

    def get_descriptor_field(self) -> FieldInfoBase[Any]:
        for field in self.fields.values():
            if field.is_discriminator:
                return field
        raise ValueError("No discriminator field found")

    def get_child(self, parsed: Mapping[str, Any]) -> type["File"]:
        descriptor_field = self.get_descriptor_field()
        descriptor_value = parsed[descriptor_field.fieldname]
        if descriptor_value not in self.children:
            raise ValueError(
                f"Unknown descriptor value {descriptor_value} for field {descriptor_field.fieldname} in class"
            )
        return self.children[descriptor_value]


def _generate_field_info(cls: type, name: str, annotation: type, ppkname: str) -> FieldInfoBase[Any]:
    # region ClassVar
    is_class_var = _is_classvar(annotation)
    if is_class_var:
        annotation = get_args(annotation)[0]

    const_value: Any | Notset = NOTSET
    if is_class_var and hasattr(cls, name):
        const_value = getattr(cls, name)

    is_discriminator = is_class_var and const_value is NOTSET
    # endregion

    is_annotated = get_origin(annotation) is Annotated

    if is_annotated:
        _args = get_args(annotation)
        overlaying_type = _args[0]
        annotations = _args[1:]
    else:
        overlaying_type: type = annotation
        annotations: tuple[Any, ...] = ()

    if _is_field_proto_t(overlaying_type):
        return FieldProtoInfo(
            fieldname=name,
            ppkname=ppkname,
            custom_type=overlaying_type,
            is_class_var=is_class_var,
            is_discriminator=is_discriminator,
            const_value=const_value,
        )

    if not is_annotated:
        if issubclass(overlaying_type, enum.StrEnum):
            return FullPFieldInfo(
                ppkname=ppkname,
                fieldname=name,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=str,
                parser=lambda x: overlaying_type(x),  # type: ignore
                serializer=lambda x: x.value,  # type: ignore
            )
        if issubclass(overlaying_type, File):
            return FieldFileInfo(
                fieldname=name,
                ppkname=ppkname,  # Notused
                file_type=overlaying_type,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
            )
        if overlaying_type not in P_TYPES:
            raise TypeError(
                f"Field {name} in class {cls.__name__} has unsupported type {overlaying_type}. Supported types are: {P_TYPES} and typing.Annotated[...]"
            )
        return PFieldInfo(
            ppkname=ppkname,
            fieldname=name,
            is_class_var=is_class_var,
            is_discriminator=is_discriminator,
            const_value=const_value,
            underlaying_type=overlaying_type,
        )

    for underlaying_type in annotations:
        if is_r_field(underlaying_type):
            _field = underlaying_type
            _underlaying_type = _field.typ
            return FullRFieldInfo(
                fieldname=name,
                ppkname=_field.name if _field.name is not None else ppkname,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=_underlaying_type,
                parser=_field.parser if _field.parser is not None else make_parser(overlaying_type),
                serializer=_field.serializer if _field.serializer is not None else make_serializer(bytes),
            )
        if is_p_field(underlaying_type):
            _field = underlaying_type
            _underlaying_type = _field.typ
            return FullPFieldInfo(
                fieldname=name,
                ppkname=_field.name if _field.name is not None else ppkname,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=_underlaying_type,
                parser=_field.parser if _field.parser is not None else make_parser(overlaying_type),
                serializer=_field.serializer if _field.serializer is not None else make_serializer(_underlaying_type),
            )
        if is_name_field(underlaying_type):
            if overlaying_type not in P_TYPES:
                raise TypeError(
                    f"Field {name} in class {cls.__name__} has unsupported type {overlaying_type}. Supported types are: {P_TYPES} and typing.Annotated[...]"
                )
            _field = underlaying_type
            return PFieldInfo(
                ppkname=_field.name,
                fieldname=name,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=overlaying_type,
            )
        if is_r_types_t(underlaying_type):
            if overlaying_type is bytes:
                return RFieldInfo(
                    ppkname=ppkname,
                    fieldname=name,
                    underlaying_type=underlaying_type,
                    is_class_var=is_class_var,
                    is_discriminator=is_discriminator,
                    const_value=const_value,
                )

            return FullRFieldInfo(
                ppkname=ppkname,
                fieldname=name,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=underlaying_type,
                parser=make_parser(overlaying_type),
                serializer=make_serializer(bytes),
            )
        if is_p_types_t(underlaying_type):
            return FullPFieldInfo(
                fieldname=name,
                ppkname=ppkname,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
                underlaying_type=underlaying_type,
                parser=make_parser(overlaying_type),
                serializer=make_serializer(underlaying_type),
            )
        if _is_field_class_proto_t(underlaying_type):
            return FieldProtoInfo(
                fieldname=name,
                ppkname=ppkname,
                custom_type=underlaying_type,
                is_class_var=is_class_var,
                is_discriminator=is_discriminator,
                const_value=const_value,
            )
    if overlaying_type in P_TYPES:
        return PFieldInfo(
            ppkname=ppkname,
            fieldname=name,
            is_class_var=is_class_var,
            is_discriminator=is_discriminator,
            const_value=const_value,
            underlaying_type=overlaying_type,
        )

    raise TypeError(
        f"Field {name} in class {cls.__name__} has unsupported underlaying type. Supported underlaying types are: {R_TYPES_T} and {P_TYPES_T}"
    )


def _process_field(
    cls: type, name: str, annotation: type, parent_field_info: FieldInfoBase[Any] | None, ppkname: str
) -> FieldInfoBase[Any]:
    field_info = _generate_field_info(cls, name, annotation, ppkname)
    if parent_field_info is None:
        return field_info
    if parent_field_info.is_discriminator:
        if field_info.const_value is NOTSET:
            raise TypeError(
                f"Class {cls.__name__} is missing constant value for discriminator field {name} from parent class"
            )
    else:
        if field_info.const_value != parent_field_info.const_value:
            raise TypeError(
                f"Class {cls.__name__} is overriding classvar field {name} from parent class with a new value, which is not allowed"
            )
    return field_info


def _process_class(cls: "type[File]") -> None:
    if _is_dataclass(cls):
        return

    ppknames: dict[str, str] = {}
    dataclasses.dataclass(slots=True, kw_only=True)(cls)
    dfields = getattr(cls, "__dataclass_fields__").values()
    for _dfield in dfields:
        _title = _dfield.name.title().replace("_", "-")
        if _title.endswith("-Mac"):
            _title = _title[:-4] + "-MAC"
        ppknames[_dfield.name] = _dfield.metadata.get("ppkname", _title)

    fields: dict[str, FieldInfoBase[Any]] = {}

    parent = get_parent_class(cls)
    parent_info = None if parent is None else get_class_info(parent)
    if parent is not None and parent_info is not None:
        if not parent_info.header:
            raise TypeError(
                f"Class {cls.__name__} has parent class {parent.__name__} which is not a header class, but {cls.__name__} is a header class."
            )

        for field_name, field in parent_info.fields.items():
            fields[field_name] = field

    field_annotations = inspect.get_annotations(cls)
    for field_name, field_annotation in field_annotations.items():
        fields[field_name] = _process_field(
            cls, field_name, field_annotation, fields.get(field_name), ppknames[field_name]
        )

    if parent is not None and parent_info is not None:
        parent_field = parent_info.get_descriptor_field()
        child_field = fields[parent_field.fieldname]

        if child_field.const_value is NOTSET:
            raise TypeError(
                f"Class {cls.__name__} is missing constant value for discriminator field {parent_field.fieldname} from parent class {parent.__name__}"
            )

        if child_field.const_value in parent_info.children:
            raise TypeError(
                f"Class {cls.__name__} has descriptor value {child_field.const_value} for field {child_field.fieldname}, but this value is already used by class {parent_info.children[child_field.const_value].__name__}"
            )
        parent_info.children[child_field.const_value] = cls

    header = any(x.is_discriminator for x in fields.values())

    info = _ClassInfo(header=header, fields=fields)

    setattr(cls, _PPK_PROTO_TYPE_INFO, info)


def dfield(*, default: Any = dataclasses.MISSING, name: str):
    return dataclasses.field(default=default, metadata={"ppkname": name})


@dataclass_transform(kw_only_default=True, field_specifiers=(dfield,))
class File:
    def __init_subclass__(cls: "type[File]", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        _process_class(cls)


def _unmarshal_inner[T: File](
    stream: StreamReader, cls: type[T], parsed: dict[str, Any]
) -> tuple[dict[str, Any], type[T]]:
    info = get_class_info(cls)

    for field in info.fields.values():
        parsed[field.fieldname] = field.unmarshal(stream, parsed)

    if not info.header:
        return parsed, cls

    parsed, child_cls = _unmarshal_inner(stream, info.get_child(parsed), parsed)
    return parsed, cast(type[T], child_cls)


def _unmarshal[T: File](cls: type[T], stream: StreamReader) -> T:
    parsed, cls = _unmarshal_inner(stream, cls, {})

    for field in get_class_info(cls).fields.values():
        if field.is_class_var:
            del parsed[field.fieldname]

    return cls(**parsed)


def unmarshal[T: File | FileProto](cls: type[T], data: bytes) -> T:
    stream = StreamReader(BytesIO(data))
    if issubclass(cls, File):
        return _unmarshal(cls, stream)
    return cls.unmarshal_ppk(stream)


def _marshal(obj: File, stream: StreamWriter) -> None:
    info = get_class_info(obj)
    if info.header:
        raise ValueError("Cannot marshal header class directly")

    for field in info.fields.values():
        field.marshal(stream, obj)


class FileProto(Protocol):
    @classmethod
    def unmarshal_ppk(cls, stream: StreamReader) -> Self: ...

    def marshal_ppk(self, stream: StreamWriter) -> None: ...


def marshal(obj: File | FileProto) -> bytes:
    stream = StreamWriter()
    if isinstance(obj, File):
        _marshal(obj, stream)
    else:
        obj.marshal_ppk(stream)
    return stream.getvalue()
