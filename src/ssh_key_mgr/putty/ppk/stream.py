import base64
import dataclasses
import typing
from io import BytesIO

from ssh_key_mgr import b64
from ssh_key_mgr.utils import wrap_lines


class Field[T](typing.NamedTuple):
    name: str
    value: T


class IntField(Field[int]):
    pass


class StrField(Field[str]):
    pass


class BytesField(Field[bytes]):
    pass


class HexField(Field[bytes]):
    pass


@dataclasses.dataclass
class StreamReader:
    data: BytesIO
    next_field: Field[str] | None = dataclasses.field(init=False)
    _extra_field: Field[str] | None = dataclasses.field(init=False)

    def __post_init__(self):
        first_field = self._read_next_field_raw()
        if first_field is None:
            self.next_field = None
        else:
            self.next_field = Field("File-Version", first_field.name)
            self._extra_field = Field("Key-Type", first_field.value)

    def _read_line(self) -> str:
        while len(value := self.data.readline()) != 0:
            if len(value := value.strip(b"\r\n")) == 0:
                continue
            return value.decode("utf-8")

        raise EOFError("No more lines to read")

    def _read_next_field_raw(self) -> None | Field[str]:
        try:
            line = self._read_line()
        except EOFError:
            return None

        name, _, value = line.partition(": ")

        if name.endswith("-Lines"):
            linecount = int(value)
            value = "".join(self._read_line() for _ in range(linecount))

        return Field(name, value)

    def _read_next_field(self) -> None | Field[str]:
        if self._extra_field is not None:
            ef = self._extra_field
            self._extra_field = None
            return ef
        return self._read_next_field_raw()

    def _read_field(self):
        if self.next_field is None:
            raise EOFError("No more fields to read")

        current_field = self.next_field

        self.next_field = self._read_next_field()

        return current_field

    def read_int(self) -> IntField:
        name, value = self._read_field()
        return IntField(name, int(value))

    def read_str(self) -> StrField:
        name, value = self._read_field()
        return StrField(name, value)

    def read_hexbytes(self) -> HexField:
        name, value = self._read_field()
        return HexField(name, bytes.fromhex(value))

    def read_bytes(self) -> BytesField:
        name, value = self._read_field()
        return BytesField(name, base64.b64decode(value))

    def read_named_int(self, name: str) -> int:
        field = self.read_int()
        if field.name != name:
            raise ValueError(f"Expected field name {name}, got {field.name}")
        return field.value

    def read_named_str(self, name: str) -> str:
        field = self.read_str()
        if field.name != name:
            raise ValueError(f"Expected field name {name}, got {field.name}")
        return field.value

    def read_named_hexbytes(self, name: str) -> bytes:
        field = self.read_hexbytes()
        if field.name != name:
            raise ValueError(f"Expected field name {name}, got {field.name}")
        return field.value

    def read_named_bytes(self, name: str) -> bytes:
        field = self.read_bytes()
        if field.name != name:
            raise ValueError(f"Expected field name {name}, got {field.name}")
        return field.value

    def read(
        self, typ: type[HexField] | type[BytesField] | type[IntField] | type[StrField]
    ) -> HexField | BytesField | IntField | StrField:
        match typ:
            case t if t is IntField:
                return self.read_int()
            case t if t is StrField:
                return self.read_str()
            case t if t is BytesField:
                return self.read_bytes()
            case t if t is HexField:
                return self.read_hexbytes()
            case _:
                raise TypeError(f"Unsupported type: {typ}")

    def eof(self) -> bool:
        return self.next_field is None


@dataclasses.dataclass
class StreamWriter:
    data: BytesIO = dataclasses.field(default_factory=BytesIO)
    first: bool = True
    version: str | None = None

    def _write_line(self, line: str) -> None:
        self.data.write(line.encode("utf-8") + b"\n")

    def _write_field(self, field: Field[str]) -> None:
        if self.first:
            if self.version is None:
                self.version = field.value
                return
            field = Field(self.version, field.value)
            self.version = None
            self.first = False

        name, value = field
        if not name.endswith("-Lines"):
            self._write_line(f"{name}: {value}")
            return
        lines = wrap_lines(value)
        self._write_line(f"{name}: {len(lines)}")
        for line in lines:
            self._write_line(line)

    def write_int(self, field: IntField) -> None:
        self._write_field(Field(field.name, str(field.value)))

    def write_str(self, field: StrField) -> None:
        self._write_field(field)

    def write_hexbytes(self, field: HexField) -> None:
        self._write_field(Field(field.name, field.value.hex()))

    def write_bytes(self, field: BytesField) -> None:
        self._write_field(Field(field.name, b64.to_line(field.value).decode("utf-8")))

    def getvalue(self) -> bytes:
        return self.data.getvalue()
