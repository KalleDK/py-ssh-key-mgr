import dataclasses
import inspect


@dataclasses.dataclass(slots=True)
class Demo:
    value: int

    @classmethod
    def __call__(cls, m: str) -> int:
        return len(m)

    def __int__(self) -> int:
        return self.value


s = Demo(42)
print(inspect.signature(Demo.__init__))
print(inspect.signature(s))
