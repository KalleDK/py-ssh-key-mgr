from typing import Any, Generic, TypeVar

SecretType = TypeVar("SecretType")


class _SecretBase(Generic[SecretType]):
    def __init__(self, secret_value: SecretType) -> None:
        self._secret_value: SecretType = secret_value

    def get_secret_value(self) -> SecretType:
        """Get the secret value.

        Returns:
            The secret value.
        """
        return self._secret_value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and self.get_secret_value() == other.get_secret_value()

    def __hash__(self) -> int:
        return hash(self.get_secret_value())

    def __str__(self) -> str:
        return str(self._display())

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._display()!r})"

    def _display(self) -> str | bytes:
        raise NotImplementedError  # pragma: no cover


class SecretStr(_SecretBase[str]):
    def __len__(self) -> int:
        return len(self._secret_value)

    def _display(self) -> str:
        return "**********" if self._secret_value else ""


class SecretBytes(_SecretBase[bytes]):
    def __len__(self) -> int:
        return len(self._secret_value)

    def _display(self) -> str:
        return "b'**********'" if self._secret_value else "b''"
