def wrap_lines[T: (bytes, str)](data: T, width: int = 64) -> list[T]:
    return [data[i : i + width] for i in range(0, len(data), width)]
