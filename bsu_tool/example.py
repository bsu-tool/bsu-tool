"""Example module — used to verify annotation tests work. Safe to delete later."""


def add_numbers(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b

def greet(name: str, loud: bool = False) -> str:
    """Return a greeting, optionally in uppercase."""
    message = f"Hello, {name}!"
    return message.upper() if loud else message
