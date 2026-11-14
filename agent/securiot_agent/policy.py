"""Local safety rules. Arming is intentionally not persisted across restarts."""

from dataclasses import dataclass


@dataclass
class Policy:
    learning_mode: bool = True
    warmup_seconds: float = 30
    cooldown_seconds: float = 10
    restore_grace_seconds: float = 60

    def __post_init__(self) -> None:
        # Local floors cannot be weakened by the caller.
        self.warmup_seconds = max(30, self.warmup_seconds)
        self.cooldown_seconds = max(10, self.cooldown_seconds)
        self.restore_grace_seconds = max(60, self.restore_grace_seconds)
