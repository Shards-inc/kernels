# Compatibility Rules Skill

- Keep tensor shape and dtype interfaces backward compatible.
- Preserve CPU fallback behavior whenever GPU path changes.
- Avoid silent default changes in public kernel entrypoints.
- Add tests for mixed-device and mixed-dtype parity.
