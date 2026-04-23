# Memory Coalescing Skill

- Keep loads and stores contiguous whenever possible.
- Minimize strided global memory access in inner loops.
- Watch for shared-memory bank conflicts during transpose patterns.
- Track bandwidth regressions in benchmark gate output.
