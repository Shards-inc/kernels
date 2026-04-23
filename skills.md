# Agent Skills Kernel

---

## Skill Registry

| Skill | Purpose |
|------|--------|
| context_parser | Normalize raw input into structured task context |
| task_decomposer | Break complex tasks into atomic executable units |
| planner | Generate ordered execution plan |
| tool_selector | Select optimal tool per task step |
| tool_executor | Execute tools with validation |
| memory_writer | Persist structured learnings |
| memory_retriever | Retrieve relevant prior context |
| reasoning_engine | Perform deterministic multi-step reasoning |
| constraint_validator | Enforce rules and constraints |
| self_reflector | Detect and correct errors |
| uncertainty_estimator | Quantify confidence levels |
| output_formatter | Normalize final output |
| parse_pdf_to_structured_json | Convert PDFs into structured JSON |
| repo_test_runner | Execute and validate repo test pipelines |
| financial_statement_analyzer | Compute financial insights deterministically |
| decision_brief_builder | Generate structured decision briefs |
| output_verifier | Validate outputs across all skills |

---

# Core Skills

---

### Skill: context_parser

**Purpose**
Transform unstructured input into structured context.

**Input Schema**
```json
{
  "raw_input": "string",
  "metadata": {
    "source": "user|system",
    "timestamp": "string"
  }
}
```

**Output Schema**
```json
{
  "intent": "string",
  "entities": ["string"],
  "constraints": ["string"],
  "confidence": 0.0
}
```

**Execution Logic**
1. Extract intent via pattern + semantic parsing.
2. Identify entities and constraints.
3. Assign confidence score.

**Constraints**
- Must output all fields.
- No null values.

**Failure Modes**
- Ambiguous intent.
- Missing input.

**Self-Check**
- Ensure confidence is within [0, 1].
- Ensure intent is non-empty.

---

### Skill: task_decomposer

**Purpose**
Convert tasks into atomic steps.

**Input Schema**
```json
{
  "task": "string",
  "context": {}
}
```

**Output Schema**
```json
{
  "subtasks": [
    {
      "id": "string",
      "description": "string",
      "dependencies": ["string"]
    }
  ]
}
```

**Execution Logic**
1. Identify goal.
2. Split into smallest executable units.
3. Define dependencies.

**Constraints**
- No cyclic dependencies.

**Failure Modes**
- Over-decomposition.
- Missing dependencies.

**Self-Check**
- Validate DAG structure.

---

### Skill: planner

**Purpose**
Sequence subtasks into execution order.

**Input Schema**
```json
{
  "subtasks": []
}
```

**Output Schema**
```json
{
  "execution_plan": ["subtask_id"]
}
```

**Execution Logic**
1. Topological sort.
2. Optimize ordering.

**Constraints**
- Must respect dependencies.

**Failure Modes**
- Invalid graph.

**Self-Check**
- Verify all nodes included.

---

### Skill: tool_selector

**Purpose**
Select optimal tool.

**Input Schema**
```json
{
  "task": "string",
  "available_tools": ["string"]
}
```

**Output Schema**
```json
{
  "selected_tool": "string",
  "confidence": 0.0
}
```

**Execution Logic**
1. Match task to tool capability.
2. Rank candidates.

**Constraints**
- Must choose one tool.

**Failure Modes**
- No suitable tool.

**Self-Check**
- Validate selected tool exists.

---

### Skill: tool_executor

**Purpose**
Execute tool calls.

**Input Schema**
```json
{
  "tool": "string",
  "parameters": {}
}
```

**Output Schema**
```json
{
  "result": {},
  "status": "success|failure"
}
```

**Execution Logic**
1. Validate parameters.
2. Execute.
3. Capture output.

**Constraints**
- Must return structured result.

**Failure Modes**
- Tool crash.

**Self-Check**
- Ensure status correctness.

---

### Skill: reasoning_engine

**Purpose**
Perform structured reasoning.

**Input Schema**
```json
{
  "data": {},
  "goal": "string"
}
```

**Output Schema**
```json
{
  "steps": ["string"],
  "conclusion": "string"
}
```

**Execution Logic**
1. Decompose reasoning steps.
2. Apply deterministic logic.

**Constraints**
- No hallucinated facts.

**Failure Modes**
- Incomplete reasoning.

**Self-Check**
- Validate logical consistency.

---

### Skill: constraint_validator

**Purpose**
Enforce constraints.

**Input Schema**
```json
{
  "data": {},
  "constraints": ["string"]
}
```

**Output Schema**
```json
{
  "valid": true,
  "violations": ["string"]
}
```

**Execution Logic**
1. Evaluate each constraint.
2. Record violations.

---

### Skill: self_reflector

**Purpose**
Detect and fix errors.

**Execution Logic**
1. Analyze output.
2. Identify inconsistencies.
3. Suggest correction.

---

### Skill: uncertainty_estimator

**Purpose**
Quantify uncertainty.

**Output Schema**
```json
{
  "confidence": 0.0
}
```

---

### Skill: output_formatter

**Purpose**
Normalize outputs.

---

## Extended Skills

---

### Skill: parse_pdf_to_structured_json

**Purpose**
Deterministic PDF parsing.

**Key Guarantees**
- Schema-validated output.
- Table normalization.
- OCR fallback.

---

### Skill: repo_test_runner

**Purpose**
Execute repo validation pipeline.

**Key Guarantees**
- Flake detection.
- Retry logic.
- Structured test summary.

---

### Skill: financial_statement_analyzer

**Purpose**
Deterministic financial computation.

**Key Guarantees**
- Ratio calculation.
- Accounting validation.
- Anomaly detection.

---

### Skill: decision_brief_builder

**Purpose**
Generate structured decisions.

**Key Guarantees**
- Template enforcement.
- Evidence-only reasoning.

---

### Skill: output_verifier

**Purpose**
Global validation layer.

**Key Guarantees**
- Schema validation.
- Hallucination detection.
- Evidence grounding.

---

## Execution Pipeline

Input
→ context_parser
→ task_decomposer
→ planner
→ tool_selector
→ tool_executor
→ reasoning_engine
→ constraint_validator
→ self_reflector
→ output_verifier
→ output_formatter

---

## Composition Rules

- All outputs must match schema.
- All skills must be independently callable.
- No implicit state.

---

## Error Recovery

1. Detect failure.
2. Retry once.
3. Escalate to reflection.
4. Abort if unresolved.

---

## Memory Strategy

- Store only validated outputs.
- Compress via summarization.
- Index via embeddings.

---

End of Kernel
