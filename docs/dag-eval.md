# DAG Library Evaluation

Evaluation of DAG/pipeline libraries for the harness step execution. Hamilton was chosen (see commit 87b8a34).

## Decision: Hamilton

> https://github.com/DAGWorks-Inc/hamilton | `pip install apache-hamilton`

Hamilton is a micro-framework for describing dataflows as Python functions. Each function becomes a node in a DAG; dependencies are inferred from function parameter names matching other function names. Created at Stitch Fix for feature engineering pipelines.

**Core philosophy:** functions *are* the graph. No DSL, no YAML, no class hierarchy — just annotated Python functions in a module.

### How It Maps to Our Use Case

```python
# harness_steps.py — a Hamilton module

from hamilton import async_driver
import harness_steps

dr = await async_driver.Builder().with_modules(harness_steps).build()
result = await dr.execute(
    ["agent_run_result", "resolved_thread", "environment_context"],
    inputs={
        "harness": harness, "config": config, "db": db,
        "threat_model": threat_model, "thread_id": tid, ...
    },
)
```

Each step function's parameter names match other function names to form the DAG automatically. External inputs (not computed by other functions) are passed via `inputs={}`.

### Async Support

Hamilton has a dedicated `AsyncDriver` (`hamilton.async_driver`) that natively supports `async def` functions as nodes. Sync and async functions can coexist in the same module.

### Pros

- **Minimal API surface** — functions *are* the graph, very Pythonic
- **Lightweight** — small dependency
- **Good async support** — `AsyncDriver` works well
- **Visualization** — `dr.display_all_functions()` generates a graph image
- **No infrastructure** — no server, no scheduler, no database; purely in-process
- **Low code overhead** — ~10 lines of driver setup + function definitions (which you'd write anyway)

### Cons

- **No resource lifecycle** — context managers spanning multiple nodes require manual plumbing outside Hamilton
- **Implicit dependency resolution** — parameter name matching is clever but a typo silently becomes an external input
- **Module-level functions only** — Hamilton inspects module attributes
- **Pulls in pandas/numpy** — even if you don't use them
- **No conditional execution** — can't skip nodes based on runtime conditions without `@config.when` (compile-time)

---

## Alternatives Considered

### Prefect

> https://github.com/PrefectHQ/prefect

Workflow orchestration platform with `@task` and `@flow` decorators. Good async support and imperative flow definition (`try/finally` works naturally). Built-in retries, caching, and observability UI.

**Rejected because:** Massive dependency (~100+ transitive deps, ~50MB+). Server-oriented design — scheduling, deployments, work pools are irrelevant for an in-process pipeline. Extreme overkill for a 5-step pipeline. Prefect wraps return values in State objects, which can interfere with passing complex objects between tasks.

### Redun

> https://github.com/insitro/redun

Workflow engine using lazy expression graphs and graph reduction. Tasks compose like normal function calls. Content-based caching via input hashing.

**Rejected because:** Async support unclear/untested. Caching by input hashing doesn't work for our objects (DB connections, container handles aren't hashable). Graph reduction model adds conceptual complexity. Small community (insitro-maintained). SQLite backend overhead we don't need.

### LangGraph (as pipeline executor)

> https://github.com/langchain-ai/langgraph | already a dependency

We already use LangGraph for agent orchestration. Its `StateGraph` could theoretically also run the harness pipeline steps.

**Rejected because:** Using the same tool for two different purposes (agent loop vs pipeline) risks conceptual confusion. Flat state dict becomes unwieldy with 12 inputs + 5 computed values. No automatic dependency resolution — edges are wired manually. Not designed for linear pipelines (designed for agent loops with cycles/interrupts).