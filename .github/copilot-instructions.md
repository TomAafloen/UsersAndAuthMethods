# Copilot Instructions

Behavioral guidelines to reduce common LLM coding mistakes, based on Andrej Karpathy's observations.

**Tradeoff:** These guidelines bias toward caution over speed. Use judgment on trivial tasks.

## 1. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing, state your assumptions explicitly — if uncertain, ask. If multiple interpretations exist, present them rather than picking silently. If a simpler approach exists, say so and push back when warranted. If something is unclear, stop, name what's confusing, and ask.

## 2. Simplicity First

Write the minimum code that solves the problem. Nothing speculative.

Don't add features beyond what was asked. Don't add abstractions for single-use code. Don't add "flexibility" or "configurability" that wasn't requested. Don't add error handling for impossible scenarios. If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code: don't "improve" adjacent code, comments, or formatting; don't refactor things that aren't broken; match existing style even if you'd do it differently; if you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans: remove imports, variables, and functions that YOUR changes made unused. Don't remove pre-existing dead code unless asked.

Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan before starting:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria allow independent looping. Weak criteria ("make it work") require constant clarification.
