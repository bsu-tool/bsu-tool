# bsu-tool: Proposed Claude Code Skills

**Date:** June 29, 2026  
**Author:** Dylan Mills  
**Purpose:** Standardize how Claude Code works with `bsu-tool` across team sessions.

## What Are Skills?

Claude Skills are reusable instruction packages that help Claude Code follow a consistent workflow. For `bsu-tool`, skills can reduce repeated prompt setup, improve token efficiency, and help every team member get the same behavior from Claude when working in the project.

Each skill should live in its own folder under `.claude/skills/` and contain a `SKILL.md` file:

```text
.claude/
  skills/
    ci/
      SKILL.md
    new-mcp-tool/
      SKILL.md
    analyze-capture/
      SKILL.md
    live-capture/
      SKILL.md
```

Each `SKILL.md` file should include frontmatter with a `name` and `description`. The description tells Claude when the skill should be used.

Skills are different from slash commands. Skills guide Claude automatically when a task matches the description. If the team wants explicit commands like `/ci`, we can add separate Claude Code slash commands later.

## Why Use Skills For bsu-tool?

Skills can help Claude:

- run the correct verification commands before commits and PRs
- follow the project's MCP tool architecture
- analyze USB captures consistently
- avoid recreating the same project instructions in every chat
- reduce repeated context and token usage
- keep human validation and packet-level evidence central to analysis

## Proposed Skills

## 1. `ci`

**Trigger:** Before a commit, push, or pull request, or whenever a change needs verification.

**Purpose:** Run the project checks in a consistent order.

**What it should do:**

1. Run `ruff check .`
2. Run `ruff format --check .`
3. Run `pyright`
4. Run `pytest`

Claude should stop on the first failure and report:

- which command failed
- the important error output
- the likely next fix

**Why it is useful:**

Every team member and every Claude session verifies changes the same way. This helps prevent broken code from being pushed because someone skipped Pyright, forgot the test command, or used the wrong workflow.

### Example `SKILL.md`

```md
---
name: ci
description: Use when verifying bsu-tool changes before commit, push, or pull request.
---

# CI Verification

Run checks from the repository root.

Use the project virtual environment if present.

1. `ruff check .`
2. `ruff format --check .`
3. `pyright`
4. `pytest`

Stop on the first failure. Report the command run, whether it passed or failed, the important error output, and the suggested next fix.

Do not skip Pyright. The project requires strict typing on every PR.
```

## 2. `new-mcp-tool`

**Trigger:** When adding or modifying an MCP tool.

**Purpose:** Keep MCP tool implementation consistent with the existing codebase.

**What it should do:**

- Add tool code under `bsu_tool/mcp/tools/`
- Register the tool module in `bsu_tool/mcp/tools/__init__.py`
- Keep `bsu_tool/mcp/server.py` as the thin server bootstrap
- Use full type annotations
- Add docstrings for public functions
- Add unit tests under `tests/unit/mcp/`
- Use the canonical session model instead of creating duplicate state
- Run Ruff, Pyright, and pytest before finishing

**Why it is useful:**

This keeps Claude from placing tools in the wrong module, skipping registration, or creating a second session model. It also reinforces the project's typing, testing, and documentation rules.

### Example `SKILL.md`

```md
---
name: new-mcp-tool
description: Use when adding or modifying an MCP tool in bsu-tool.
---

# Add A New MCP Tool

Follow the existing MCP architecture.

- Add tool code under `bsu_tool/mcp/tools/`
- Register the tool module in `bsu_tool/mcp/tools/__init__.py`
- Keep `bsu_tool/mcp/server.py` as the thin server bootstrap
- Use full type annotations
- Add docstrings for public functions
- Add unit tests under `tests/unit/mcp/`
- Use the canonical session model instead of creating duplicate state
- Run Ruff, Pyright, and pytest before finishing
```

## 3. `analyze-capture`

**Trigger:** When analyzing an existing `.pcapng` USB capture file.

**Purpose:** Guide Claude through the current or near-term analysis workflow for existing capture files.

**What it should do:**

1. Load the capture with `load_capture`.
2. List devices with `list_devices`.
3. Identify likely target devices by bus number, device number, endpoints, packet counts, descriptors, and transfer types.
4. Prefer packet-level evidence over guesses.
5. Clearly separate known facts from hypotheses.
6. If packet retrieval tools are unavailable, state what information is missing and what tool should be built next.

**Why it is useful:**

This gives Claude a repeatable USB-analysis workflow and keeps it grounded in actual capture evidence rather than unsupported assumptions.

### Example `SKILL.md`

```md
---
name: analyze-capture
description: Use when analyzing an existing USB pcap-ng capture with bsu-tool MCP tools.
---

# Analyze Existing USB Capture

Use this workflow for existing `.pcapng` files.

1. Load the capture with `load_capture`.
2. List devices with `list_devices`.
3. Identify likely target devices by bus number, device number, endpoints, packet counts, descriptors, and transfer types.
4. Prefer packet-level evidence over guesses.
5. Clearly separate known facts from hypotheses.
6. If packet retrieval tools are unavailable, say what information is missing and what tool should be built next.

Focus on vendor-specific USB devices. Standard classes such as HID, audio, video, CDC, and mass storage are out of scope unless the user explicitly asks otherwise.
```

## 4. `live-capture`

**Trigger:** When driving the planned live USB capture workflow on Linux.

**Purpose:** Define the target end-to-end workflow for capturing device behavior while an analyst performs physical actions.

**Important note:** This skill describes the target workflow. Some tools may not exist yet. Claude should not pretend missing tools exist.

**Target workflow:**

1. Identify the target USB bus/device.
2. Start capture.
3. Ask the analyst to perform one physical action at a time.
4. Add named markers for each action.
5. Stop capture.
6. Compile or decode capture data.
7. Inspect traffic around markers.
8. Look for repeated URB sequences and command/response pairs.
9. Present hypotheses with packet-level evidence.

**Why it is useful:**

This is the main workflow the project is building toward. Capturing it as a skill helps Claude follow the same process every session and makes missing tool work obvious.

### Example `SKILL.md`

```md
---
name: live-capture
description: Use when driving the planned live USB capture workflow for bsu-tool on Linux.
---

# Live Capture Workflow

This is the target workflow for Linux systems with usbmon access.

Expected sequence:

1. Identify the target USB bus/device.
2. Start capture.
3. Ask the analyst to perform one physical action at a time.
4. Add named markers for each action.
5. Stop capture.
6. Compile/decode capture data.
7. Inspect traffic around markers.
8. Look for repeated URB sequences and command/response pairs.
9. Present hypotheses with packet-level evidence.

If a required MCP tool does not exist yet, do not pretend it does. State which tool is missing and suggest the next implementation step.
```

## Skills vs. Slash Commands

Skills and slash commands solve different problems:

| Feature | Purpose |
|---|---|
| Skills | Give Claude reusable instructions and workflows. |
| Slash commands | Give users explicit commands to run from chat, such as `/ci`. |

Recommended approach:

- Start with skills first.
- Add slash commands later only if the team wants explicit commands like `/ci` or `/analyze`.

Possible future slash command structure:

```text
.claude/
  commands/
    ci.md
    analyze.md
```

## Security Notes

Skills should be treated like project code. They shape how Claude behaves, so the team should review them before relying on them.

Do not put the following in skills:

- API keys
- secrets
- private sponsor data
- raw sensitive captures
- instructions to bypass validation
- instructions to ignore failing tests
- instructions to run destructive commands without user approval

USB captures may contain sensitive data, including device identifiers, payload bytes, keystrokes, firmware behavior, or proprietary protocol details. Skills should remind Claude to treat captures as sensitive and to prefer payload previews or summaries unless full data is explicitly needed.

## Recommended Next Steps

1. Create `.claude/skills/` in the project.
2. Add the four starter skills:
   - `ci`
   - `new-mcp-tool`
   - `analyze-capture`
   - `live-capture`
3. Review the skill text as a team.
4. Commit the skills only after the team agrees they should be shared project behavior.
5. Consider adding slash commands later if the team wants explicit `/ci` or `/analyze` commands.

## Summary

Claude Skills are a good fit for `bsu-tool` because the project depends on repeated, structured AI-assisted workflows. MCP gives Claude tools to call. Skills tell Claude how to use those tools consistently.

For this project:

- MCP is what Claude can call.
- Skills are how Claude should work.

