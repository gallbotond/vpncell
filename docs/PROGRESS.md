# Progress

Progress is tracked per platform track. Each track edits only its own file,
so parallel tracks do not conflict:

| Track | File | State |
|---|---|---|
| Linux (Ubuntu 26.04, the shipped product) | [progress/linux.md](progress/linux.md) | released as `.deb`; build history, open items for the user |
| Windows | [progress/windows.md](progress/windows.md) | design pending ([#69](https://github.com/gallbotond/vpncell/issues/69)) |
| macOS | [progress/macos.md](progress/macos.md) | design pending ([#69](https://github.com/gallbotond/vpncell/issues/69)) |

Cross-platform work (CI, portable packages: #67, #68, #71) is recorded in
[progress/linux.md](progress/linux.md), "Cross-platform groundwork", because
it runs on the Linux host and must not change Linux behaviour.

## How to resume

1. Read [AGENTS.md](../AGENTS.md): the order of work, your platform's
   section (commands, test host, shared resources, hard limits).
2. Read your track's progress file above: "Current step" says where work
   stopped.
3. Read [DECISIONS.md](DECISIONS.md) (wins) and [DESIGN.md](DESIGN.md).
   DESIGN.md describes the Linux design; #69 will say which parts apply to
   Windows and macOS.
4. Check open PRs and issues for your track: `gh pr list`,
   `gh issue list --label <linux|windows|macos|cross-platform>`.
5. Linux only: the commands to build, install and test are in
   [progress/linux.md](progress/linux.md), "How to resume".
