#!/usr/bin/env node
// Claude Code PreToolUse hook — no-primary-branch-switch.
//
// Blocks a git command that would CHANGE THE BRANCH of a PRIMARY working
// tree (`~/projects/<repo>`). Branch-specific work — committing, rebasing,
// squashing, opening PRs — belongs in a `git worktree`, leaving the primary
// checkout on whatever branch it is already on. Primary checkouts are
// frequently in active use by another parallel Claude session (uncommitted /
// staged WIP, cascade commits); switching their branch out from under that
// session destroys unsaved work and lands the next commit on the wrong branch.
//
// Detection: a `git checkout <branch>` / `git switch <branch>` /
// `git checkout -b` / `git switch -c` (and the `-` previous-branch shorthand)
// whose target working tree is the MAIN (primary) working tree, not a linked
// worktree. File-restore forms (`git checkout -- <path>`, `git checkout .`,
// `git checkout <ref> <path>`) are NOT branch switches and pass. Operations
// inside a linked worktree pass. Anything that isn't a git branch-switch passes.
//
// This is the user-global sibling of primary-checkout-branch-guard: it is
// wired through the wheelhouse dispatcher so it fires from EVERY repo session
// (any `~/projects/<repo>` primary checkout), not only fleet-managed ones.
//
// Effective directory: `git -C <path> checkout <branch>` runs the checkout in
// <path>, and a leading `cd <dir> &&` moves the whole line there, so the guard
// resolves the effective dir (shared extractGitCwd) and classifies THAT — a
// worktree cwd cannot launder a switch aimed at the primary via `-C`.
//
// Classification: a linked worktree's `git rev-parse --git-dir` differs from
// its `--git-common-dir`; the primary working tree's are EQUAL. Equality is the
// primary/worktree test.
//
// Bypassable: the user types the exact phrase `Allow branch switch` in a
// message. Only a genuine human user turn counts (bypassPhrasePresent) — not
// the assistant, not a tool result, not a peer-agent relay.
//
// Fails OPEN on any parse / git error: this guards one specific hazardous
// shape, it is not a general git gate.

import { bashGuard, block, defineHook, runHook } from '../_shared/guard.mts'
import type { GuardResult } from '../_shared/guard.mts'
import { gitOut } from '../_shared/git-branch.mts'
import { extractGitCwd } from '../_shared/git-cwd.mts'
import { splitGitSubcommand } from '../_shared/git-subcommand.mts'
import { commandsFor } from '../_shared/shell-command.mts'
import { bypassPhrasePresent } from '../_shared/transcript.mts'

// Pre-flight trigger: every branch-switch carries the literal `checkout` or
// `switch` token — the substring the dispatcher gates on before importing this
// guard. A blocking command necessarily contains one of these.
export const triggers: readonly string[] = ['checkout', 'switch']

export const BYPASS_PHRASE = 'Allow branch switch'

// A `git checkout` arg list that's a working-tree / file restore rather than a
// branch switch: `git checkout -- <file>` or `git checkout .`.
function looksLikePathRestore(rest: readonly string[]): boolean {
  return rest.includes('--') || rest.includes('.')
}

/**
 * Given a `checkout` / `switch` subcommand and the args that follow it (the
 * output of splitGitSubcommand), decide whether the invocation MOVES HEAD.
 *
 * `switch` is always branch-oriented: `git switch <name>`, `git switch -c
 * <name>` (create), and `git switch -` (previous) all move HEAD; a bare `git
 * switch` with only flags has no target and does not.
 *
 * `checkout` is a branch switch on `-b`/`-B` (create), on the `-` shorthand,
 * or on exactly one non-flag arg with no `--`/`.` (`git checkout main`). Two+
 * non-flag args is the `<tree> <pathspec>` file-restore form and passes.
 */
export function isBranchSwitch(
  sub: 'checkout' | 'switch',
  rest: readonly string[],
): boolean {
  if (sub === 'switch') {
    if (rest.includes('-c') || rest.includes('-C')) {
      return true
    }
    return rest.some(a => a === '-' || !a.startsWith('-'))
  }
  // sub === 'checkout'
  if (rest.includes('-b') || rest.includes('-B')) {
    return true
  }
  if (looksLikePathRestore(rest)) {
    return false
  }
  const nonFlag = rest.filter(a => !a.startsWith('-'))
  if (nonFlag.length === 0) {
    // No positional target: only the `-` previous-branch shorthand switches.
    return rest.includes('-')
  }
  // Exactly one non-flag arg (`git checkout main`) is the branch-switch form.
  // Two+ non-flag args is `<tree> <pathspec>` — a file op — so pass.
  return nonFlag.length === 1
}

// The kind of working tree a directory is. 'unknown' → fail open (allow).
export type WorkingTreeKind = 'primary' | 'unknown' | 'worktree'

/**
 * Classify a `git rev-parse` result. The primary working tree's `--git-dir`
 * equals its `--git-common-dir`; a linked worktree's differ. Pure — the caller
 * feeds it the two absolute paths (empty string = git could not report one).
 */
export function classifyGitDir(
  gitDir: string,
  commonDir: string,
): WorkingTreeKind {
  if (!gitDir || !commonDir) {
    return 'unknown'
  }
  return gitDir === commonDir ? 'primary' : 'worktree'
}

function defaultProbe(dir: string): string | undefined {
  return gitOut(dir, [
    'rev-parse',
    '--path-format=absolute',
    '--git-dir',
    '--git-common-dir',
  ])
}

/**
 * Real probe: ask git for the absolute git-dir + common-dir of `dir` and
 * classify. Returns 'unknown' on any git error (not a repo, git unavailable)
 * so the guard fails open. Injectable via the `probe` seam for tests.
 */
export function workingTreeKind(
  dir: string,
  probe: (d: string) => string | undefined = defaultProbe,
): WorkingTreeKind {
  const out = probe(dir)
  if (!out) {
    return 'unknown'
  }
  const [gitDir = '', commonDir = ''] = out.split('\n').map(s => s.trim())
  return classifyGitDir(gitDir, commonDir)
}

/**
 * The first `git checkout`/`switch` segment of `command` that MOVES HEAD, and
 * the effective directory it runs in. Sees through `&&` chains, quoting, and
 * `$(…)` substitution via the shared shell parser; resolves the dir honoring a
 * leading `cd` and the git op's own `-C` (extractGitCwd).
 */
export function firstBranchSwitch(
  command: string,
  hookCwd?: string | undefined,
): { readonly dir: string; readonly segment: string } | undefined {
  for (const c of commandsFor(command, 'git')) {
    const { rest, sub } = splitGitSubcommand(c.args)
    if (sub !== 'checkout' && sub !== 'switch') {
      continue
    }
    if (!isBranchSwitch(sub, rest)) {
      continue
    }
    const dir = extractGitCwd(command, { cwd: hookCwd, subcommand: sub })
    return { dir, segment: `git ${c.args.join(' ')}` }
  }
  return undefined
}

export function blockMessage(segment: string): string {
  return [
    '[no-primary-branch-switch] Blocked: this changes the branch of a PRIMARY',
    'checkout — the move that clobbers another session working in it. Do branch',
    'work in a worktree instead, so the primary stays on whatever branch it is on:',
    '',
    '  git -C <repo> worktree add /tmp/wt-<name> <branch>   # or -b <newbranch>',
    '  # ...work in /tmp/wt-<name>..., then: git -C <repo> worktree remove /tmp/wt-<name>',
    '',
    `  Blocked command: ${segment}`,
    '',
    'If you genuinely must switch the primary checkout, the user must type the',
    `EXACT phrase in a new message:  ${BYPASS_PHRASE}`,
  ].join('\n')
}

/**
 * Pure decision given already-gathered facts. Returns a block message or
 * undefined (allow). Exported so tests need no stdin / git.
 */
export function decide(input: {
  readonly phraseOk: boolean
  readonly segment: string | undefined
  readonly targetKind: WorkingTreeKind
}): string | undefined {
  if (!input.segment) {
    return undefined
  }
  if (input.targetKind !== 'primary') {
    // Worktree / unknown → allow (fail open on unknown).
    return undefined
  }
  if (input.phraseOk) {
    return undefined
  }
  return blockMessage(input.segment)
}

export const check = bashGuard((command, payload): GuardResult => {
  const hookCwd = (payload as { cwd?: string | undefined } | undefined)?.cwd
  const match = firstBranchSwitch(command, hookCwd)
  if (!match) {
    return undefined
  }
  if (workingTreeKind(match.dir) !== 'primary') {
    return undefined
  }
  if (bypassPhrasePresent(payload.transcript_path, [BYPASS_PHRASE])) {
    return undefined
  }
  return block(blockMessage(match.segment))
})

export const hook = defineHook({
  bypass: ['branch-switch'],
  bypassMode: 'manual',
  check,
  event: 'PreToolUse',
  matcher: ['Bash'],
  triggers,
  type: 'guard',
})
void runHook(hook, import.meta.url)
