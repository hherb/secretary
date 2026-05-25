---
name: nextsession  
description: instructions what to do when starting the next sessions
disable-model-invocation: false
allowed-tools: Bash(git *) Bash(cargo test *) Bash(uv run pytest *)
---
read NEXT_SESSION.md and follow its instructions. 
If you have any questions, ask me
Remember our general coding principles:
- test driven development
- no magic numbers
- prefer pure functions in reusable modules over complex code
- proper inline documentation and unit tests mandatory
- try and keep code files under 500 lines where reasonably possible, refactor when files grow to big where reasonable
Once you have completed yor tasks, check
(a) does README.md need updating because of the changes made in this session? If so, update README.md
(b) does ROADMAP.md need updating because of the changes made in this session? If so, update ROADMAP.md
Before we end, the baton handoff must capture:
(1) what we shipped this session with commit SHAs, 
(2) what's next with concrete acceptance criteria, 
(3) any open decisions or risks, 
(4) the exact commands needed to resume (cd, branch, test command). 

**(5) Handoff file model (NEXT_SESSION.md is a symlink — author the handoff once, not twice).**

`NEXT_SESSION.md` at the repo root is a **relative symlink** to the latest file in `docs/handoffs/`. The handoff doc is the only authored file; `NEXT_SESSION.md` is a pointer that transparently resolves to it. This is intentional — it eliminates the prior pattern (carry two byte-identical copies of the baton, one at NEXT_SESSION.md and one at docs/handoffs/) which produced inevitable merge conflicts whenever the same content was edited on both the feature branch and `main` during a pause window.

**Workflow:**
- Author the new handoff at `docs/handoffs/<YYYY-MM-DD>-<task-or-feature-slug>-shipped.md`.
- Retarget the symlink in one line: `ln -snf docs/handoffs/<your-new-file>.md NEXT_SESSION.md`.
- Verify: `ls -la NEXT_SESSION.md` shows the `->` target; `head -3 NEXT_SESSION.md` reads the handoff content transparently.
- Commit BOTH the new handoff file AND the retargeted symlink as one commit on the feature branch (per [[feedback_next_session_in_pr]]).

**Why this avoids conflicts:**
- New handoff files NEVER conflict (new path on each task).
- The symlink contents are a single line (the target path); the only way it conflicts is if two branches retarget to *different* paths simultaneously — rare, and a trivial 1-line resolution when it happens.
- Fixall / review-feedback edits during an open PR go into the handoff doc itself; if `main` already has a synced copy (per [[feedback_next_session_main_authoritative]]), the handoff file path becomes the conflict surface unless you bind the histories first (see next section).

**Fixup-time merge discipline (closes the add/add gap with main-side baton syncs):**

When you resume an in-flight feature branch to apply review fixups (or any further commit), the FIRST thing you do — before editing files — is:

```bash
git fetch origin
git merge origin/main          # absorbs any pause-window sync commits
# If the handoff doc conflicts (the typical case), branch version wins:
git checkout --ours docs/handoffs/<latest>.md
git add docs/handoffs/<latest>.md
git commit --no-edit
```

This binds the branch's history to main's so subsequent edits to the handoff doc on the branch are 3-way-mergeable at PR ship time. Without this step, the squash-merge surfaces an add/add conflict on the handoff doc path (both branches added the same path independently from a shared ancestor that didn't have it), and the PR ends up CONFLICTING / DIRTY.

Symptoms that this step was skipped:
- `gh pr view <n> --json mergeable,mergeStateStatus` returns `CONFLICTING` / `DIRTY`.
- The PR was clean at first push, then went CONFLICTING after a fixup commit.
- The conflict is exclusively in the handoff doc, not in code files.

Do not author the handoff separately as a "frozen archive snapshot" of a hand-edited NEXT_SESSION.md — the handoff IS the live baton; NEXT_SESSION.md is its symlink. If you find yourself rewriting both files in lockstep, the symlink is broken — restore it.