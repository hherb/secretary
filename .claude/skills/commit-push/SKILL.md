---
name: commit-push
description: Run tests, stage changes, write conventional commit, push to current branch
---
1. Run the project's test suite; abort if failures.
2. Run `git status` and `git diff` to summarize changes.
3. Stage relevant files and commit with a conventional message (feat:/fix:/docs:/refactor:).
4. **If the current branch has an open PR** and the branch is on a feature branch (not main): `git fetch origin && git merge origin/main` to absorb any pause-window baton syncs (per [[feedback_next_session_main_authoritative]]) into the branch's history. Resolve handoff-doc conflicts by keeping the branch version (`git checkout --ours docs/handoffs/<file>.md`) — the in-flight fixup is strictly newer than main's snapshot. Re-run the test suite if the merge brought in code changes.
5. Push to the current branch's upstream.
