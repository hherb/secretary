---
name: fixall  
description: instructions to cleanup after code review
disable-model-invocation: false
allowed-tools: Bash(git *) Bash(cargo test *) Bash(uv run pytest *)
---
Address all issues identified in the code review one by one. If fixing them appears manageable within scope, fix fix them now. If not, lodge the issue on github. Once all issues have been addressed, review the code changes thoroughly. If satisfied no issues left open, commit and push the changes into the PR.

**Before editing any files**, switch to the open PR's feature branch / worktree, then run `git fetch origin && git merge origin/main` to absorb any pause-window baton syncs (per [[feedback_next_session_main_authoritative]]) into the branch's history. Skipping this step causes add/add conflicts on the handoff doc whenever main has been preemptively synced — the squash-merge does not silently resolve them. If the merge has conflicts (typically only the handoff doc), keep the branch version (`git checkout --ours <path>` + `git add` + `git commit --no-edit`) because the in-flight fixup is strictly newer than main's snapshot.