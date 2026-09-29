# GitHub Workflow for a 4-Member Team

## 1. Repository setup (M4, Week 1, one time)

1. Create the repository `QRGUARD` on GitHub (private until submission) and add the 3 teammates as
   collaborators with **Write** access.
2. Push the initial skeleton (this Phase 1 commit) to `main`, then create `develop` from `main`.
3. **Settings → Branches → Branch protection** for `main` **and** `develop`:
   - Require a pull request before merging, with **1 approval**
   - Require status checks to pass (backend-ci / web-ci / mobile-ci)
   - Require the branch to be up to date before merging
   - Block force pushes and deletions
4. Add `.github/CODEOWNERS`:
   ```
   /mobile/                     @member1
   /backend/                    @member2
   /backend/app/analyzers/message*  @member3
   /backend/app/analyzers/ocr.py    @member3
   /backend/app/analyzers/screenshot_analyzer.py @member3
   /backend/app/data/scam_rules.yaml @member3
   /web/  /firebase/  /.github/ @member4
   /docs/api-spec.md            @member1 @member2 @member4
   /backend/app/scoring/        @member2 @member3
   ```
5. Create a **GitHub Project** (board view) with the columns *Backlog · This week · In progress ·
   In review · Done*. Create **milestones** Week 1 … Week 12 and labels:
   `area:mobile`, `area:backend`, `area:scam-ocr`, `area:web`, `area:devops`, `type:bug`,
   `type:feature`, `type:docs`, `security`, `blocked`.

## 2. Branch model

```mermaid
gitGraph
  commit id: "phase-1 docs"
  branch develop
  checkout develop
  branch feature/backend-url-analyzer
  commit id: "url features"
  commit id: "tests"
  checkout develop
  merge feature/backend-url-analyzer
  branch feature/mobile-qr-scanner
  commit id: "camera scan"
  checkout develop
  merge feature/mobile-qr-scanner
  checkout main
  merge develop tag: "v0.1-alpha"
```

| Branch | Purpose | Who merges |
|---|---|---|
| `main` | Always demo-ready. Deployed automatically to Render and Vercel. | M4, via PR from `develop` only, at the end of each milestone |
| `develop` | Integration branch. Everything meets here. | Any member, via reviewed PR |
| `feature/<area>-<short-name>` | One task / issue, **lives 1–5 days** | Author opens PR → `develop` |
| `fix/<area>-<short-name>` | Bug fix | same |
| `hotfix/<name>` | Urgent fix to `main` | PR to `main`, then merge `main` back into `develop` |

### About the suggested `feature/mobile`, `feature/backend` … branches

Long-lived per-person branches drift apart for weeks and then produce painful "big bang" merges.
We **recommend short-lived feature branches** named by area (`feature/mobile-qr-scanner`,
`feature/backend-url-analyzer`, `feature/scam-rules-kyc`, `feature/web-history-page`). They give you
the same "four parallel streams", but integrate every few days.

If your guide requires the four named branches, keep them, but **merge `develop` into your branch
at least twice a week** and open a PR back to `develop` at least once a week.

## 3. Daily flow for each member

```bash
git checkout develop && git pull origin develop
git checkout -b feature/backend-url-analyzer        # one issue = one branch
# ... work, commit small and often ...
git add -p && git commit -m "feat(backend): detect IP-address hosts in URLs"
git fetch origin && git merge origin/develop          # stay current, resolve conflicts locally
git push -u origin feature/backend-url-analyzer
# open PR on GitHub → base: develop, link issue ("Closes #12"), request reviewer
```

**Commit messages** use Conventional Commits: `feat(mobile): …`, `fix(backend): …`, `test(scam): …`,
`docs: …`, `chore(ci): …`.

## 4. Pull requests and code review

- The PR template asks: What/Why, How to test, Screenshots (UI), Checklist (tests added, no secrets,
  API spec updated if the contract changed).
- **Reviewer rotation:** M1 ↔ M4 (both frontends), M2 ↔ M3 (both backend analysis). Anything touching
  `api-spec.md` or `scoring/` needs the extra CODEOWNER.
- Review within **24 h**. Comments should be specific ("this regex misses `hxxps`"), not vague.
- Merge with **Squash and merge** into `develop` (clean history), and **Merge commit** from
  `develop` into `main`.
- Delete the feature branch after merging.

## 5. How four people avoid breaking each other

1. **Contract first (Week 1).** `docs/api-spec.md` plus example JSON responses are agreed and frozen.
   The web and mobile teams build against **mock responses** (`services/mockApi.ts`, switched on by
   `USE_MOCK_API=true`) until the real endpoint exists.
2. **Folder ownership + CODEOWNERS.** Members rarely edit the same files.
3. **Shared `Indicator` contract.** M2 and M3 write different analyzers that emit the same object, so
   they don't need to touch each other's code.
4. **CI with path filters.** A mobile PR only runs mobile checks, and a red check blocks the merge.
5. **Small PRs** (< 400 changed lines) merged often.
6. **Weekly integration meeting** (30 min): merge `develop` → `main`, run the end-to-end demo script,
   and update the board.
7. **Feature flags via env** (e.g. `TI_VIRUSTOTAL_ENABLED`) so unfinished work can be merged while
   switched off.

## 6. Issue tracking

Each issue has a title, the acceptance criteria as a checklist, a label, an assignee and a milestone.
Bugs must include reproduction steps and expected vs actual behaviour. Reference issues in commits
(`refs #14`) and in PRs (`Closes #14`).

## 7. Releases

Tag `main` at milestones: `v0.1-alpha` (Week 4: URL analysis end-to-end), `v0.2-beta` (Week 8: all
analyzers), `v1.0-rc` (Week 11), `v1.0` (final submission). Release notes are generated from PR titles.
