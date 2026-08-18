attach file should link to the tool call/message

- extend coverage tool to query coverage combined of the past n runs with the same project

- Ability to query user for answers on a set of quetions, e.g. scoping clarification
- Project context/prompt used for all profiles/projects
- Capture network traffic

## Bugs:
- Clone always gets latest ref. But we want to use the one of the audit run.

## Open questions
- Concept of projects to group profiles?
- Where are todo notes stored? do they survive restarts?
- What about memories? - I think we store them in the db now, validate
- How to do validation? make sure it does what it can
- Should we introduce the term "projects" to bundle profiles and findings? Project -> profiles -> findings

## Future directions:
- feature: validation of external findings
- Support auditing of PRs (create containers with ref checked out + PR descriptions as context)

## Sandboxing:
- Prepare fat Docker image with many tools included
- Allow amd64 execution of images
- Restrict reading AGENT.md files as they might inject arbitrary instructions

## Resilience:
- On shutdown, mark running audits as "interrupted" instead of "aborted" and persist their checkpoint state. On startup, auto-resume any interrupted threads so a new instance picks up where the old one left off.

## Penetration tests:

- Credentials, target endpoint and API schema as inputs
- Multiple accounts at different privilege levels for IDOR/BOLA testing
- Out-of-scope definition and enforcement
- Resource ownership model:
  - Per-user (each user owns their data)
  - Per-organization (shared within an org)
  - Mixed (combination of user-scoped, org-scoped, and public resources)
- Workflow: recon and endpoint mapping, vulnerability identification, exploitation with PoC, severity rating, remediation guidance, final report with executive summary ranked by business impact

## Harness:
- Multi-step flows:
  0) Discover the checked out code:
  - Is LFS required? Warn
  - Which ecosystems do we use?
  1) create script to setup env. Run and optionally persist it for future "cold start runs"
  2) Audit and report findings.
  3) Validation of all.
  4) Create Semgrep and CodeQL rules for avoiding findings in the future.
  5) Report on gaps of this audit run.
- New mode: focus on commits of the past week, month
- memory handling must be more conservative. If we give the memory to the next run, it is likely going to ignore bugs as they were deemed irrelevant
- Deduplicating with existing findings in GH and the database
- build docker images dynamically or via UI
- fresh containers per thread? e.g. each forking should get a forked/cloned container
- Validation:
  - allow exporting files from the container
  - add post audit step that checks if findings were validated, PoC exists. Add a stage that can ask question back automatically, or propose the user options.


## Prompt/Tool usage docs:
- avoid duplicating risks like, yes hoops could be vulnerable
- explain other repos are available
- improve memory instructions, it mostly created audit_notes.md
- explain that users can not access container contents (you need to show examples)
- make clear that we are zoo/kittycad. Data exfiltrated is only relevant if it crosses a threat zone
- add justificatiosn for severity and difficulty
- integrate this knowledge: https://github.com/KittyCAD/wiki/blob/fb9734660deb02b01f28bea291a40690289564d4/eng/full-stack-local-development.md?plain=1#L4
- never attach readable documents as attachments, those typically go into notes

## TM:
- Zoo will have one thread-model, or maybe ZDS as a whole. We need to make sure that the LLM picks the risks relevant for it.
- improving thread model post audit
- thread model editing in forked chats

## Tools:
- systematic creation of Semgrep rules
- CodeQL available as tool
- searching through security issues on github
- We want that we can publish code to private forks. Like the github advisory private fork.
- use git blame


## Misc:
- pausable chats and web ui to continue them

## Publication/Export:
- confirmation about the action that will be performed when releasing on github
- allow closing findings by tracking a GitHub issue

Reasons for not finding a bug:

- missing depth
- lack of identifying relevant sinks (for billing its minting credits)
