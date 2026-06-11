- allow closing findings by referencing it with a github issue
- allow opening github issues from the finding tab
- Support auditing of PRs (create containers with ref checked out + PR descriptions as context)


- make validation notes an array. We want to allow for multiple rounds of validation, and we don't want to lose the previous notes. Maybe we can also add a timestamp to each note?

- resolving links in locations is broken if the LLM links to a finding outside of /src/target, src/modeling-app/src/components/CommandBar/CommandBarSelectionInput.tsx:196
- We maybe need a better heuristic to match links. Maybe we configure only an org and then analyze the link if its a known repo.

- use git blame
- never attach readble documents as findings, those typicalls go into notes

- fresh containers per thread? e.g. when forking you get a new one

- confirmation about the action that will be performed when releasing on github

- We want that we can publish code to private forks. Like the github advisory private fork.

- add justificatiosn for severity and difficulty

- types for threads (main, finding)

- allow comments on findings

- allow stopping conversations

- support editing severity as well as other fields

- support effort https://reference.langchain.com/python/langchain-anthropic/chat_models/ChatAnthropic/effort

- build docker images dynamically or via UI

- ingegrate this knowledge: https://github.com/KittyCAD/wiki/blob/fb9734660deb02b01f28bea291a40690289564d4/eng/full-stack-local-development.md?plain=1#L4

- add post audit step that checks if findings were validated, PoC exists. Add a stage that can ask quesitosn back automatically, or propose the user options.

- feature: validation of external findings

Bugs:
- deduplicate findings in one thread at least
- the composer does not update when starting a thread from a finding
- memory handling must be more conservative. If we give the memory to the next run, it is likely going to ignore bugs as they were deemed irrelevant

Prompt:
- avoid duplicating risks like, yes hoops could be vulnerable
- explain other repos are available
- improve memory instructions, it mostly created audit_notes.md
- explain that users can not access container contents (you need to show examples)
- make clear that we are zoo/kittycad. Data exfiltrated is only relevant if it crosses a threat zone

Validation:
- building and setting the project up
- allow exporting files from the container

TM:
- Zoo will have one thread-model, or maybe ZDS as a whole. We need to make sure that the LLM picks the risks relevant for it.
- improving thread model post audit
- thread model editing in forked chats

Tools:
- systematic creation of Semgrep rules
- CodeQL available as tool
- searching through security issues on github
  - Deduplicating with existing findings in GH and the database

Misc: 
- pausable chats and web ui to continue them

Open questions:
- What about memories? - I think we store them in the db now, validate
- How to do validation? make sure it does what it can
- tweak the todos, maybe one todo list per agent/validation/finding?
- 