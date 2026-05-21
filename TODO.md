- allow closing findings by referencing it with a github issue
- allow opening github issues from the finding tab
- Support auditing of PRs (create containers with ref checked out + PR descriptions as context)


- make validation notes an array. We want to allow for multiple rounds of validation, and we don't want to lose the previous notes. Maybe we can also add a timestamp to each note?

- resolving links in locations is broken if the LLM links to a finding outside of /src/target 
- We maybe need a better heuristic to match links. Maybe we configure only an org and then analyze the link if its a known repo.

Bugs:
- deduplicate findings in one thread at least
- 


Prompt:
- avoid duplicating risks like, yes hoops could be vulnerable
- explain other repos are available
- improve memory instructions, it mostly created audit_notes.md
- explain that users can not access container contents (you need to show examples)

Validation:
- building and setting the project up
- allow exporting files from the container

TM:
- Zoo will have one thread-model, or maybe ZDS as a whole. We need to make sure that the LLM picks the risks relevant for it.
- improving thread model post audit
- thread model editing in forked chats

Tools:

- searching through security issues on github
  - Deduplicating with existing findings in GH and the database

Misc: 
- pausable chats and web ui to continue them

Open questions:
- What about memories? - I think we store them in the db now, validate
- How to do validation? make sure it does what it can
- tweak the todos, maybe one todo list per agent/validation/finding?
- 