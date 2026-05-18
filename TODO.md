- allow closing findings by referencing it with a github issue
- allow opening github issues from the finding tab
- Support auditing of PRs (create containers with ref checked out + PR descriptions as context)


Prompt:
- avoid duplicating risks like, yes hoops could be vulnerable
- explain other repos are available
- improve memory instructions, it mostly created audit_notes.md

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