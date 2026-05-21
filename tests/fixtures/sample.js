// Line 1: normal usage
const el = document.getElementById("app");

// Line 4: property access with dot
window.document.title = "hello";

// Line 7: should NOT match — no dot before document
let documentName = "test";

// Line 10: another dot-prefixed match
this.document.createElement("div");

// Line 13: false positive if dot not escaped — xdocument
let xdocument = "nope";
