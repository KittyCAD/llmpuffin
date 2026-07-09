/**
 * llmpuffin frontend bundle.
 *
 * Imports htmx, idiomorph (htmx morph extension), Alpine.js, and CodeMirror.
 * Registers Alpine stores/data and DOM event listeners.
 */

// ── Vendor imports ──

import htmx from "htmx.org";
import "idiomorph/dist/idiomorph-ext.esm.js";
import Alpine from "alpinejs";

import { EditorView, basicSetup } from "codemirror";
import { EditorState } from "@codemirror/state";
import { StreamLanguage } from "@codemirror/language";
import { toml } from "@codemirror/legacy-modes/mode/toml";

// Expose globals — inline template scripts reference these directly
window.htmx = htmx;
window.Alpine = Alpine;

// ── Alpine store: UI (theme + sidebar) ──

document.addEventListener("alpine:init", () => {
  Alpine.store("ui", {
    sidebarCollapsed:
      localStorage.getItem("llmpuffin.sidebar.collapsed") === "1",
    dark: document.documentElement.classList.contains("dark"),
    toggleSidebar() {
      this.sidebarCollapsed = !this.sidebarCollapsed;
      localStorage.setItem(
        "llmpuffin.sidebar.collapsed",
        this.sidebarCollapsed ? "1" : "0"
      );
    },
    toggleTheme() {
      this.dark = !this.dark;
      localStorage.setItem("llmpuffin.theme", this.dark ? "dark" : "light");
    },
  });
});

// ── Alpine store: Toasts ──

document.addEventListener("alpine:init", () => {
  Alpine.store("toasts", {
    items: [],
    _id: 0,
    push(level, message) {
      const id = ++this._id;
      this.items.push({ id, level: level || "info", message: message || "" });
      setTimeout(() => this.dismiss(id), 4500);
    },
    dismiss(id) {
      this.items = this.items.filter((x) => x.id !== id);
    },
  });
});

// Surface stashed toast (across HX-Location nav) + URL params on first load.
document.addEventListener("alpine:initialized", () => {
  const toasts = Alpine.store("toasts");
  try {
    const pending = JSON.parse(
      sessionStorage.getItem("llmpuffin.pendingToast") || "null"
    );
    if (pending) {
      sessionStorage.removeItem("llmpuffin.pendingToast");
      toasts.push(pending.level, pending.message);
    }
  } catch (_) {}
  try {
    const p = new URLSearchParams(window.location.search);
    let changed = false;
    ["success", "error", "info"].forEach((k) => {
      const v = p.get(k);
      if (v) {
        toasts.push(k, v);
        p.delete(k);
        changed = true;
      }
    });
    if (changed) {
      const qs = p.toString();
      history.replaceState(
        {},
        "",
        window.location.pathname +
          (qs ? "?" + qs : "") +
          window.location.hash
      );
    }
  } catch (_) {}
});

// htmx → toast bridges.
document.addEventListener("toast", (e) => {
  const d = e.detail || {};
  Alpine.store("toasts").push(d.level, d.message);
});
document.addEventListener("htmx:beforeOnLoad", (e) => {
  const xhr = e.detail && e.detail.xhr;
  if (!xhr || !xhr.getResponseHeader) return;
  const trigger = xhr.getResponseHeader("HX-Trigger");
  const loc = xhr.getResponseHeader("HX-Location");
  if (trigger && loc) {
    try {
      const parsed = JSON.parse(trigger);
      if (parsed && parsed.toast) {
        sessionStorage.setItem(
          "llmpuffin.pendingToast",
          JSON.stringify(parsed.toast)
        );
      }
    } catch (_) {}
  }
});
document.addEventListener("htmx:responseError", (e) => {
  const xhr = e.detail && e.detail.xhr;
  Alpine.store("toasts").push(
    "error",
    "Request failed" + (xhr ? " (" + xhr.status + ")" : "")
  );
});
document.addEventListener("htmx:sendError", () => {
  Alpine.store("toasts").push("error", "Network error");
});

// ── Alpine data: sortable tables ──

document.addEventListener("alpine:init", () => {
  Alpine.data("sortable", () => ({
    col: null,
    asc: true,
    sort(key) {
      if (this.col === key) {
        this.asc = !this.asc;
      } else {
        this.col = key;
        this.asc = true;
      }
      const tbody = this.$root.querySelector("tbody");
      const rows = Array.from(tbody.querySelectorAll("tr"));
      const dir = this.asc ? 1 : -1;
      rows.sort((a, b) => {
        const ca = a.querySelector("[data-sort-" + key + "]");
        const cb = b.querySelector("[data-sort-" + key + "]");
        if (!ca || !cb) return 0;
        const va = ca.getAttribute("data-sort-" + key);
        const vb = cb.getAttribute("data-sort-" + key);
        const na = parseFloat(va),
          nb = parseFloat(vb);
        if (!isNaN(na) && !isNaN(nb)) return (na - nb) * dir;
        return va.localeCompare(vb, undefined, { sensitivity: "base" }) * dir;
      });
      rows.forEach((r) => tbody.appendChild(r));
    },
    sortClass(key) {
      if (this.col !== key) return "sortable";
      return "sortable " + (this.asc ? "asc" : "desc");
    },
  }));
});

// ── Clickable table rows ──

document.addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-href]");
  if (!tr) return;
  if (e.target.closest("a, button, input, select, textarea, form")) return;
  if (e.ctrlKey || e.metaKey) {
    window.open(tr.dataset.href, "_blank");
  } else {
    window.location.href = tr.dataset.href;
  }
});
document.addEventListener("auxclick", (e) => {
  if (e.button !== 1) return;
  const tr = e.target.closest("tr[data-href]");
  if (!tr) return;
  window.open(tr.dataset.href, "_blank");
  e.preventDefault();
});

// ── Local timezone formatting for <time> elements ──

function formatTimes(root) {
  (root || document).querySelectorAll("time[datetime]").forEach((el) => {
    const d = new Date(el.getAttribute("datetime"));
    if (isNaN(d)) return;
    const fmt = el.dataset.fmt || "short";
    const opts = {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    };
    if (fmt === "long") opts.second = "2-digit";
    el.textContent = d.toLocaleString(undefined, opts);
  });
}
document.addEventListener("htmx:load", (e) => formatTimes(e.detail.elt));

// ── CodeMirror: TOML editor / viewer ──

const cmTheme = EditorView.theme({
  "&": {
    fontSize: "0.8125rem",
    border: "1px solid hsl(var(--border))",
    borderRadius: "var(--radius)",
  },
  ".cm-content": {
    fontFamily: '"Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
    padding: "0.5rem 0",
  },
  ".cm-gutters": {
    fontFamily: '"Geist Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
    border: "none",
    background: "hsl(var(--muted) / 0.3)",
  },
  ".cm-activeLine": { background: "hsl(var(--muted) / 0.3)" },
  ".cm-activeLineGutter": { background: "hsl(var(--muted) / 0.5)" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { overflow: "auto" },
});

function initCodeMirror(root) {
  (root || document)
    .querySelectorAll("[data-codemirror]")
    .forEach((el) => {
      if (el._cmView) return; // already initialized

      const mode = el.dataset.codemirror; // "edit" or "readonly"
      const readonly = mode === "readonly";

      // For "edit": el is a <textarea> inside a form. Replace it with CM.
      // For "readonly": el is a <div> with content in data-value.
      const doc = readonly
        ? (el.dataset.value || "")
        : el.value || "";

      const extensions = [
        basicSetup,
        cmTheme,
        EditorView.lineWrapping,
        StreamLanguage.define(toml),
      ];

      if (readonly) {
        extensions.push(EditorState.readOnly.of(true));
        extensions.push(EditorView.editable.of(false));
      } else {
        // Sync changes back to a hidden textarea for form submission
        const textarea = el;
        extensions.push(
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              textarea.value = update.state.doc.toString();
            }
          })
        );
      }

      const state = EditorState.create({ doc, extensions });
      const parent = readonly ? el : document.createElement("div");

      if (!readonly) {
        el.style.display = "none";
        el.parentNode.insertBefore(parent, el);
      }

      const view = new EditorView({ state, parent });
      el._cmView = view;
    });
}
document.addEventListener("htmx:load", (e) => initCodeMirror(e.detail.elt));

// ── Start Alpine ──

Alpine.start();
