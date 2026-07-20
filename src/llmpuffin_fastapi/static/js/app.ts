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

import { treemap, hierarchy, treemapSquarify } from "d3-hierarchy";
import { select } from "d3-selection";
import { scaleLinear } from "d3-scale";

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
document.addEventListener("toast", ((e: CustomEvent) => {
  const d = e.detail || {};
  Alpine.store("toasts").push(d.level, d.message);
}) as EventListener);
document.addEventListener("htmx:beforeOnLoad", ((e: CustomEvent) => {
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
}) as EventListener);
document.addEventListener("htmx:responseError", ((e: CustomEvent) => {
  const xhr = e.detail && e.detail.xhr;
  Alpine.store("toasts").push(
    "error",
    "Request failed" + (xhr ? " (" + xhr.status + ")" : "")
  );
}) as EventListener);
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
      const tbody = (this as any).$root.querySelector("tbody");
      const rows = Array.from(tbody.querySelectorAll("tr")) as HTMLElement[];
      const dir = this.asc ? 1 : -1;
      rows.sort((a: HTMLElement, b: HTMLElement) => {
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
  const target = e.target as HTMLElement;
  const tr = target.closest("tr[data-href]") as HTMLElement | null;
  if (!tr) return;
  if (target.closest("a, button, input, select, textarea, form")) return;
  if (e.ctrlKey || e.metaKey) {
    window.open(tr.dataset.href, "_blank");
  } else {
    window.location.href = tr.dataset.href;
  }
});
document.addEventListener("auxclick", (e) => {
  if (e.button !== 1) return;
  const tr = (e.target as HTMLElement).closest("tr[data-href]") as HTMLElement | null;
  if (!tr) return;
  window.open(tr.dataset.href, "_blank");
  e.preventDefault();
});

// ── Local timezone formatting for <time> elements ──

function formatTimes(root: Element | Document) {
  (root || document).querySelectorAll("time[datetime]").forEach((el) => {
    const d = new Date(el.getAttribute("datetime")!);
    if (isNaN(d.getTime())) return;
    const fmt = (el as HTMLElement).dataset.fmt || "short";
    const opts: Intl.DateTimeFormatOptions = {
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
document.addEventListener("htmx:load", ((e: CustomEvent) => formatTimes(e.detail.elt)) as EventListener);

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
      // Skip if already initialized (direct hit or sibling CM editor exists)
      if (el._cmView) return;
      if (el.previousElementSibling && el.previousElementSibling.classList.contains("cm-editor")) return;
      if (el.querySelector && el.querySelector(".cm-editor")) return;

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
document.addEventListener("htmx:load", ((e: CustomEvent) => initCodeMirror(e.detail.elt)) as EventListener);

// ── Coverage treemap (d3) ──

function initTreemap(root) {
  (root || document)
    .querySelectorAll("[data-treemap]")
    .forEach((el) => {
      if (el._treemap) return;
      el._treemap = true;

      const raw = JSON.parse(el.dataset.treemap);
      if (!raw || !raw.dirs || !raw.dirs.length) return;
      const allData = raw.dirs;
      const allFiles = raw.files;

      el.style.position = "relative";

      const colorScale = (pct) => {
        if (pct >= 80) return "hsl(var(--success) / 0.7)";
        if (pct >= 40) return "hsl(var(--warning, 38 92% 50%) / 0.6)";
        if (pct > 0) return "hsl(var(--destructive) / 0.5)";
        return "hsl(var(--muted))";
      };

      // Breadcrumb bar
      const nav = select(el)
        .append("div")
        .style("margin-bottom", "0.5rem")
        .style("font-size", "0.8125rem")
        .style("font-family", "'Geist Mono', ui-monospace, monospace");

      // SVG container
      const svgContainer = select(el).append("div");

      // File list container (shown when clicking a leaf dir)
      const fileListContainer = select(el).append("div");

      // Tooltip
      const tooltip = select(el)
        .append("div")
        .style("position", "absolute")
        .style("pointer-events", "none")
        .style("background", "hsl(var(--card))")
        .style("border", "1px solid hsl(var(--border))")
        .style("border-radius", "var(--radius)")
        .style("padding", "0.375rem 0.625rem")
        .style("font-size", "0.75rem")
        .style("box-shadow", "0 2px 8px rgba(0,0,0,0.15)")
        .style("opacity", 0)
        .style("z-index", 10);

      interface DirGroup {
        path: string;
        total: number;
        reached: number;
        hasChildren: boolean;
        isFiles?: boolean;
        value?: number;
      }

      function groupAtDepth(prefix: string, depth: number): DirGroup[] {
        // Group dirs under prefix by taking `depth` path segments.
        // Returns aggregated groups with hasChildren flag.
        const groups: Record<string, DirGroup> = {};
        const pfx = prefix ? prefix + "/" : "";

        for (const d of allData) {
          // Skip the "." root entry and dirs outside our prefix
          if (d.path === ".") continue;
          if (prefix && !d.path.startsWith(pfx)) continue;

          const rest = prefix ? d.path.slice(pfx.length) : d.path;
          const segments = rest.split("/");
          const key = segments.slice(0, depth).join("/");
          if (!key) continue;

          const fullPath = prefix ? pfx + key : key;
          if (!groups[key]) groups[key] = { path: fullPath, total: 0, reached: 0, hasChildren: false };
          groups[key].total += d.total;
          groups[key].reached += d.reached;
          if (segments.length > depth) {
            groups[key].hasChildren = true;
          }
        }

        // Also include files directly in the prefix dir (the "." equivalent)
        for (const d of allData) {
          if (d.path === (prefix || ".")) {
            const key = "(files)";
            if (!groups[key]) groups[key] = { path: d.path, total: 0, reached: 0, hasChildren: false, isFiles: true };
            groups[key].total += d.total;
            groups[key].reached += d.reached;
          }
        }

        return Object.values(groups).filter((g: DirGroup) => g.total > 0);
      }

      function renderBreadcrumb(prefix: string) {
        nav.html("");
        const parts = prefix ? prefix.split("/") : [];

        nav
          .append("a")
          .text("/")
          .attr("href", "#/")
          .style("text-decoration", "none")
          .style("color", parts.length ? "hsl(var(--primary))" : "hsl(var(--foreground))")
          .style("font-weight", parts.length ? "normal" : "600")
          .on("click", (e) => { e.preventDefault(); render(""); });

        for (let i = 0; i < parts.length; i++) {
          nav.append("span").text(i > 0 ? " / " : " ").style("color", "hsl(var(--muted-foreground))");
          const p = parts.slice(0, i + 1).join("/");
          const isLast = i === parts.length - 1;
          nav
            .append("a")
            .text(parts[i])
            .attr("href", "#/" + p)
            .style("text-decoration", "none")
            .style("color", isLast ? "hsl(var(--foreground))" : "hsl(var(--primary))")
            .style("font-weight", isLast ? "600" : "normal")
            .on("click", (e) => { e.preventDefault(); render(p); });
        }

      }

      let _pushHistory = true;

      function showFiles(dirPath: string) {
        fileListContainer.html("");
        const pfx = dirPath + "/";
        const files = allFiles.filter((f) => {
          const dir = f.path.lastIndexOf("/") >= 0 ? f.path.slice(0, f.path.lastIndexOf("/")) : ".";
          return dir === dirPath;
        });
        if (!files.length) return;

        const header = fileListContainer
          .append("div")
          .style("display", "flex")
          .style("align-items", "center")
          .style("justify-content", "space-between")
          .style("padding", "0.5rem 0.75rem 0.25rem")
          .style("border-top", "1px solid hsl(var(--border))");

        header
          .append("span")
          .style("font-family", "'Geist Mono', ui-monospace, monospace")
          .style("font-size", "0.8125rem")
          .style("font-weight", "500")
          .text(dirPath + "/");

        header
          .append("button")
          .text("close")
          .style("font-size", "0.75rem")
          .style("padding", "0.125rem 0.5rem")
          .style("cursor", "pointer")
          .style("border", "1px solid hsl(var(--border))")
          .style("border-radius", "var(--radius)")
          .style("background", "transparent")
          .style("color", "hsl(var(--muted-foreground))")
          .on("click", () => fileListContainer.html(""));

        const list = fileListContainer
          .append("div")
          .style("max-height", "16rem")
          .style("overflow-y", "auto")
          .style("padding", "0 0.75rem 0.5rem");

        for (const f of files) {
          const name = f.path.split("/").pop();
          const row = list
            .append("div")
            .style("display", "flex")
            .style("align-items", "center")
            .style("gap", "0.5rem")
            .style("padding", "0.2rem 0")
            .style("font-size", "0.75rem")
            .style("font-family", "'Geist Mono', ui-monospace, monospace");

          row
            .append("span")
            .style("width", "8px")
            .style("height", "8px")
            .style("border-radius", "50%")
            .style("flex-shrink", "0")
            .style("background", f.reached ? "hsl(var(--success))" : "hsl(var(--muted))");

          row.append("span").text(name);
        }
      }

      function render(prefix: string) {
        fileListContainer.html("");
        const children = groupAtDepth(prefix, 2);
        if (!children.length) return;

        renderBreadcrumb(prefix);

        // Update URL fragment
        const frag = "#/" + prefix;
        if (_pushHistory && window.location.hash !== frag) {
          history.pushState(null, "", frag);
        }

        const width = el.clientWidth || 800;
        const height = Math.max(350, Math.min(width * 0.55, 550));

        svgContainer.html("");

        const rootNode = hierarchy({
          name: "root",
          children: children.map((d: DirGroup) => ({ ...d, value: d.total })),
        })
          .sum((d) => d.value || 0)
          .sort((a, b) => b.value - a.value);

        treemap()
          .size([width, height])
          .padding(2)
          .round(true)
          .tile(treemapSquarify)(rootNode);

        const svg = svgContainer
          .append("svg")
          .attr("viewBox", `0 0 ${width} ${height}`)
          .style("width", "100%")
          .style("height", "auto")
          .style("display", "block")
          .style("border-radius", "var(--radius)");

        const leaves = rootNode.leaves();

        const cells = svg
          .selectAll("g")
          .data(leaves)
          .join("g")
          .attr("transform", (d) => `translate(${d.x0},${d.y0})`)
          .style("cursor", (d) => (d.data.isFiles ? "default" : "pointer"));

        cells
          .append("rect")
          .attr("width", (d) => d.x1 - d.x0)
          .attr("height", (d) => d.y1 - d.y0)
          .attr("rx", 3)
          .attr("fill", (d) => {
            const pct = d.data.total > 0 ? (100 * d.data.reached) / d.data.total : 0;
            return colorScale(pct);
          })
          .attr("stroke", "hsl(var(--card))")
          .attr("stroke-width", 1)
          .style("transition", "opacity 0.15s")
          .on("mouseenter", function (event, d) {
            svg.selectAll("rect").style("opacity", 0.4);
            select(this).style("opacity", 1);
            const pct = d.data.total > 0 ? Math.round((100 * d.data.reached) / d.data.total) : 0;
            const label = d.data.isFiles ? "(files in " + (prefix || "/") + ")" : d.data.path + "/";
            tooltip
              .html(
                `<strong style="font-family:'Geist Mono',monospace">${label}</strong><br>` +
                `${d.data.reached}/${d.data.total} files · ${pct}%` +
                (!d.data.isFiles ? `<br><span style="color:hsl(var(--muted-foreground))">click to ${d.data.hasChildren ? "expand" : "show files"}</span>` : "")
              )
              .style("opacity", 1);
          })
          .on("mousemove", function (event) {
            const rect = el.getBoundingClientRect();
            tooltip
              .style("left", event.clientX - rect.left + 12 + "px")
              .style("top", event.clientY - rect.top - 10 + "px");
          })
          .on("mouseleave", function () {
            svg.selectAll("rect").style("opacity", 1);
            tooltip.style("opacity", 0);
          })
          .on("click", function (event, d) {
            if (d.data.isFiles) return;
            tooltip.style("opacity", 0);
            if (d.data.hasChildren) {
              render(d.data.path);
            } else {
              showFiles(d.data.path);
            }
          });

        // Labels
        cells
          .filter((d) => d.x1 - d.x0 > 60 && d.y1 - d.y0 > 28)
          .append("text")
          .attr("x", (d) => (d.x1 - d.x0) / 2)
          .attr("y", (d) => (d.y1 - d.y0) / 2 - 4)
          .attr("text-anchor", "middle")
          .attr("dominant-baseline", "middle")
          .attr("fill", "hsl(var(--foreground))")
          .attr("font-size", (d) => (d.x1 - d.x0 > 120 ? 11 : 9))
          .attr("font-family", "'Geist Mono', ui-monospace, monospace")
          .style("pointer-events", "none")
          .text((d) => {
            const maxChars = Math.floor((d.x1 - d.x0) / 7);
            if (d.data.isFiles) return "(files)";
            // Show path relative to current prefix
            const pfx = prefix ? prefix + "/" : "";
            const label = d.data.path.startsWith(pfx) ? d.data.path.slice(pfx.length) : d.data.path;
            return label.length > maxChars ? label.slice(0, maxChars - 1) + "…" : label;
          });

        cells
          .filter((d) => d.x1 - d.x0 > 60 && d.y1 - d.y0 > 40)
          .append("text")
          .attr("x", (d) => (d.x1 - d.x0) / 2)
          .attr("y", (d) => (d.y1 - d.y0) / 2 + 10)
          .attr("text-anchor", "middle")
          .attr("dominant-baseline", "middle")
          .attr("fill", "hsl(var(--foreground) / 0.7)")
          .attr("font-size", 9)
          .style("pointer-events", "none")
          .text((d) => {
            const pct = d.data.total > 0 ? Math.round((100 * d.data.reached) / d.data.total) : 0;
            return `${pct}% · ${d.data.reached}/${d.data.total}`;
          });
      }

      // Read initial path from URL fragment
      const initialPath = (window.location.hash || "").replace(/^#\/?/, "");
      _pushHistory = false;
      render(initialPath);
      _pushHistory = true;

      // Support back/forward navigation
      window.addEventListener("popstate", () => {
        const path = (window.location.hash || "").replace(/^#\/?/, "");
        _pushHistory = false;
        render(path);
        _pushHistory = true;
      });
    });
}
document.addEventListener("htmx:load", ((e: CustomEvent) => initTreemap(e.detail.elt)) as EventListener);

// ── Start Alpine ──

Alpine.start();
