declare module "idiomorph/dist/idiomorph-ext.esm.js";
declare module "alpinejs";
declare module "@codemirror/legacy-modes/mode/toml" {
  export const toml: any;
}
declare module "d3-hierarchy";
declare module "d3-selection";
declare module "d3-scale";

interface Window {
  htmx: any;
  Alpine: any;
}