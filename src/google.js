// Marks the Google homepage so google.css can apply homepage-only rules.
// A data attribute rather than a class, so Google's own scripts rewriting
// <html class="..."> can't wipe it out.
const { pathname, search } = window.location;
const params = new URLSearchParams(search);
const isHome = (pathname === "/" || pathname === "/webhp") && (!params.has("q") || params.has("zx"));

if (isHome) {
  document.documentElement.dataset.blhsPage = "home";
}
