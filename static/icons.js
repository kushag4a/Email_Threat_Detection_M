/* ============================================================
   Inline SVG icon system (Phase 2 fix)
   Self-contained — no external icon font / CDN required.
   All icons share the same 24x24 grid, 2px rounded stroke.
   ============================================================ */
const ICONS = {
  home: '<path d="M3 11.5 12 4l9 7.5"/><path d="M5 10v9a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1v-9"/>',
  inbox: '<path d="M4 12h4l2 3h4l2-3h4"/><path d="M5 4h14l2 8v7a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-7z"/>',
  'chart-pie': '<path d="M12 12V3a9 9 0 1 1-9 9h9z"/>',
  'chart-line': '<path d="M4 19h16"/><path d="M4 15l4-5 4 3 4-7 4 4"/>',
  grid: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18M15 3v18"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.5-6 8-6s8 2 8 6"/>',
  gear: '<circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2.2"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7"/><rect x="10.5" y="20.1" width="3" height="3" rx="0.7"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(45 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(90 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(135 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(180 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(225 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(270 12 12)"/><rect x="10.5" y="0.9" width="3" height="3" rx="0.7" transform="rotate(315 12 12)"/>',
  logout: '<path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3"/><path d="M15 16l4-4-4-4"/><path d="M19 12H9"/>',
  bell: '<path d="M18 16v-5a6 6 0 1 0-12 0v5l-2 3h16z"/><path d="M10 21a2 2 0 0 0 4 0"/>',
  scan: '<circle cx="10" cy="10" r="6"/><path d="M8 12V9M10 12V7M12 12V9.5"/><path d="M15 15l5 5"/>',
  'file-import': '<path d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v4h4"/><path d="M12 11v6M9 14l3 3 3-3"/>',
  warning: '<path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4"/><circle cx="12" cy="17" r="1" fill="currentColor" stroke="none"/>',
  refresh: '<path d="M4 12a8 8 0 0 1 14.6-4.6M20 12a8 8 0 0 1-14.6 4.6"/><path d="M18.6 3v4.4H14.2"/><path d="M5.4 21v-4.4H9.8"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  'chevron-left': '<path d="M15 5l-7 7 7 7"/>',
  'chevron-right': '<path d="M9 5l7 7-7 7"/>',
  'file-export': '<path d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v4h4"/><path d="M12 17v-6M9 14l3-3 3 3"/>',
  upload: '<path d="M7 18a4 4 0 0 1-.6-7.96A5 5 0 0 1 16 9a4 4 0 0 1 1 7.9"/><path d="M12 20v-8"/><path d="M9 15l3-3 3 3"/>',
  shield: '<path d="M12 3l7 3v6c0 5-3.4 8.4-7 9-3.6-.6-7-4-7-9V6l7-3z"/><path d="M12 3v18"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  pin: '<path d="M12 21s7-6.1 7-11a7 7 0 1 0-14 0c0 4.9 7 11 7 11z"/><circle cx="12" cy="10" r="2.4"/>',
  gauge: '<path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4-5"/><circle cx="12" cy="15" r="1.2" fill="currentColor" stroke="none"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.2a2.5 2.5 0 1 1 3.8 2.1c-.9.6-1.3 1-1.3 2.1"/><circle cx="12" cy="17" r="1" fill="currentColor" stroke="none"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  key: '<circle cx="8" cy="15" r="3.4"/><path d="M10.4 12.6 19 4"/><path d="M15.5 8 18 10.5"/><path d="M18 5.5 20.5 8"/>',
  route: '<circle cx="6" cy="18" r="2.2"/><circle cx="18" cy="6" r="2.2"/><path d="M8 18h5a3 3 0 0 0 3-3v-1a3 3 0 0 1 3-3"/>',
  paperclip: '<path d="M8 12.5V7a4 4 0 0 1 8 0v9a2.5 2.5 0 0 1-5 0V8.5"/>',
  bot: '<rect x="5" y="8" width="14" height="10" rx="2"/><circle cx="9" cy="13" r="1.2" fill="currentColor" stroke="none"/><circle cx="15" cy="13" r="1.2" fill="currentColor" stroke="none"/><path d="M12 8V5M9 5h6"/><path d="M3 12h2M19 12h2"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.8 2.6 2.8 15.4 0 18M12 3c-2.8 2.6-2.8 15.4 0 18"/>',
  satellite: '<path d="M4 14a9 9 0 0 1 9-9"/><path d="M9 15l9-9"/><circle cx="9" cy="15" r="1.6" fill="currentColor" stroke="none"/><path d="M4 20l3-3"/><path d="M14 6.5a4 4 0 0 1 3.5 3.5"/>',
  layers: '<path d="M12 3 3 8l9 5 9-5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  flag: '<path d="M5 3v18"/><path d="M5 4h11l-2.5 4L16 12H5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  spinner: '<circle cx="12" cy="12" r="9" opacity="0.25"/><path d="M21 12a9 9 0 0 0-9-9"/>',
  'file-question': '<path d="M6 3h8l4 4v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v4h4"/><path d="M10.8 13.3a1.4 1.4 0 1 1 2.1 1.2c-.5.35-.7.6-.7 1.1"/><circle cx="12" cy="16.6" r=".15" fill="currentColor" stroke="none"/>',
  plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
  'circle-check': '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9"/>',
  dollar: '<path d="M12 2v20"/><path d="M17 6.5c0-2-2-3-5-3s-5 1.2-5 3 2 2.6 5 3 5 1.3 5 3.3-2 3.2-5 3.2-5-1.2-5-3.2"/>',
  bug: '<rect x="7" y="8" width="10" height="10" rx="4"/><path d="M12 8V5M9 5 7.5 3.5M15 5l1.5-1.5M4 12h3M17 12h3M5 17l2.5-1.5M19 17l-2.5-1.5"/>',
  folder: '<path d="M3 6.5a1.5 1.5 0 0 1 1.5-1.5H9l2 2.2h8.5A1.5 1.5 0 0 1 21 8.7v9.3a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18V6.5z"/>',
  palette: '<circle cx="12" cy="12" r="9"/><circle cx="8.2" cy="10" r="1.3" fill="currentColor" stroke="none"/><circle cx="12" cy="7.5" r="1.3" fill="currentColor" stroke="none"/><circle cx="15.8" cy="10" r="1.3" fill="currentColor" stroke="none"/><circle cx="9" cy="14.5" r="1.3" fill="currentColor" stroke="none"/><path d="M12 21a9 9 0 0 1 0-18c1 0 1.6.6 1.6 1.5 0 .5-.2.9-.5 1.2-.3.3-.5.7-.5 1.1 0 .8.7 1.4 1.5 1.4H16a4 4 0 0 1 4 4c0 4.9-3.6 8.8-8 8.8z"/>',
  download: '<path d="M12 4v11"/><path d="M8 11.5 12 15.5 16 11.5"/><path d="M5 19h14"/>',
  moon: '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a6.8 6.8 0 0 0 10.5 10.5z"/>',
  sun: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.4M12 19.1v2.4M4.2 4.2l1.7 1.7M18.1 18.1l1.7 1.7M2.5 12h2.4M19.1 12h2.4M4.2 19.8l1.7-1.7M18.1 5.9l1.7-1.7"/>',
  check: '<path d="M4.5 12.5 9 17 19.5 6.5"/>',
  swap: '<path d="M4 8h13"/><path d="M14 4l3 4-3 4"/><path d="M20 16H7"/><path d="M10 12l-3 4 3 4"/>',
  link: '<path d="M9.5 14.5 14.5 9.5"/><path d="M11 6.5 12.6 4.9a3.6 3.6 0 0 1 5 5L16 11.5"/><path d="M13 17.5 11.4 19.1a3.6 3.6 0 0 1-5-5L8 12.5"/>',
  calendar: '<rect x="3" y="4.5" width="18" height="16" rx="2"/><path d="M3 9.5h18"/><path d="M8 3v3M16 3v3"/>'
};

function ic(name, cls){
  const body = ICONS[name] || ICONS.help;
  return `<svg class="icon${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${body}</svg>`;
}

/* Convert every static placeholder <i data-icon="name"> in the DOM into
   an inline SVG. Runs once at load — icons never depend on network access. */
function hydrateIcons(root){
  (root || document).querySelectorAll('[data-icon]').forEach(el => {
    const name = el.getAttribute('data-icon');
    const extraCls = el.getAttribute('data-icon-class') || '';
    el.outerHTML = ic(name, extraCls);
  });
}
hydrateIcons(document);
