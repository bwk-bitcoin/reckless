#pragma once

// The Silent Payments account type mark (the design kit's SpMark), the app mark before
// the reckless one (ws-plaude/silent#111): a broken ring plus a filled centre dot. Both
// follow the live theme color (stroke + fill).

namespace embedded_icon {

constexpr char SP_MARK[] = R"svg(<svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
<circle cx="24" cy="24" r="18" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-dasharray="102 113.1" transform="rotate(-33 24 24)"/>
<circle cx="24" cy="24" r="5.5" fill="currentColor"/>
</svg>)svg";

} // namespace embedded_icon
