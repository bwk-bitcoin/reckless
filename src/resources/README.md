# Embedded Resources

Fonts and other binary assets are embedded as C++ headers containing `constexpr`
byte arrays. This avoids the Qt resource system while keeping assets compiled
into the binary.

## Embedding a font

```bash
cd src/resources
./embed_font.sh /path/to/Font-Regular.ttf font/font_name.h FONT_NAME
```

This generates a header with a `constexpr uint8_t` array in the
`embedded_font` namespace.

## Loading at runtime

```cpp
#include "resources/font/noto_sans.h"
#include <QFontDatabase>

QFontDatabase::addApplicationFontFromData(
    QByteArray(reinterpret_cast<const char *>(embedded_font::NOTO_SANS),
               embedded_font::NOTO_SANS_SIZE));
```

Call this once before creating any widgets (e.g. in `main.cpp` after
`QApplication` is constructed).

## Current embedded fonts

| Header | Font | Variable |
|--------|------|----------|
| `font/noto_sans.h` | Noto Sans Regular | `NOTO_SANS` |

## Embedding icons (Lucide)

```bash
cd src/resources
./fetch_icons.sh
```

This clones the [Lucide](https://lucide.dev) icon set, generates one header per
SVG in `icon/<name>.h` (raw string literal in the `embedded_icon` namespace),
and a master `icon/icons.h` that includes all of them.

Only icons that are `#include`d in C++ code contribute to binary size.

### Using an icon

1. Include the generated header:
   ```cpp
   #include "resources/icon/trash_2.h"
   ```
2. Render with `renderIcon()` from `theme/Icon.h`:
   ```cpp
   auto qicon = renderIcon(embedded_icon::TRASH_2, 24, color, 2);
   ```
3. Or use a named helper (add new ones in `theme/Icon.cpp`):
   ```cpp
   button->setIcon(icon::trash());
   ```

Named helpers read color from `Palette` and size/stroke from `IconPalette`
so icons automatically follow the current theme.

### Browsing available icons

Browse and search the full icon set at **https://lucide.dev/icons**.
Use the search bar to find icons by name or concept (e.g. "wallet",
"arrow", "settings"). The filename on the site maps directly to the
header name: `arrow-right` on the site → `icon/arrow_right.h` →
`embedded_icon::ARROW_RIGHT`.

## The app mark

`brand/reckless_mark.svg` is the app mark, drawn in its own colours: the window icon
(`icon::windowIcon`) and the menu tab (`icon::recklessMark`). After changing it, run

```bash
src/resources/brand/generate_mark.sh
```

It regenerates `icon/reckless_mark.h` (the SVG as `embedded_icon::RECKLESS_MARK`) and
`brand/png/reckless_mark_<size>.png` at 16, 24, 32, 48, 64, 128, 256 and 512 px, rendered
by Qt's SVG renderer (`brand/render_mark.cpp`). CMake stops at configure time when the
header does not hold the SVG unchanged.

## Platform app icons

The same script writes `brand/reckless.ico` (16, 24, 32, 48, 64 and 256 px) and
`brand/reckless.icns` (16 to 512 px at @1x and @2x) with `brand/pack_icons.py`. CMake
compiles the `.ico` into the Windows executable (`brand/reckless.rc.in`), makes the
`.icns` the macOS bundle icon (`MACOSX_BUNDLE_ICON_FILE`), and on Linux installs
`brand/reckless.desktop` with the mark under `share/icons/hicolor` (scalable SVG plus
the PNGs). The Nix Linux output gets them through `cmake --install`.

## The full logo

`brand/reckless_wordmark_black.svg` and `brand/reckless_wordmark_white.svg` are the full
reckless logo (ws-plaude/silent#120): dark letters for a light theme, white letters for a
dark one, on the welcome screen (`MenuTab`, `icon::recklessWordmark`). `generate_mark.sh`
embeds them as `icon/reckless_wordmark_{black,white}.h` and renders
`brand/png/reckless_wordmark_{black,white}_<WxH>.png` at 300, 600 and 1200 px wide; CMake
checks the headers against the SVGs like the mark's. `HEADERS_ONLY=1` writes only the
headers, with no compiler.
