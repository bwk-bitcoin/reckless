#include "theme/Icon.h"

#include <QColor>
#include <QIcon>
#include <QImage>
#include <QPainter>
#include <QPixmap>
#include <QRect>
#include <QSize>

#include <algorithm>
#include <cstdlib>

namespace smoke {
namespace {

void require(bool passed, const char *context) {
    if (!passed) {
        qFatal("window icon: %s", context);
    }
}

// The buffer Qt 6.9 and later send a Wayland compositor for one window icon size, as
// QWaylandXdgToplevelIconV1::addPixmap fills it: a straight alpha image the pixmap is
// drawn into, announced as premultiplied ARGB8888.
auto waylandBuffer(const QIcon &icon, const QSize &size) -> QImage {
    const QPixmap pixmap = icon.pixmap(size, 1.0);
    QImage buffer(pixmap.size(), QImage::Format_ARGB32);
    buffer.fill(0);
    {
        QPainter painter(&buffer);
        painter.drawPixmap(pixmap.rect(), pixmap, pixmap.rect());
    }
    return buffer;
}

// The largest channel difference, over `background`, between the compositor drawing
// `buffer` as premultiplied and the mark drawn as it should be.
auto compositeError(const QImage &buffer, const QImage &mark, const QColor &background) -> int {
    int error = 0;
    for (int y = 0; y < mark.height(); ++y) {
        for (int x = 0; x < mark.width(); ++x) {
            const QRgb read = buffer.pixel(x, y);
            const QRgb want = mark.pixel(x, y);
            const int read_alpha = qAlpha(read);
            const int want_alpha = qAlpha(want);
            const int channels[3][3] = {
                {qRed(read), qRed(want), background.red()},
                {qGreen(read), qGreen(want), background.green()},
                {qBlue(read), qBlue(want), background.blue()},
            };
            for (const auto &channel : channels) {
                // Premultiplied over the background, as the compositor blends.
                const int drawn =
                    std::min(255, channel[0] + (((255 - read_alpha) * channel[2]) + 127) / 255);
                const int correct =
                    ((channel[1] * want_alpha) + (channel[2] * (255 - want_alpha)) + 127) / 255;
                error = std::max(error, std::abs(drawn - correct));
            }
        }
    }
    return error;
}

auto maxError(const QIcon &icon) -> int {
    int error = 0;
    for (const QSize &size : icon.availableSizes()) {
        QImage mark(size, QImage::Format_ARGB32_Premultiplied);
        mark.fill(Qt::transparent);
        {
            QPainter painter(&mark);
            icon::recklessMark().paint(&painter, mark.rect());
        }
        mark = mark.convertToFormat(QImage::Format_ARGB32);
        const QImage buffer = waylandBuffer(icon, size);
        require(buffer.size() == mark.size(), "a buffer is not at its icon size");
        for (const QColor &background : {QColor(0xef, 0xf0, 0xf1), QColor(0x2a, 0x2e, 0x32)}) {
            error = std::max(error, compositeError(buffer, mark, background));
        }
    }
    return error;
}

} // namespace

void windowIconSmoke() {
    const QIcon straight = icon::windowIcon(false);
    const QIcon premultiplied = icon::windowIcon(true);
    require(straight.availableSizes().size() == 7, "the window icon has not its 7 sizes");
    require(premultiplied.availableSizes() == straight.availableSizes(),
            "the premultiplied window icon has other sizes");
    for (const QSize &size : straight.availableSizes()) {
        require(straight.pixmap(size, 1.0).size() == size, "a window icon size is rescaled");
    }
    // The reckless mark (ws-plaude/silent#111) keeps its 206.37 x 211.83 proportions,
    // centred: the R's stem, at the SVG's left edge, lands about 3 px in from the 256 px
    // image's left side instead of on it, and the mark draws its own blues.
    const QImage big = straight.pixmap(QSize(256, 256), 1.0).toImage();
    require(qAlpha(big.pixel(0, 128)) == 0 && qAlpha(big.pixel(255, 128)) == 0,
            "the mark is stretched to the square: its sides touch the icon's edges");
    int inked = 0;
    for (int x = 0; x < big.width(); ++x) {
        const QRgb pixel = big.pixel(x, 128);
        if (qAlpha(pixel) == 255) {
            require(qBlue(pixel) > qRed(pixel) && qBlue(pixel) > qGreen(pixel),
                    "the window icon is not drawn in the reckless mark's blues");
            ++inked;
        }
    }
    require(inked > 0, "the window icon draws nothing across its middle");
    bool stem = false;
    for (int x = 3; x <= 8; ++x) {
        stem |= qAlpha(big.pixel(x, 128)) == 255;
    }
    require(stem, "no R stem 3 to 8 px in from the left: the window icon is not the reckless mark");

    // ws-plaude/silent#120: the full logo on the welcome screen, white letters for a dark
    // theme and dark ones for a light theme, its blue mark the same in both.
    for (bool dark : {false, true}) {
        const QImage logo = icon::recklessWordmark(dark).pixmap(QSize(600, 152), 1.0).toImage();
        int white = 0;
        int black = 0;
        for (int y = 0; y < logo.height(); ++y) {
            for (int x = logo.width() / 3; x < logo.width(); ++x) {
                const QRgb pixel = logo.pixel(x, y);
                if (qAlpha(pixel) < 255) {
                    continue;
                }
                white += qRed(pixel) > 230 && qGreen(pixel) > 230 && qBlue(pixel) > 230 ? 1 : 0;
                black += qRed(pixel) < 40 && qGreen(pixel) < 40 && qBlue(pixel) < 40 ? 1 : 0;
            }
        }
        require(dark ? (white > 0 && black == 0) : (black > 0 && white == 0),
                "the logo's letters are white on a dark theme and dark on a light one");
    }

    // The offscreen platform is not Wayland: the icon goes as it is.
    require(!icon::windowIconPremultiplied(), "offscreen asks for a premultiplied window icon");

    // Through the Wayland buffer, the straight icon's edges come out far too bright, the
    // premultiplied one's as drawn, within rounding: a pixmap keeps its colours
    // premultiplied, so a nearly transparent pixel (alpha about 11) is off by up to 12 on
    // a channel.
    const int straight_error = maxError(straight);
    const int premultiplied_error = maxError(premultiplied);
    qInfo("window icon: wayland composite error straight %d, premultiplied %d", straight_error,
          premultiplied_error);
    require(straight_error > 40, "the straight icon composites right: the check sees no bug");
    require(premultiplied_error <= 12, "the premultiplied icon composites wrong");
}

} // namespace smoke
