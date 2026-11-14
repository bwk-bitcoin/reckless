// Renders an SVG into square PNGs with Qt's SVG renderer, the one the app draws the
// mark with: its aspect ratio kept and centred, rendered at 4x and scaled down.
//
// Usage: render_mark <svg> <output prefix> <size>...
// Writes <output prefix><size>.png for each size.

#include <QGuiApplication>
#include <QImage>
#include <QPainter>
#include <QSvgRenderer>
#include <cstdio>

int main(int argc, char **argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QGuiApplication app(argc, argv);
    if (argc < 4) {
        std::fprintf(stderr, "usage: render_mark <svg> <output prefix> <size>...\n");
        return 2;
    }
    QSvgRenderer renderer(QString::fromLocal8Bit(argv[1]));
    if (!renderer.isValid()) {
        std::fprintf(stderr, "render_mark: cannot read %s\n", argv[1]);
        return 1;
    }
    renderer.setAspectRatioMode(Qt::KeepAspectRatio);
    constexpr int supersample = 4;
    for (int i = 3; i < argc; ++i) {
        const int size = QString::fromLocal8Bit(argv[i]).toInt();
        if (size <= 0) {
            std::fprintf(stderr, "render_mark: bad size %s\n", argv[i]);
            return 2;
        }
        QImage big(size * supersample, size * supersample, QImage::Format_ARGB32_Premultiplied);
        big.fill(Qt::transparent);
        {
            QPainter painter(&big);
            renderer.render(&painter, QRectF(big.rect()));
        }
        auto image = big.scaled(size, size, Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
        auto path =
            QString::fromLocal8Bit(argv[2]) + QString::number(size) + QStringLiteral(".png");
        if (!image.save(path)) {
            std::fprintf(stderr, "render_mark: cannot write %s\n", qPrintable(path));
            return 1;
        }
    }
    return 0;
}
