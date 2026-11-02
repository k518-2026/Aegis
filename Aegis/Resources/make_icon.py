"""
Aegis アプリアイコン生成スクリプト
盾（Aegis = 神話の盾）＋点検済みのチェックを、アプリ本体と同じ配色で描く。
16〜32px 用は線を太く・階調を単純にした別デザインを描き分ける。
"""
from PIL import Image, ImageDraw
import os

ACCENT_TOP = (94, 190, 255)
ACCENT_BOTTOM = (26, 111, 214)
INK = (13, 16, 22)
INK_TOP = (42, 49, 61)
WHITE = (255, 255, 255)

SS = 8  # スーパーサンプリング倍率


def qbez(p0, p1, p2, steps=40):
    """2次ベジェ曲線の点列"""
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0]
        y = u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def shield_points(cx, top, w, h, r):
    """上部は角丸、下部は先端がまるい盾の輪郭"""
    left, right = cx - w / 2, cx + w / 2
    shoulder = top + h * 0.45   # ここから内側へ絞り込む
    tip = top + h
    p = []
    # 左上の角丸
    p += qbez((left, top + r), (left, top), (left + r, top))
    # 上辺 → 右上の角丸
    p += qbez((right - r, top), (right, top), (right, top + r))
    # 右側面 → 先端
    p.append((right, shoulder))
    p += qbez((right, shoulder), (right, top + h * 0.86), (cx, tip))
    # 先端 → 左側面
    p += qbez((cx, tip), (left, top + h * 0.86), (left, shoulder))
    return p


def gradient(size, c_top, c_bottom):
    img = Image.new("RGB", (1, size))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(size - 1, 1)
        d.point((0, y), tuple(int(a + (b - a) * t) for a, b in zip(c_top, c_bottom)))
    return img.resize((size, size), Image.BILINEAR)


def check_points(cx, cy, s):
    """チェックマーク（太さのある多角形）"""
    return [
        (cx - 0.46 * s, cy - 0.02 * s),
        (cx - 0.24 * s, cy - 0.24 * s),
        (cx - 0.08 * s, cy + 0.10 * s),
        (cx + 0.34 * s, cy - 0.40 * s),
        (cx + 0.50 * s, cy - 0.20 * s),
        (cx - 0.07 * s, cy + 0.40 * s),
    ]


def draw_icon(px, simple=False):
    n = px * SS
    canvas = Image.new("RGBA", (n, n), (0, 0, 0, 0))

    # --- 盾のマスク ---
    margin = n * (0.07 if simple else 0.08)
    w = n - margin * 2
    h = n - margin * 2
    pts = shield_points(n / 2, margin, w, h, w * 0.20)

    mask = Image.new("L", (n, n), 0)
    ImageDraw.Draw(mask).polygon(pts, fill=255)

    if simple:
        body = Image.new("RGB", (n, n), (45, 145, 235))
    else:
        body = gradient(n, ACCENT_TOP, ACCENT_BOTTOM)
    canvas.paste(body, (0, 0), mask)

    d = ImageDraw.Draw(canvas)

    if not simple:
        # 内側に一段暗い盾を敷き、面に厚みを出す（上から下へゆるやかに暗くする）
        inner = shield_points(n / 2, margin + h * 0.085, w * 0.83, h * 0.845, w * 0.17)
        inner_mask = Image.new("L", (n, n), 0)
        ImageDraw.Draw(inner_mask).polygon(inner, fill=255)
        canvas.paste(gradient(n, INK_TOP, INK), (0, 0), inner_mask)

    # --- チェックマーク ---
    cx = n / 2
    cy = n * (0.50 if simple else 0.505)
    s = n * (0.56 if simple else 0.54)
    d.polygon(check_points(cx, cy, s), fill=WHITE + (255,))

    return canvas.resize((px, px), Image.LANCZOS)


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    sizes = [16, 20, 24, 32, 48, 64, 128, 256]
    images = [draw_icon(s, simple=(s <= 32)) for s in sizes]

    ico = os.path.join(out_dir, "aegis.ico")
    images[-1].save(ico, format="ICO",
                    sizes=[(s, s) for s in sizes],
                    append_images=images[:-1])

    images[-1].save(os.path.join(out_dir, "aegis-256.png"))
    print("生成しました:", ico)


if __name__ == "__main__":
    main()
