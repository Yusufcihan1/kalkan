"""Kalkan simgesi: koyu yeşil kalkan, içinde nane yeşili onay işareti."""
from PIL import Image, ImageDraw

S = 1024


def draw(size):
    k = 4
    W = size * k
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = W * 0.08
    top, bot = m, W - m
    left, right = m * 1.4, W - m * 1.4
    cx = W / 2
    shield = [(cx, top), (right, top + W * 0.12), (right, top + W * 0.42), (cx + W * 0.02, bot), (cx - W * 0.02, bot),
              (left, top + W * 0.42), (left, top + W * 0.12)]
    # yumuşak alt kıvrım için çokgeni noktalarla zenginleştir
    pts = [(cx, top), (right, top + W * 0.13)]
    import math
    for i in range(0, 21):
        t = i / 20
        x = right - (right - cx) * t
        y = top + W * 0.42 + (bot - top - W * 0.42) * math.sin(t * math.pi / 2)
        pts.append((x, y))
    for i in range(20, -1, -1):
        t = i / 20
        x = left + (cx - left) * t
        y = top + W * 0.42 + (bot - top - W * 0.42) * math.sin(t * math.pi / 2)
        pts.append((x, y))
    pts.append((left, top + W * 0.13))
    d.polygon(pts, fill=(15, 31, 26, 255))
    inset = W * 0.06
    pts2 = [(cx + (x - cx) * 0.86, top + inset + (y - top) * 0.86) for x, y in pts]
    d.polygon(pts2, fill=(11, 110, 91, 255))
    lw = int(W * 0.075)
    d.line([(W * 0.33, W * 0.52), (W * 0.46, W * 0.65), (W * 0.69, W * 0.38)], fill=(95, 211, 176, 255), width=lw, joint="curve")
    for p in [(W * 0.33, W * 0.52), (W * 0.69, W * 0.38)]:
        d.ellipse([p[0] - lw / 2, p[1] - lw / 2, p[0] + lw / 2, p[1] + lw / 2], fill=(95, 211, 176, 255))
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    big = draw(256)
    big.save("app/static/icon.png")
    big.save("icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("ok")
