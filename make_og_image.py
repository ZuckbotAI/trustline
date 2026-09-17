"""Generate the Trustline link-preview (og:image) card: 1200x630."""
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 1200, 630
BG_TOP = (43, 39, 112)      # deep indigo #2b2770
BG_BOT = (23, 21, 58)       # darker indigo
ACCENT = (224, 123, 57)     # burnt orange #e07b39
WHITE = (245, 244, 252)
MUTED = (178, 175, 205)

img = Image.new("RGB", (W, H))
px = img.load()
for y in range(H):
    t = y / H
    for x in range(W):
        px[x, y] = tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3))
d = ImageDraw.Draw(img)

# subtle orange glow circle, top-right
glow = Image.new("L", (W, H), 0)
gd = ImageDraw.Draw(glow)
gd.ellipse([W - 420, -160, W + 160, 420], fill=46)
img = Image.composite(Image.new("RGB", (W, H), (58, 44, 30)), img, glow)
d = ImageDraw.Draw(img)

# checkmark badge (matches favicon): rounded square + orange check
bx, by, bs, br = 120, 195, 200, 44
d.rounded_rectangle([bx, by, bx + bs, by + bs], radius=br, fill=(52, 47, 128), outline=ACCENT, width=6)
# check: from (bx+55, by+105) to (bx+92, by+140) to (bx+150, by+62)
d.line([(bx + 52, by + 102), (bx + 90, by + 140)], fill=ACCENT, width=22, joint="curve")
d.line([(bx + 90, by + 140), (bx + 152, by + 58)], fill=ACCENT, width=22, joint="curve")

fb = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
fr = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
f_title = ImageFont.truetype(fb, 128)
f_tag = ImageFont.truetype(fr, 44)
d.text((370, 205), "Trustline", font=f_title, fill=WHITE)
tag = "Your work, verified."
tw = d.textlength(tag, font=f_tag)
tx = max(122, (W - tw) / 2)
d.text((122, 450), tag, font=f_tag, fill=MUTED)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "og-image.png")
os.makedirs(os.path.dirname(out), exist_ok=True)
img.save(out, "PNG")
print("wrote", out, img.size)
