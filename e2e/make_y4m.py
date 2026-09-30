"""Write a short Y4M video that shows a QR code (fake camera input for Chromium). DEMO / TEST DATA."""

import sys

import qrcode
from PIL import Image

out = sys.argv[1]
payload = "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund"
W, H = 640, 480
code = qrcode.make(payload).convert("L").resize((360, 360), Image.Resampling.NEAREST)
frame = Image.new("L", (W, H), 255)
frame.paste(code, ((W - 360) // 2, (H - 360) // 2))
y_plane = frame.tobytes()
uv_plane = bytes([128]) * ((W // 2) * (H // 2))
with open(out, "wb") as f:
    f.write(f"YUV4MPEG2 W{W} H{H} F10:1 Ip A1:1 C420jpeg\n".encode())
    for _ in range(20):
        f.write(b"FRAME\n" + y_plane + uv_plane + uv_plane)
print("wrote", out)
