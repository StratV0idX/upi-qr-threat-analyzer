# -----------------------------------------
# Project: UPI QR Threat Analyzer
# Author: Roshan Jeffrin R
# GitHub: https://github.com/StratV0idX
# Description: Detects potential UPI QR scams using heuristic analysis
# -----------------------------------------
import cv2
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image
from urllib.parse import urlparse, parse_qs


# Extract info from url
def parse_upi(upi_string):
    parsed = urlparse(upi_string)
    params = parse_qs(parsed.query)

    return {
        "pa": params.get("pa", [""])[0],
        "pn": params.get("pn", [""])[0],
        "am": params.get("am", [""])[0],
        "tn": params.get("tn", [""])[0],
        "cu": params.get("cu", [""])[0],
        "mc": params.get("mc", [""])[0],
    }


def analyze_risk(url):
    check = 0
    reasons = []

    # 1. No amount (static QR)
    if not url["am"]:
        check += 2
        reasons.append("No amount (Static QR)")

    # 2. Wallet-based handles
    legit_handles = [
        "@upi",
        "@oksbi",
        "@okhdfcbank",
        "@okaxis",
        "@okicici",
        "@paytm",
        "@ybl",  # PhonePe
        "@ibl",  # ICICI Bank
        "@axl",  # Axis Bank
        "@apl",  # Airtel Payments Bank
        "@airtel",
        "@postbank",
        "@indus",
        "@hsbc",
        "@kotak",
        "@rbl",
        "@yesbank",
        "@sib",  # South Indian Bank
        "@fbl",  # Federal Bank
        "@idbi",
        "@dbs",
        "@citi",
        "@pnb",
        "@barodampay",
        "@sbi",
    ]
    if not any(handle in url["pa"] for handle in legit_handles):
        check += 2
        reasons.append("Unknown or suspicious UPI handle")

    # 3. Generic ID (numbers in ID)
    if any(char.isdigit() for char in url["pa"]):
        check += 1
        reasons.append("Generic/random UPI ID")

    # 4. No transaction note
    if not url["tn"]:
        check += 2
        reasons.append("No transaction note")

    # 5. Suspicious keywords
    suspicious_keywords = [
        "receive",
        "receive money",
        "get money",
        "claim",
        "claim reward",
        "reward",
        "cashback",
        "free",
        "offer",
        "win",
        "winner",
        "prize",
        "gift",
        "bonus",
        "urgent",
        "limited",
        "now",
        "click",
        "scan to receive",
        "scan & earn",
        "verify",
        "update",
        "kyc",
        "refund",
        "request",
        "collect",
        "approval",
        "pending",
        "release",
        "credit",
        "transfer",
        "processing",
        "guaranteed",
        "instant",
        "loan",
        "emi",
        "otp",
        "password",
        "secure",
        "security",
        "alert",
        "suspended",
        "blocked",
        "reactivate",
        "link",
        "http",
        "https",
        ".com",
        ".in",
        "bit.ly",
        "tinyurl",
        "shorturl",
    ]
    if any(word in url["pn"].lower() for word in suspicious_keywords):
        check += 2
        reasons.append("Suspicious keywords in name")

    return check, reasons


def exit():
    frame.destroy()


def at_screen():
    for widget in frame.winfo_children()[3:]:  # keep title + image + button
        widget.destroy()

    Label(scroll_frame, text="--- ANALYSIS REPORT ---", font=("Arial", 14)).pack()
    Label(scroll_frame, text=f"Url: {data}").pack()
    Label(scroll_frame, text=f"UPI ID: {url['pa']}").pack()
    Label(scroll_frame, text=f"Name: {url['pn']}").pack()
    Label(scroll_frame, text=f"Amount: {url['am']}").pack()
    Label(scroll_frame, text=f"Transaction Note: {url['tn']}").pack()
    Label(scroll_frame, text=f"Currency: {url['cu']}").pack()
    Label(scroll_frame, text=f"Merchant Code: {url['mc']}").pack()
    Label(scroll_frame, text=f"Risk Score: {score}").pack()
    Label(scroll_frame, text=f"Risk: {risk_text}", fg=risk_color).pack()

    Label(scroll_frame, text="Reasons:", font=("Arial", 12)).pack()

    for r in reasons:
        Label(scroll_frame, text=f"- {r}").pack()

    Label(
        frame,
        text="Developed by Roshan Jeffrin R | GitHub: StratV0idX",
        font=("Arial", 8),
    ).pack()
    b.config(state="disabled")
    Button(scroll_frame, text="Exit", command=exit).pack()


# Initiating Frame
frame = Tk()
frame.title("Qr code analyser")
frame.geometry("640x640")


# Create canvas
canvas = Canvas(frame)
canvas.pack(side=LEFT, fill=BOTH, expand=True)

# Add scrollbar
scrollbar = Scrollbar(frame, orient=VERTICAL, command=canvas.yview)
scrollbar.pack(side=RIGHT, fill=Y)

# Configure canvas
canvas.configure(yscrollcommand=scrollbar.set)

# Create inner frame
scroll_frame = Frame(canvas)

# Add frame to canvas
canvas.create_window((0, 0), window=scroll_frame, anchor="nw")


# Update scroll region
def on_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


scroll_frame.bind("<Configure>", on_configure)

Label(scroll_frame, text="Qr Code Analyser", font=("impact", 30)).pack()
Label(scroll_frame, text="Choose the QR Code", font=(10)).pack()
image_path = filedialog.askopenfilename(
    title="Select QR Image",
    filetypes=[
        ("Image Files", "*.png"),
        ("Image Files", "*.jpg"),
        ("Image Files", "*.jpeg"),
        ("Image Files", "*.tiff"),
        ("Image Files", "*.bmp"),
        ("Image Files", "*.svg"),
    ],
)

# OpenCV image (for detection)
cv_img = cv2.imread(image_path)
pil_img = Image.open(image_path)

# PIL image (for display)
tk_img = ImageTk.PhotoImage(pil_img)
img_label = Label(frame, image=tk_img)
img_label.pack()

# Initialize QR detector
detector = cv2.QRCodeDetector()

# Detect and decode
data, bbox, _ = detector.detectAndDecode(cv_img)

if data:
    print("QR Code Data:", data)

    # Draw bounding box
    if bbox is not None:
        for i in range(len(bbox)):
            pt1 = tuple(map(int, bbox[i][0]))
            pt2 = tuple(map(int, bbox[(i + 1) % len(bbox)][0]))
            cv2.line(cv_img, pt1, pt2, (0, 255, 0), 2)
    else:
        print("No QR code found")

    url = parse_upi(data)

    analyze_risk(url)

    score, reasons = analyze_risk(url)

    # Decide risk level
    if score >= 6:
        risk_text = "HIGH RISK"
        risk_color = "Red"  # Red
    elif score >= 3:
        risk_text = "MEDIUM RISK"
        risk_color = "Yellow"  # Yellow
    else:
        risk_text = "LOW RISK"
        risk_color = "Green"  # Green

b = Button(scroll_frame, text="ANALYSE", command=at_screen)
b.pack()
frame.mainloop()
