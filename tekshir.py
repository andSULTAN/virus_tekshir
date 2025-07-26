import requests
import time
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# 🔐 Token va API kalitni shu yerga joylang
TELEGRAM_TOKEN = "8338047326:AAGf3OAgZyG-XXMRhzHdoRfVBNLu-o65fg4
VT_API_KEY = "5f6b2c23c95cbe0a3c0f2221dea2859b766a304a3ecfc59d06e21c457a212872"

# --- VirusTotal fayl skan ---
def scan_file_with_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()["data"]["id"]
    return None

# --- VirusTotal URL skan ---
def scan_url_with_virustotal(url_to_scan):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url_to_scan}
    response = requests.post(scan_url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()["data"]["id"]
    return None

# --- Tahlil natijasini olish ---
def get_analysis_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    for _ in range(5):  # 5 marta tekshiramiz, tahlil tugashini kutamiz
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                stats = data["data"]["attributes"]["stats"]
                return f"""
🔍 VirusTotal tahlil natijasi:

🟥 Tahlikali (malicious): {stats.get("malicious", 0)}
🟨 Shubhali (suspicious): {stats.get("suspicious", 0)}
🟩 Zararsiz (harmless): {stats.get("harmless", 0)}
❓ Aniqlanmagan: {stats.get("undetected", 0)}
                """.strip()
        time.sleep(5)  # Har 5 soniyada qaytadan tekshir
    return "⏳ Tahlil hali tugamagan yoki xatolik yuz berdi."

# --- Fayl yuborilganda ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = await update.message.document.get_file()
    file_path = f"./{update.message.document.file_name}"
    await file.download_to_drive(file_path)
    await update.message.reply_text("🕒 Faylingiz tekshirilmoqda...")
    analysis_id = scan_file_with_virustotal(file_path)
    if analysis_id:
        result = get_analysis_result(analysis_id)
        await update.message.reply_text(result)
    else:
        await update.message.reply_text("❌ VirusTotal’ga yuborishda xatolik yuz berdi.")

# --- Link yuborilganda ---
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("❗ Bu URL emas. Menga to‘g‘ri link yuboring.")
        return
    await update.message.reply_text("🔎 Link VirusTotal orqali tekshirilmoqda...")
    analysis_id = scan_url_with_virustotal(url)
    if analysis_id:
        result = get_analysis_result(analysis_id)
        await update.message.reply_text(result)
    else:
        await update.message.reply_text("❌ Linkni VirusTotal’ga yuborishda xatolik yuz berdi.")

# --- /start komandasi ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Salom! Fayl yoki havola (link) yuboring — virus bor-yo‘qligini tekshiraman 🔍")

# --- Botni ishga tushirish ---
def main():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.run_polling()

if __name__ == "__main__":
    main()
