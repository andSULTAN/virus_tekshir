import os
import time
import requests
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)

# --- Kalitlar ---
TELEGRAM_TOKEN = "8338047326:AAE4Ov4TUQZAMv-DWng40BOke96ZjShrEuA"
VT_API_KEY = "5f6b2c23c95cbe0a3c0f2221dea2859b766a304a3ecfc59d06e21c457a212872"

# --- Faylni VirusTotalga yuborish ---
def scan_file_with_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                return response.json()["data"]["id"]
    except Exception as e:
        print(f"Fayl yuborishda xatolik: {str(e)}")
    return None

# --- Linkni VirusTotalga yuborish ---
def scan_url_with_virustotal(url_to_scan):
    scan_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url_to_scan}
    try:
        response = requests.post(scan_url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()["data"]["id"]
    except Exception as e:
        print(f"URL yuborishda xatolik: {str(e)}")
    return None

# --- Tahlil natijasi ---
def get_analysis_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}

    for i in range(50):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                status = data["data"]["attributes"]["status"]

                if status == "completed":
                    stats = data["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)

                    if malicious > 0:
                        return f"""🚨 *XAVFLI FAYL ANIQLANDI!*

🦠 VirusToplam tahliliga ko‘ra, bu faylda *{malicious} ta xavfli virus* aniqlangan.

❗️ Bu fayl qurilmangizga zarar yetkazishi, shaxsiy ma'lumotlaringizni o‘g‘irlashi yoki boshqa zararli harakatlar qilishi mumkin (masalan: parollarni o‘g‘irlash, ruxsatlarsiz kuzatish, fonda yashirin ishlash).

🟨 Shubhali: {suspicious}  
🟩 Zararsiz: {harmless}  
❓ Aniqlanmagan: {undetected}

📛 *Tavsiya:* Bu faylni OCHMANG va zudlik bilan o‘chiring. Antivirus orqali qurilmangizni tekshiring."""

                    elif suspicious > 0:
                        return f"""⚠️ *Shubhali fayl aniqlandi.*

Fayl xavfli bo‘lmasligi mumkin, ammo ayrim antiviruslar uni shubhali deb baholagan.

🟥 Xavfli: {malicious}
🟨 Shubhali: {suspicious}
🟩 Zararsiz: {harmless}

📌 *Tavsiya:* Faqat ishonchli manbadan foydalaning, extiyot bo‘ling."""

                    else:
                        return f"""✅ *Hech qanday xavf aniqlanmadi.*

VirusTotal servisiga ko‘ra bu fayl zararsiz.

🟩 Zararsiz: {harmless}
❓ Aniqlanmagan: {undetected}

✔️ Fayl xavfsiz deb topildi."""

        except Exception as e:
            print(f"Tahlil olishda xatolik: {str(e)}")
        time.sleep(5)

    return "⏳ 25 soniya kutildi, lekin hali tahlil tugamadi."

# --- Fayl yuborilganda ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        document = update.message.document
        file = await document.get_file()
        file_path = f"./{document.file_name}"

        await file.download_to_drive(custom_path=file_path)
        await update.message.reply_text("🕒 Faylingiz VirusTotal orqali tekshirilmoqda...")

        analysis_id = scan_file_with_virustotal(file_path)
        if analysis_id:
            result = get_analysis_result(analysis_id)
            await update.message.reply_text(result, parse_mode="Markdown")
        else:
            await update.message.reply_text("❌ Faylni VirusTotal’ga yuborishda muammo yuz berdi.")

        os.remove(file_path)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Xatolik: {str(e)}")

# --- Link yuborilganda ---
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text("❗ Bu URL emas. Iltimos, to‘g‘ri link yuboring.")
        return

    await update.message.reply_text("🔎 Link VirusTotal orqali tekshirilmoqda...")

    analysis_id = scan_url_with_virustotal(url)
    if analysis_id:
        result = get_analysis_result(analysis_id)
        await update.message.reply_text(result, parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Linkni VirusTotal’ga yuborishda xatolik yuz berdi.")

# --- /start komandasi ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [
            InlineKeyboardButton("📂 Fayl yuborish", callback_data="file"),
            InlineKeyboardButton("🔗 Link yuborish", callback_data="url"),
        ],
        [InlineKeyboardButton("ℹ️ Yordam", callback_data="help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        text=(
            "👋 Assalomu alaykum!\n"
            "Men Virus skaneri botman.\n\n"
            "📁 Fayl yoki 🔗 Link yuboring — VirusTotal orqali xavfsizligini tekshiraman.\n"
            "⏱️ Tekshiruv odatda 30-60 soniya davom etadi."
        ),
        reply_markup=reply_markup
    )

# --- Tugmalar ishlovi ---
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        query = update.callback_query
        await query.answer()

        if query.data == "file":
            await query.edit_message_text("📁 Fayl yuboring. Uni tekshirib beraman.")
        elif query.data == "url":
            await query.edit_message_text("🔗 Link yuboring. Virusli yoki yo‘qligini tekshiraman.")
        elif query.data == "help":
            await query.edit_message_text(
                "🛠️ *Foydalanish yo‘riqnomasi:*\n\n"
                "📂 Fayl yoki 🔗 Link yuboring.\n"
                "⏳ VirusTotal orqali 30-60 soniyada tekshiraman.\n"
                "🛡️ Xavfsizlik natijalarini chiqaraman.",
                parse_mode="Markdown"
            )
        else:
            await query.edit_message_text("⚠️ Noma'lum buyruq.")
    except Exception as e:
        await update.callback_query.message.reply_text(f"❌ Tugmani ishlov berishda xatolik: {str(e)}")

# --- Botni ishga tushirish ---
def main():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.run_polling()

if __name__ == "__main__":
    main()
