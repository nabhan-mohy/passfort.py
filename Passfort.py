import re
import math
import string
import requests
import hashlib
from typing import Dict, Tuple
import secrets
import time
from ratelimit import limits, sleep_and_retry
from colorama import init, Fore, Style

# Initialize colorama for cross-platform color support
init()
BLUE = Fore.BLUE
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET
LARGE = Style.BRIGHT  # Using Style.BRIGHT for emphasis

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.char_sets = {
            'lowercase': set(string.ascii_lowercase),
            'uppercase': set(string.ascii_uppercase),
            'digits': set(string.digits),
            'special': set(string.punctuation)
        }
        self.keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '1q2w3e',
            'poiuyt', 'lkjhgf', 'mnbvcx', '123qwe', 'zaq12wsx'
        ]
        self.last_api_call = 0

    def _load_common_passwords(self) -> set:
        """Load a larger set of common passwords"""
        common = {
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', 'football', 'abc123', 'password1',
            '12345678', '111111', '123123', 'admin123', 'master',
            'sunshine', 'princess', 'dragon', 'passw0rd', 'baseball',
            'trustno1', 'shadow', 'michael', 'jennifer', 'superman',
            '123456789', 'qazwsx', 'killer', 'bailey', 'password123'
        }
        return common

    @sleep_and_retry
    @limits(calls=1, period=2)
    def _check_hibp_breach(self, password: str) -> bool:
        """Check if password appears in Have I Been Pwned database with rate limiting
        Uses SHA-1 hashing and k-anonymity for privacy"""
        try:
            sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {'User-Agent': 'PasswordAnalyzer/1.0'}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for h in hashes:
                    if h.split(':')[0] == suffix:
                        return True
            return False
        except Exception:
            return False

    def analyze_password(self, password: str, username: str = "") -> Dict:
        analysis = {
            'strength_score': 0,
            'entropy': 0.0,
            'weaknesses': [],
            'recommendations': [],
            'metrics': {},
            'suggested_passwords': []
        }
        analysis['metrics'].update(self._evaluate_strength(password))
        analysis['weaknesses'].extend(self._detect_weaknesses(password, username))
        analysis['entropy'] = self._calculate_entropy(password)
        analysis['metrics']['breached'] = self._check_hibp_breach(password)
        analysis['strength_score'] = self._calculate_strength_score(analysis)
        analysis['recommendations'] = self._generate_recommendations(analysis)
        analysis['suggested_passwords'] = self._suggest_strong_passwords()
        return analysis

    def _evaluate_strength(self, password: str) -> Dict:
        metrics = {
            'length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in string.punctuation for c in password),
            'repeated_chars': self._check_repeated_chars(password),
            'sequential_chars': self._check_sequences(password),
            'keyboard_pattern': self._check_keyboard_patterns(password),
            'character_transitions': self._analyze_char_transitions(password)
        }
        return metrics

    def _detect_weaknesses(self, password: str, username: str) -> list:
        weaknesses = []
        pwd_lower = password.lower()
        if pwd_lower in self.common_passwords:
            weaknesses.append("Password is in common password list")
        if self._check_keyboard_patterns(password):
            weaknesses.append("Contains keyboard pattern sequences")
        if username and username.lower() in pwd_lower:
            weaknesses.append("Password contains username")
        if self._has_dictionary_patterns(password):
            weaknesses.append("Contains predictable dictionary patterns")
        if self._check_date_patterns(password):
            weaknesses.append("Contains date-like patterns")
        return weaknesses

    def _check_keyboard_patterns(self, password: str) -> bool:
        pwd_lower = password.lower()
        return any(pattern in pwd_lower for pattern in self.keyboard_patterns)

    def _check_date_patterns(self, password: str) -> bool:
        date_patterns = [r'\d{4}', r'\d{2}[/-]\d{2}', r'\d{2}[/-]\d{2}[/-]\d{2,4}']
        return any(re.search(pattern, password) for pattern in date_patterns)

    def _analyze_char_transitions(self, password: str) -> float:
        if len(password) < 2:
            return 1.0
        transitions = 0
        for i in range(len(password) - 1):
            if password[i].isalpha() and password[i+1].isalpha():
                if password[i].isupper() != password[i+1].isupper():
                    transitions += 1
            elif password[i].isdigit() != password[i+1].isdigit():
                transitions += 1
            elif (password[i] in string.punctuation) != (password[i+1] in string.punctuation):
                transitions += 1
        return transitions / (len(password) - 1)

    def _calculate_entropy(self, password: str) -> float:
        """Provides a theoretical measure of password randomness"""
        char_pool = 0
        for char_set in self.char_sets.values():
            if any(c in char_set for c in password):
                char_pool += len(char_set)
        return len(password) * math.log2(char_pool) if char_pool else 0.0

    def _check_repeated_chars(self, password: str) -> bool:
        return any(password.count(c) >= 4 for c in set(password))

    def _check_sequences(self, password: str) -> bool:
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and
                ord(password[i+2]) == ord(password[i+1]) + 1):
                return True
        return False

    def _has_dictionary_patterns(self, password: str) -> bool:
        common_subs = {
            '@': 'a', '0': 'o', '1': 'l', '!': 'i', '3': 'e',
            '$': 's', '7': 't', '4': 'a', '9': 'g', '8': 'b'
        }
        normalized = password.lower()
        for sub, char in common_subs.items():
            normalized = normalized.replace(sub, char)
        common_words = {'password', 'admin', 'user', 'login', 'secret', 
                       'account', 'love', 'work', 'home', 'family'}
        return any(word in normalized for word in common_words)

    def _calculate_strength_score(self, analysis: Dict) -> int:
        """Combines multiple factors including length, complexity, and patterns"""
        score = min(analysis['metrics']['length'] * 4, 40)
        metrics = analysis['metrics']
        if metrics['has_uppercase']: score += 10
        if metrics['has_lowercase']: score += 10
        if metrics['has_digits']: score += 10
        if metrics['has_special']: score += 10
        score += int(metrics['character_transitions'] * 10)
        if metrics['repeated_chars']: score -= 15
        if metrics['sequential_chars']: score -= 15
        if metrics['keyboard_pattern']: score -= 20
        if analysis['weaknesses']: score -= 20
        if metrics['breached']: score -= 30
        return max(0, min(100, score))

    def _generate_recommendations(self, analysis: Dict) -> list:
        recs = []
        metrics = analysis['metrics']
        if analysis['strength_score'] < 60:
            recs.append("Use a stronger password with more complexity")
        if metrics['length'] < 12:
            recs.append("Increase password length to at least 12 characters")
        if not all([metrics['has_uppercase'], metrics['has_lowercase'],
                   metrics['has_digits'], metrics['has_special']]):
            recs.append("Mix uppercase, lowercase, numbers, and special characters")
        if metrics['breached']:
            recs.append("This password was found in a breach - change it immediately")
        if metrics['keyboard_pattern']:
            recs.append("Avoid keyboard patterns (e.g., qwerty, asdf)")
        recs.append("Consider using a unique passphrase (e.g., 'CorrectHorseBatteryStaple')")
        return recs

    def generate_secure_password(self, length: int = 16) -> str:
        alphabet = (string.ascii_letters + string.digits + string.punctuation)
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def _suggest_strong_passwords(self) -> list:
        suggestions = []
        suggestions.append(self.generate_secure_password(16))
        words = ['correct', 'horse', 'battery', 'staple', 'blue', 'mountain',
                'thunder', 'river', 'silver', 'cloud']
        passphrase = ''.join(secrets.choice(words).capitalize() for _ in range(4)) + \
                    str(secrets.randbelow(100))
        suggestions.append(passphrase)
        complex_pwd = (secrets.choice(string.ascii_uppercase) +
                      secrets.choice(string.ascii_lowercase * 5) +
                      secrets.choice(string.digits * 3) +
                      secrets.choice(string.punctuation * 2) +
                      ''.join(secrets.choice(string.printable) for _ in range(10)))
        suggestions.append(complex_pwd)
        return suggestions

def start_passfort():
    print(f"{BLUE}+-----------------------------------------------------------------------+{RESET}")
    print(f"{LARGE}{BLUE}██████╗  █████╗ ███████╗███████╗███████╗ ██████╗ ██████╗ ███████╗ |{RESET}")
    print(f"{LARGE}{BLUE}██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ |{RESET}")
    print(f"{LARGE}{BLUE}██████╔╝███████║███████╗█████╗  █████╗  ██║   ██║██████╔╝█████╗   |{RESET}")
    print(f"{LARGE}{BLUE}██╔═══╝ ██╔══██║╚════██║██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██╔══╝   |{RESET}")
    print(f"{LARGE}{BLUE}██║     ██║  ██║███████║███████╗███████╗╚██████╔╝██║  ██║███████╗ |{RESET}")
    print(f"{LARGE}{BLUE}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ |{RESET}")
    print(f"{BLUE}+-----------------------------------------------------------------------+{RESET}")
    print(f"{YELLOW}|               Developed by: NEBHAN_MOHY for xAI Research             |{RESET}")
    print(f"{YELLOW}|               Password Security | Analysis | Protection              |{RESET}")
    print(f"{BLUE}+------------------------------------------------------------------------+{RESET}")

def main():
    start_passfort()
    analyzer = PasswordAnalyzer()
    password = input(f"{CYAN}Enter password to analyze: {RESET}")
    username = input(f"{CYAN}Enter username (optional): {RESET}")
    result = analyzer.analyze_password(password, username)
    
    print(f"\n{GREEN}Password Analysis:{RESET}")
    # Color strength score based on value
    score = result['strength_score']
    score_color = GREEN if score >= 80 else YELLOW if score >= 60 else RED
    print(f"{MAGENTA}Strength Score:{RESET} {score_color}{score}/100{RESET}")
    print(f"{MAGENTA}Entropy:{RESET} {CYAN}{result['entropy']:.2f} bits{RESET}")
    
    print(f"\n{MAGENTA}Metrics:{RESET}")
    for key, value in result['metrics'].items():
        value_color = GREEN if str(value).lower() in ('true', '1.0') else RED if str(value).lower() == 'false' else CYAN
        print(f"- {YELLOW}{key}:{RESET} {value_color}{value}{RESET}")
    
    if result['weaknesses']:
        print(f"\n{RED}Weaknesses:{RESET}")
        for w in result['weaknesses']:
            print(f"- {RED}{w}{RESET}")
    
    print(f"\n{GREEN}Recommendations:{RESET}")
    for r in result['recommendations']:
        print(f"- {YELLOW}{r}{RESET}")
    
    print(f"\n{MAGENTA}Suggested Strong Passwords:{RESET}")
    for i, suggestion in enumerate(result['suggested_passwords'], 1):
        print(f"{CYAN}{i}. {GREEN}{suggestion}{RESET}")

if __name__ == "__main__":
    main()
