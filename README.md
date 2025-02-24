# passfort.py
PassFort: A Python-based password analyzer by NEBHAN_MOHY for xAI Research. Evaluates strength, detects weaknesses, and checks breaches via HIBP API. Offers colored output, entropy scoring, and strong password suggestions. Install with pip3: requests, ratelimit, colorama. Run python3 passfort.py for secure password analysis.

- Analyzes password complexity, length, and randomness (entropy).
- Identifies weaknesses like common patterns, breached passwords, and personal data inclusion.
- Integrates with the Have I Been Pwned API (using SHA-1 and k-anonymity) for breach detection.
- Offers color-coded feedback and generates strong password alternatives.

  source venv/bin/activate  # On Linux/macOS
  venv\Scripts\activate     # On Windows

  pip3 install requests ratelimit colorama
  pip3 list | grep -E "requests|ratelimit|colorama
  python3 passfort.py

  ![Screenshot 2025-02-24 091724](https://github.com/user-attachments/assets/77898414-67a6-4a48-9991-2f481be59174)
