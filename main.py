from getpass import getpass
import re
import math
import hashlib
import requests


HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"
COLOR_OK = '\033[92m'
COLOR_WARN = '\033[93m'
COLOR_FAIL = '\033[91m'
COLOR_END = '\033[0m'


def get_password_complexity(password):
    spec_char_patt = "[^0-9a-zA-Z]"
    return {
        "has_lower": re.search("[a-z]", password) is not None,  # 26
        "has_upper": re.search("[A-Z]", password) is not None,  # 26
        "has_numeral": re.search("[0-9]", password) is not None,  # 10
        "has_spec_char": re.search(spec_char_patt, password) is not None,  # 33
    }


def get_password_entropy(pass_length, pass_complexity):
    r = 26 if pass_complexity["has_lower"] else 0
    r = r + 26 if pass_complexity["has_upper"] else r
    r = r + 10 if pass_complexity["has_numeral"] else r
    r = r + 32 if pass_complexity["has_spec_char"] else r  # if US keyboard
    return math.log2(r ** pass_length)


# does not require hibp api key since this part is free service
def password_has_been_pwned(password):
    sha1pw = hashlib.sha1(bytes(password, encoding='utf-8')).hexdigest()
    first_five_sha1 = sha1pw[0:5]
    # checks if prefix matches in db, returns 800+ suffixes that might match
    resp = requests.get(f"{HIBP_RANGE_URL}{first_five_sha1}").text
    possibles = [h.split(':')[0] for h in resp.split('\n')]
    # check our hash suffix against possibles
    return f"{sha1pw.upper()[5:]}" in possibles


pw = getpass("\nInput your password: ")
pw_len = len(pw)
pw_comp = get_password_complexity(pw)
entropy = get_password_entropy(pw_len, pw_comp)
print("------------------------")
print(f"Password length: {pw_len}")
if entropy < 50:
    col = COLOR_FAIL
elif entropy >= 50 and entropy < 60:
    col = COLOR_WARN
else:
    col = COLOR_OK
print(f"Password entropy (>=60 is strong): {col}{entropy:2.3f}{COLOR_END}")
pwned = password_has_been_pwned(pw)
print(f"Has been pwned: {
      COLOR_FAIL if pwned else COLOR_OK}{pwned}{COLOR_END}")
print("------------------------")
print("Suggested improvements:\n")
if pwned:
    print(f"{COLOR_FAIL}Your password's hash has been discovered in a breach!{
          COLOR_END}")
    print(f"{COLOR_FAIL}- IF IN USE, CHANGE THIS PASSWORD IMMEDIATELY!{
          COLOR_END}\n")
if False in pw_comp.values():
    print("Use a password with:")
    if pw_comp["has_upper"] is False or pw_comp["has_lower"] is False:
        print("- a mixture of uppercase and lowercase letters")
    if pw_comp["has_numeral"] is False:
        print("- one or more numbers")
    if pw_comp["has_spec_char"] is False:
        print("- one or more special characters")
    print("- When making a password, use character replacement,"
          + " such as: Th1s_Exampl3\n")
if pw_len < 12:
    print("Use a password 12 characters or longer.")
    print("- Maybe use a passphrase, such as: This_length_is_better44")
    print("- Or use the first letter song in lyrics: Ycagwyw=St0nes\n")
if not pwned and entropy >= 60 and pw_len >= 12:
    print("This password should be good!")
