import os
import hashlib
import threading
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor

def process_password(password: str, hashtype: str, output_file: str, lock: threading.Lock) -> None:

    match hashtype:
        case "md5":
            m = hashlib.md5()
        case "sha1":
            m = hashlib.sha1()
        case "sha256":
            m = hashlib.sha256()
        case "sha512":
            m = hashlib.sha512()
        case _:
            return

    m.update(password.encode('utf-8'))
    hash_line = f"{m.hexdigest()}:{password}\n"
    
    with lock:
        with open(output_file, 'a') as f:
            f.write(hash_line)

def write_hashtable(wordlist: str, hashtype: str) -> None:
    base_name = wordlist.rsplit('.txt', 1)[0]
    output_file = f"{base_name}-{hashtype}-hashtable.txt"
    
    
    lock = threading.Lock()
    
    with open(wordlist, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:

        futures = [
            executor.submit(
                process_password,
                password,
                hashtype,
                output_file,
                lock
            )
            for password in passwords
        ]
        
        for future in futures:
            future.result()

    print(f"[✅] Successfully created {len(passwords)} entries in {output_file}")
    print(f"[🏁] Total processed: {len(passwords)} passwords")

def main():
    parser = ArgumentParser(prog="Hashtable Generator",
        description="Generate precomputed hashtables (hash:pass) from a wordlist",
        epilog="🤝 Contribute: https://github.com/ibnaleem/hashtable")
    parser.add_argument("-w", "--wordlist", help="The wordlist to create a hashtable of", required=True)
    parser.add_argument("-m", "--hashtype", help="the hashtype to use for the hashtable", required=True)
    args = parser.parse_args()

    print(f"[*] Initialising with {os.cpu_count()} CPU cores")
    print(f"[*] Processing {args.wordlist} with {args.hashtype.upper()}")
    write_hashtable(args.wordlist, args.hashtype)

if __name__ == "__main__":
    main()