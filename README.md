# hashtable
Generate precomputed hash tables from large wordlists. Precompute `hash:password` pairs for fast reverse searches. Designed for security research and password analysis.

## ⚠️ DISCLAIMER  

**This tool is intended for:**
- Educational purposes 
- Legitimate security research  
- Auditing **your own** systems/passwords

**By using this software, you agree:**  
1. **Never** to use it on systems/data without **explicit ownership or permission**  
2. Password hashtables may contain sensitive information – **do not share** generated files  
3. **You are solely responsible** for complying with laws (e.g., GDPR, CFAA) in your jurisdiction  
4. Modern secure systems use "salted hashes" – this tool **will not work** against properly secured passwords  

**Illegal uses include (but are not limited to):**
- Bypassing authentication mechanisms 
- Distributing password lists without consent
- Accessing accounts/systems you don’t own  

The developer assumes **no liability** for misuse. Security tools can be weapons – use responsibly. 

## What Does This Do?
Converts a wordlist (list of passwords) into a file of `[hash]:[password]` pairs. For example:  
**Input File ([`500-worst-passwords.txt`](https://github.com/ibnaleem/hashtable/blob/main/examples/500-worst-passwords.txt))**:
```
12345
dragon
qwerty
696969
mustang
letmein
```
**Output File ([`500-worst-passwords-sha1-hashtable.txt`](https://github.com/ibnaleem/hashtable/blob/main/examples/500-worst-passwords-sha1-hashtable.txt))**:
```
5c6d9edc3a951cda763f650235cfc41a3fc23fe8:batman
e68e11be8b70e435c65aef8ba9798ff7775c361e:trustno1
5f50a84c1fa3bcff146405017f36aec1a10a9e38:thomas
6c616f7c2d2fde9018a09f06eaefcfc7582bc7ba:tigger
12e9293ec6b30c7fa8a0926af42807e929c1684f:robert
3674951ec264a72168cb2d89a5f634e512f6629d:enter
782f9b10621e362d5bd0def3a279b5e0908c9ebb:ashley
badcfa3c62742b3bcc1dcd893e78713bd36aa430:thunder
248510136410798c784ba702df249756ad286be4:cowboy
f8248e12727710c946f73d8f6e02eb93530dd9de:silver
```

## Why Use This?  
### 1. **Instant Password Lookups**  
   - Services like [CrackStation](https://crackstation.net/) and [Weakpass](https://weakpass.com) use giant hashtables to **instantly** find passwords for stolen hashes.  
   - Without a hashtable, cracking takes hours/days. With it, common passwords are found **in seconds**.

### 2. **Save Time**  
   - Hashing is slow. This tool does the work upfront so lookups take **zero time** later.

## How to Use  
```bash
$ git clone https://github.com/ibnaleem/hashtable.git # Linux
$ cd hashtable
$ python3 hashtable -h
usage: Hashtable Generator [-h] -w WORDLIST -m HASHTYPE

Generate precomputed hashtables (hash:pass) from a wordlist

options:
  -h, --help            show this help message and exit
  -w, --wordlist WORDLIST
                        The wordlist to create a hashtable of
  -m, --hashtype HASHTYPE
                        the hashtype to use for the hashtable

🤝 Contribute: https://github.com/ibnaleem/hashtable
```
Supported Hashes: `md5`, `sha1`, `sha256`, `sha512`. If you would like more hashing algorithms, please open a PR.
## How Websites Use This
Weakpass.com, CrackStation, etc., use multi-billion-entry hashtables. They use a tool like this to generate them.
You give them a hash → they check their precomputed list → instantly return the password if it exists.
## Contributing
I trust you understand how to contribute to a project on GitHub.
## LICENSE
This project is under the GPLv3 License.
