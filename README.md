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
**Output File ([`500-worst-passwords_sha1.txt`](https://github.com/ibnaleem/hashtable/blob/main/examples/500-worst-passwords_sha1.txt))**:
```
2672275fe0c456fb671e4f417fb2f9892c7573ba:12345
8851def7166796964bf58174a5f3f50d073d709d:dragon
3c8b9f4b983afa9f644d26e2b34fa3e03a2bef16:qwerty
95b679919194b7b37b298b9368f3b89a93e3cde4:696969
059a9d50d1155bb31ad65df3e0cfb20c8f98894b:mustang
34ca062314edaa193e03f318ae20ae134274b358:letmein
```

## Why Use This?  
### 1. **Instant Password Lookups**  
   - Services like [CrackStation](https://crackstation.net/) and [Weakpass](https://weakpass.com) use giant hashtables to **instantly** find passwords for stolen hashes.  
   - Without a hashtable, cracking takes hours/days. With it, common passwords are found **in seconds**.

### 2. **Save Time**  
   - Hashing is slow. This tool does the work upfront so lookups take **zero time** later.

## How to Use  
**Install Dependencies** (OpenSSL):  
```bash
$ brew install openssl  # macOS
$ sudo apt install libssl-dev  # Linux
```
**Clone & Compile**
```bash
$ git clone https://github.com/ibnaleem/hashtable.git
$ cd hashtable
$ gcc -o hashtable hashtable.c -I/path/to/openssl/include -L/path/to/openssl/lib -lcrypto
$ ./hashtable <input_file> <hash_type>
# Example:
$ ./hashtable passwords.txt sha512 
```
Supported Hashes: `md5`, `sha1`, `sha256`, `sha512`. If you would like more hashing algorithms, please open a PR.
## How Websites Use This
Weakpass.com, CrackStation, etc., use multi-billion-entry hashtables. They use a tool like this to generate them.
You give them a hash → they check their precomputed list → instantly return the password if it exists.
## Contributing
I trust you understand how to contribute to a project on GitHub.
## LICENSE
This project is under the GPLv3 License.
