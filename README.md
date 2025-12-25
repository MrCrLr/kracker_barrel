
# **Kracker Barrel: Multiprocessing Password Cracker**

Kracker Barrel is a high-performance password-recovery tool built for speed, flexibility, and ease of use. It leverages multiprocessing, automatic parameter detection, and robust logging to handle various cryptographic hash types efficiently. Whether you’re a security researcher or conducting password recovery, **Kracker Barrel** gets the job done.

---

## **Table of Contents**
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Advanced Options](#advanced-options)
- [Configuration File](#configuration-file)
- [Hash Maker Tool](#hash-maker-tool)
- [License](#license)

---

## **Features**
- **Auto-Detection**: Automatically identifies the parameters from input hashes.
- **Parallel Processing**: Uses Python’s `ProcessPoolExecutor` for concurrent, scalable CPU processing.
- **Dynamic Wordlist Handling**: Processes large wordlists in manageable batches for optimal memory usage by using a generator to yield and queue batches of potential password matches.
- **Robust Logging**: Tracks everything, from attempted passwords to batch processing times.
- **Configurable Batch Size**: Tailor batch sizes to fit system resources.
- **Wide Hash Support**: Handles Argon2, bcrypt, scrypt, PBKDF2, NTLM, MD5, SHA-256, and SHA-512.
- **Dictionary, Brute-Force and Mask-Based Operational Modes**: Generate new passwords efficiently and check your forgotten passwords against a multitude of combinaitons. More attack modes (Rules-based and hybrid-modes) coming soon. 
---

## **Installation**

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/kracker_barrel.git
   cd kracker_barrel
   ```

2. Install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## **Development Quick Check**

```bash
uv sync && uv run python tests/smoke_test.py
```

---

## **Usage**

To start cracking passwords, provide a file containing hashed passwords and specify the type of operation (`dict`, `mask`, `brut`).

### **Basic Command**
```bash
python main.py -d <hash_type> target_hashes.txt rockyou.txt
```

### **Arguments**
| Flag                | Description                                                                   |
|---------------------|-------------------------------------------------------------------------------|
| Dictionary Mode     |                                                                               |
| `-d` or `--dict`    | Path to the wordlist for dictionary attacks.                                  |
| `<hash_type>`       | E.g., `argon`, `bcrypt`, `pbkdf2`, `scrypt`, `ntlm`, `md5`, `sha256`, `sha512`|
| `target_hashes.txt` | Path to the file containing target hashes.                                    |
| `wordlist.txt`      | Path to the file containing the wordlist.                                     |
| Mask-Based Mode     |                                                                               |
| `-m` or `--mask`    | Operation type (`dict`, `mask`, or `brut`).                                   |
| `<hash_type>`       | E.g., `argon`, `bcrypt`, `pbkdf2`, `scrypt`, `ntlm`, `md5`, `sha256`, `sha512`|
| `target_hashes.txt` | Path to the file containing target hashes.                                    |
| `--pattern <?l?l?d>`| Mask pattern for mask-based attacks (e.g., `?l?l?d?d`).                       |
| Brute-Force Mode    |                                                                               |
| `-b` or `--brut`    | Operation type (`dict`, `mask`, or `brut`).                                   |
| `<hash_type>`       | E.g., `argon`, `bcrypt`, `pbkdf2`, `scrypt`, `ntlm`, `md5`, `sha256`, `sha512`|
| `target_hashes.txt` | Path to the file containing target hashes.                                    |
| `--charset <abc123>`| Character set for brute force (e.g., `AaBbCc123#?*`).                         |
| `--min <int>`       | Minimum length for brute-force candidates (e.g., `1`).                        |
| `--max <int>`       | Maximum length for brute-force candidates (e.g., `5`).                        |

---

## **Supported Hash Algorithms**

| Algorithm | Description                                      | Parameters Logged                          |
|-----------|-----------------------------------------------   |--------------------------------------------|
| **Argon2**| Memory-hard algorithm with configurable costs    | Time cost, memory cost, parallelism        |
| **Bcrypt**| Adjustable work factor, secure password hashing  | Rounds                                     |
| **Scrypt**| Memory-hard key derivation function              | Length, memory cost (n), block size (r), parallelism (p)|
| **PBKDF2**| Iterative key derivation function                | Algorithm, iterations, salt length         |
| **NTLM**  | Windows password hashing                         | Encoding (UTF-16LE), hash length           |
| **MD5**   | Basic hash (insecure for passwords)              | Encoding (UTF-8), hash length              |
| **SHA-256**| Cryptographic hash function                     | Encoding (UTF-8), hash length              |
| **SHA-512**| Cryptographic hash function                     | Encoding (UTF-8), hash length              |

---

## **Advanced Options**

### **Batch Size and Concurrency**
You can fine-tune the performance by adjusting:
- **Batch Size**: Controls the number of passwords processed per batch (`batch_size` in the code). Preloaded batches are stored in a queue. The generator yields batches to queeu a number of batches equal to number of CPU cores * 3 as a default. This eliminates processes ever needing to wait for work.
- **Concurrency**: Maximize CPU utilization by increasing the number of workers (`workers` variable in `kracker.py`). Default setting automatically detects machine's cores and sets workers equal.

### **Dynamic Hash Parameter Parsing**
Hash parameters such as time cost, memory cost, or rounds are auto-parsed directly from the hash input. Manual configuration is no longer necessary.

## **Configuration file**

Cracker Barrel now supports using a configuration file (`config.yaml`) to define the cracking mode and its parameters. This allows users to save multiple configurations and easily switch between setups. The command-line arguments parser defaults to the configuration file unless overriding arguments are provided at runtime.

### Advantages

- Simplifies workflow for commonly used setups.
- Allows for easy planning and recovery strategies.
- Facilitates the storage of multiple cracking configurations.

---
Config.yaml|||
--|--|--|
|||
DICTIONARY RECOVERY |||
**operation**: | `dict`
**hash_type**: | `argon`  |# Supported: argon, bcrypt, scrypt, pbkdf2, ntlm, md5, sha256, sha512
**target_file**: | `hashed_passwords.txt`  |# File containing hashed passwords (place in "data/")
**password_list**: | `rockyou.txt`      |# File with potential passwords (place in "refs/")
|||
BRUTE FORCE RECOVERY |||
**operation**: | `brut`
**hash_type**: | `sha256`  |# Supported: argon, bcrypt, scrypt, pbkdf2, ntlm, md5, sha256, sha512
**target_file**: | `hashed_passwords.txt`  |# File containing hashed passwords (place in "data/")
**charset**: | `abcdef12345`                 |# Charset for brute force (default: alphanumeric)
**min**: | `1`                               |# Minimum password length
m**ax**: | `4`                               |# Maximum password length
|||
MASK-BASED RECOVERY |||
**operation**: | `mask`
**hash_type**: | `bcrypt`  |# Supported: argon, bcrypt, scrypt, pbkdf2, ntlm, md5, sha256, sha512
**target_file**: | `hashed_passwords.txt`  |# File containing hashed passwords (place in "data/")
**pattern**: | `"?u?l?d"`                    |# Mask pattern (e.g., ?u = uppercase, ?l = lowercase, ?d = digit)

---

## **Hash Maker Tool**

The **Hash Maker** companion script helps generate test hashes for validating Kracker Barrel’s functionality.

### **Usage**
Generate hashes using `hashmaker.py`:
```bash
python hashmaker.py -o pbkdf2 <output_file>
```

#### **Available Algorithms**:
| Algorithm | Example Command                                                                |
|-----------|--------------------------------------------------------------------------------|
| Argon2, test mode, with output file  | `python hashmaker.py -o argon -t output_file.txt`   |
| Bcrypt, outputted to terminal only   | `python hashmaker.py -o bcrypt`                     |
| Usage: | `-o {argon,bcrypt,scrypt,pbkdf2,md5,ntlm,sha256,sha512} [-t] [output_file]`       |


---
## **Metadata file generator**
`<output_file.txt>` is optional. If provided hashes are saved with an additional metadata file documenting the parameters and the plaintext password. If no output file, hashes are outputted to terminal only.

---

## **Test Mode**
Enable the `--test_mode` or `-t` flag to create test hashes with reduced computational difficulty for faster cracking. These hashes do not meet industry security standards but are ideal for validation.

---

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
