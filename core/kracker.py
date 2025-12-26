from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Event, Queue
import time
from pathlib import Path
from tqdm import tqdm
from core.hash_handler import crack_chunk, init_worker, crack_range, init_worker_range
from core.brut_gen import get_brute_count
from core.mask_gen import get_mask_count, compile_mask_alphabets, get_mask_space_size
from core.rules_gen import load_rules, get_rule_count
from utils.detector import Detector
from utils.file_io import (
    validate_password_file,
    load_target_hash,
    count_wordlist_entries,
)
from utils.logger import PURPLE, GREEN, LIGHT_YELLOW, RESET

# import pdb


class Kracker:
    def __init__(self, args):
        self.operation = args.operation # dict, brut, mask, rule
        self.target_file = Path ("data") / args.target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file) # List of hashes to crack
        self.path_to_passwords = Path("refs") / args.password_list if args.password_list else None
        self.rules_file = args.rules_file or args.rules
        self.rule_wordlist = args.password_list or args.wordlist1
        self.mask_pattern = args.pattern # Mask-based attack
        self.custom_strings = args.custom if args.custom else None # Mask-based custom string to append
        self.brute_settings = dict(charset=args.charset if args.charset else None, min=args.min, max=args.max)
        self.max_expansions_per_word = args.max_expansions_per_word
        self.max_candidates = args.max_candidates
        self.workers = args.workers
        self.batch_size = args.batch_size
        self.workers_defaulted = False
        self.batch_size_defaulted = False
        self.rules = []
        self.base_words_processed = 0
        self.expanded_candidates = 0

        # Detect and initialize hash handler
        self.hash_type = Detector.detect(self.hash_digest_with_metadata)
        self._set_defaults()
        self.hash_handler = Detector.initialize(self.hash_digest_with_metadata, self.hash_type)
        self.preload_limit = self._get_preload_limit()

        self.start_time = time.perf_counter()
        self.goal = len(self.hash_digest_with_metadata) # Number of hashes in file to crack
        self.found_flag = {"found": 0, "goal": self.goal, "matches": {}}  # Track progress in main process
        self.stop_event = Event()

        if self.operation == "rule":
            rules_path = self._resolve_rules_path(self.rules_file)
            if not self.rule_wordlist:
                raise ValueError("Rule mode requires a wordlist (password_list or --wordlist1).")
            wordlist_path = self._resolve_wordlist_path(self.rule_wordlist)
            if not rules_path:
                raise ValueError("Rule mode requires a rules file (rules_file or --rules).")
            if not wordlist_path:
                raise ValueError(f"Rule wordlist not found: {self.rule_wordlist}")
            if self.max_expansions_per_word is not None and self.max_expansions_per_word <= 0:
                raise ValueError("--max-expansions-per-word must be a positive integer.")
            if self.max_candidates is not None and self.max_candidates <= 0:
                raise ValueError("--max-candidates must be a positive integer.")
            self.rules_file = rules_path
            self.path_to_passwords = wordlist_path
            if not self._wordlist_has_entries(self.path_to_passwords):
                raise ValueError("Rule wordlist is empty.")
            self.rules = load_rules(rules_path)
            if not self.rules:
                raise ValueError("Rule mode requires at least one rule.")

    @staticmethod
    def _resolve_wordlist_path(wordlist_name):
        if not wordlist_name:
            return None
        candidate = Path(wordlist_name)
        if candidate.exists():
            return candidate
        candidate = Path("refs") / wordlist_name
        if candidate.exists():
            return candidate
        return None

    @staticmethod
    def _resolve_rules_path(rules_name):
        if not rules_name:
            return None
        candidate = Path(rules_name)
        if candidate.exists():
            return candidate
        candidate = Path("refs") / rules_name
        if candidate.exists():
            return candidate
        candidate = Path("core") / rules_name
        if candidate.exists():
            return candidate
        return None

    def _get_preload_limit(self):
        return self.workers * 2

    def _set_defaults(self):
        cpu_count = Detector.get_cpu_count()
        expensive_hashes = {"bcrypt", "argon", "scrypt", "pbkdf2"}
        if self.workers is not None and self.workers <= 0:
            raise ValueError("--workers must be a positive integer.")
        if self.batch_size is not None and self.batch_size <= 0:
            raise ValueError("--batch-size must be a positive integer.")
        if self.workers is None:
            cap = 4 if self.hash_type in expensive_hashes else 6
            self.workers = min(cpu_count, cap)
            self.workers_defaulted = True
        if self.batch_size is None:
            if self.hash_type in expensive_hashes:
                self.batch_size = 1000
            else:
                self.batch_size = 20000
            self.batch_size_defaulted = True

    @staticmethod
    def _wordlist_has_entries(wordlist_path):
        with Path(wordlist_path).open("r", encoding="latin-1", errors="replace") as file:
            return any(line.strip() for line in file)


class BatchManager:
    def __init__(self, kracker):
        self.kracker = kracker
        self.batch_generator = None
        self.total_passwords = 0
        self.batch_queue = Queue(maxsize=kracker.preload_limit)  # Queue with a limit based on preload limit
        self.max_batches = 0
        self.rem_batches = 0


    def initialize_batch_generator(self):
        if self.kracker.operation == "dict":
            invalid_lines = validate_password_file(self.kracker.path_to_passwords)
            if invalid_lines:
                print(f"Invalid lines detected: {invalid_lines}")
            total_words = count_wordlist_entries(self.kracker.path_to_passwords)
            self.batch_generator = self._range_generator(total_words, self.kracker.batch_size)
            self.total_passwords = total_words

        elif self.kracker.operation == "brut":
            total_space = get_brute_count(self.kracker.brute_settings)
            self.batch_generator = self._range_generator(total_space, self.kracker.batch_size)
            self.total_passwords = total_space

        elif self.kracker.operation == "mask":
            alphabets = compile_mask_alphabets(self.kracker.mask_pattern, self.kracker.custom_strings)
            total_space = get_mask_space_size(alphabets)
            self.batch_generator = self._range_generator(total_space, self.kracker.batch_size)
            self.total_passwords = total_space

        elif self.kracker.operation == "rule":
            if not self.kracker.path_to_passwords or not self.kracker.rules:
                raise ValueError("Rule mode requires a wordlist and at least one rule.")
            total_words = count_wordlist_entries(self.kracker.path_to_passwords)
            expansions_per_word = len(self.kracker.rules)
            if self.kracker.max_expansions_per_word is not None:
                expansions_per_word = min(expansions_per_word, self.kracker.max_expansions_per_word)
            if expansions_per_word <= 0:
                total_words = 0
            if self.kracker.max_candidates is not None and expansions_per_word > 0:
                max_base_words = (self.kracker.max_candidates + expansions_per_word - 1) // expansions_per_word
                total_words = min(total_words, max_base_words)
            self.batch_generator = self._range_generator(total_words, self.kracker.batch_size)
            self.total_passwords = get_rule_count(
                self.kracker.path_to_passwords,
                self.kracker.rules,
                max_expansions_per_word=self.kracker.max_expansions_per_word,
                max_candidates=self.kracker.max_candidates,
            )

        self.max_batches = -(-self.total_passwords // self.kracker.batch_size)
        self.rem_batches = self.max_batches

    def _range_generator(self, total_items, batch_size):
        start = 0
        while start < total_items:
            end = min(start + batch_size, total_items)
            yield (start, end)
            start = end


    def preload_batches(self):
        """
        Preload batches into a multiprocessing.Queue until the queue is full
        or the generator is exhausted.
        """
        try:
            while not self.batch_queue.full():
                if self.kracker.stop_event.is_set():
                    return
                batch = next(self.batch_generator)
                self.batch_queue.put(batch)
                self.rem_batches -= 1
        except StopIteration:
            tqdm.write(f"{LIGHT_YELLOW}No more batches to preload.{RESET}")

    def get_batch(self):
        """
        Retrieve a batch from the multiprocessing.Queue.
        """
        try:
            return self.batch_queue.get_nowait()
        except Exception:
            print("No batch available in the queue.")
            return None


class Workers:
    def __init__(self, kracker, batch_man, reporter):
        self.kracker = kracker
        self.batch_man = batch_man
        self.reporter = reporter  # Reporter instance for logging


    def run(self):
        """Main loop to process password batches and handle matches."""
        print(self.reporter)  # Calls the __str__ method to print the configuration
        try:
            self.batch_man.initialize_batch_generator()
        except (NotImplementedError, ValueError) as exc:
            print(f"{LIGHT_YELLOW}{exc}{RESET}")
            return

        use_ranges = self.kracker.operation in {"dict", "rule", "brut", "mask"}
        if use_ranges:
            executor = ProcessPoolExecutor(
                max_workers=self.kracker.workers,
                initializer=init_worker_range,
                initargs=(
                    self.kracker.hash_type,
                    self.kracker.hash_digest_with_metadata,
                    self.kracker.stop_event,
                    self.kracker.operation,
                    self.kracker.path_to_passwords,
                    self.kracker.rules_file,
                    self.kracker.max_expansions_per_word,
                    self.kracker.max_candidates,
                    self.kracker.brute_settings,
                    self.kracker.mask_pattern,
                    self.kracker.custom_strings,
                    1024,
                    False,
                    "mmap",
                ),
            )
            task_fn = crack_range
        else:
            executor = ProcessPoolExecutor(
                max_workers=self.kracker.workers,
                initializer=init_worker,
                initargs=(self.kracker.hash_type, self.kracker.hash_digest_with_metadata, self.kracker.stop_event),
            )
            task_fn = crack_chunk
        try:
            print(f"{LIGHT_YELLOW}Starting batch preloading... {RESET}")
            self.batch_man.preload_batches()

            futures = []  # Queue to hold active Future objects

            # Initialize tqdm with total number of batches
            with tqdm(
                desc=f"{PURPLE}Batch Processing{RESET}",
                total=self.batch_man.max_batches,
                mininterval=0.1,
                smoothing=0.1,
                ncols=100,
                leave=True,
                ascii=True,
            ) as progress_bar:
                # Main processing loop
                while futures or self.batch_man.rem_batches > 0 or not self.batch_man.batch_queue.empty():
                    # Submit tasks until the preload limit is reached
                    while len(futures) < self.kracker.preload_limit and not self.batch_man.batch_queue.empty():
                        batch = self.batch_man.get_batch()
                        if batch is None:
                            break
                        if self.kracker.stop_event.is_set():
                            break
                        future = executor.submit(task_fn, batch)
                        futures.append(future)

                    # Process completed futures
                    for future in as_completed(futures):
                        try:
                            self.process_task_result(future)
                            progress_bar.update(1)  # Update the progress bar

                            # Stop if all target hashes are matched
                            if self.kracker.found_flag["found"] == self.kracker.found_flag["goal"]:
                                self.kracker.stop_event.set()
                                for pending in futures:
                                    if not pending.done():
                                        pending.cancel()
                                self.reporter.final_summary()
                                return  # Exit immediately

                        except Exception as e:
                            print(f"Error processing future: {e}")
                        finally:
                            futures.remove(future)
                    # Dynamically preload more batches if needed
                    if self.batch_man.rem_batches > 0 and self.batch_man.batch_queue.empty():
                        self.batch_man.preload_batches()

            self.reporter.final_summary()

        except KeyboardInterrupt:
            self.kracker.stop_event.set()
            self.kracker.found_flag["found"] = -1
            print(f"{LIGHT_YELLOW}Process interrupted.{RESET}")
        finally:
            executor.shutdown(cancel_futures=True)
            print(f"{PURPLE}Program terminated.{RESET}")

    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            results, meta = task_result.result()  # Expecting a tuple
            if isinstance(meta, dict):
                verified_count = meta.get("verified_count", 0)
                self.reporter.summary_log["total_count"] += verified_count
                self.kracker.base_words_processed += meta.get("base_words_processed", 0)
                self.kracker.expanded_candidates += meta.get("expanded_generated", 0)
            else:
                self.reporter.summary_log["total_count"] += meta

            # Process all matches in the results list
            for target_hash, pwned_pwd in results.items():
                matches = self.kracker.found_flag["matches"]
                if target_hash not in matches:
                    matches[target_hash] = pwned_pwd
                    self.kracker.found_flag["matches"] = matches
                    tqdm.write(f"{GREEN}[MATCH!] --> {pwned_pwd} --> {target_hash}{RESET}")
                    self.kracker.found_flag["found"] += 1

            return True, meta
        
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count
