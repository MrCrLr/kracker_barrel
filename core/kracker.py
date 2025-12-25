from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager, Queue
import time
from pathlib import Path
from tqdm import tqdm
from core.hash_handler import crack_chunk
from core.brut_gen import generate_brute_candidates, yield_brute_batches, get_brute_count
from core.mask_gen import generate_mask_candidates, yield_maskbased_batches, get_mask_count
from core.rules_gen import load_rules, generate_rule_candidates, yield_rule_batches, get_rule_count
from utils.detector import Detector
from utils.file_io import get_number_of_passwords, yield_dictionary_batches, validate_password_file, load_target_hash
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
        self.workers = max(1, Detector.get_cpu_count() - 1)
        self.preload_limit = self.workers * 6
        self.batch_size = 2000  # Adjust batch size for performance
        self.rules = []

        # Detect and initialize hash handler
        self.hash_type = Detector.detect(self.hash_digest_with_metadata)
        self.hash_handler = Detector.initialize(self.hash_digest_with_metadata, self.hash_type)

        self.manager = Manager()
        self.start_time = time.perf_counter()
        self.goal = len(self.hash_digest_with_metadata) # Number of hashes in file to crack
        self.found_flag = self.manager.dict(found=0, goal=self.goal, matches={})  # Global found_flag for stopping on goal match

        if self.operation == "rule":
            rules_path = self._resolve_rules_path(self.rules_file)
            if not self.rule_wordlist:
                raise ValueError("Rule mode requires a wordlist (password_list or --wordlist1).")
            wordlist_path = self._resolve_wordlist_path(self.rule_wordlist)
            if not rules_path:
                raise ValueError("Rule mode requires a rules file (rules_file or --rules).")
            if not wordlist_path:
                raise ValueError(f"Rule wordlist not found: {self.rule_wordlist}")
            self.rules_file = rules_path
            self.path_to_passwords = wordlist_path
            self.rules = load_rules(rules_path)

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
            self.batch_generator = yield_dictionary_batches(self.kracker.path_to_passwords, self.kracker.batch_size)
            self.total_passwords = get_number_of_passwords(self.kracker.path_to_passwords)

        elif self.kracker.operation == "brut":
            generator = generate_brute_candidates(self.kracker.brute_settings)
            self.batch_generator = yield_brute_batches(generator, self.kracker.batch_size)
            self.total_passwords = get_brute_count(self.kracker.brute_settings)

        elif self.kracker.operation == "mask":
            generator = generate_mask_candidates(self.kracker.mask_pattern, self.kracker.custom_strings)
            self.batch_generator = yield_maskbased_batches(generator, self.kracker.batch_size)
            self.total_passwords = get_mask_count(self.kracker.mask_pattern, self.kracker.custom_strings)

        elif self.kracker.operation == "rule":
            if not self.kracker.path_to_passwords or not self.kracker.rules:
                raise ValueError("Rule mode requires a wordlist and at least one rule.")
            generator = generate_rule_candidates(self.kracker.path_to_passwords, self.kracker.rules)
            self.batch_generator = yield_rule_batches(generator, self.kracker.batch_size)
            self.total_passwords = get_rule_count(self.kracker.path_to_passwords, self.kracker.rules)

        self.max_batches = -(-self.total_passwords // self.kracker.batch_size)
        self.rem_batches = self.max_batches


    def preload_batches(self):
        """
        Preload batches into a multiprocessing.Queue until the queue is full
        or the generator is exhausted.
        """
        try:
            while not self.batch_queue.full():
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

        try:
            with ProcessPoolExecutor(max_workers=self.kracker.workers) as executor:
                print(f"{LIGHT_YELLOW}Starting batch preloading... {RESET}")
                self.batch_man.preload_batches()

                futures = []  # Queue to hold active Future objects

                # Initialize tqdm with total number of batches
                with tqdm(desc=f"{PURPLE}Batch Processing{RESET}", 
                          total=self.batch_man.max_batches, 
                          mininterval=0.1, smoothing=0.1, 
                          ncols=100, leave=True, ascii=True) as progress_bar:
                    

                    # Main processing loop
                    while futures or self.batch_man.rem_batches > 0 or not self.batch_man.batch_queue.empty():
                        # Submit tasks until the preload limit is reached
                        while len(futures) < self.kracker.preload_limit and not self.batch_man.batch_queue.empty():
                            batch = self.batch_man.get_batch()
                            if batch is None:
                                break
                            future = executor.submit(
                                crack_chunk,
                                self.kracker.hash_type,
                                self.kracker.hash_digest_with_metadata,
                                batch,
                                self.kracker.found_flag,
                            )
                            futures.append(future)

                        # Process completed futures
                        for future in as_completed(futures):
                            try:
                                self.process_task_result(future)
                                progress_bar.update(1)  # Update the progress bar
                                
                                # Stop if all target hashes are matched
                                if self.kracker.found_flag["found"] == self.kracker.found_flag["goal"]:
                                    progress_bar.close()
                                    self.reporter.final_summary()
                                    return  # Exit immediately

                            except Exception as e:
                                print(f"Error processing future: {e}")
                            finally:
                                futures.remove(future)
                        # Dynamically preload more batches if needed
                        if self.batch_man.rem_batches > 0 and self.batch_man.batch_queue.empty():
                            self.batch_man.preload_batches()

                progress_bar.close()
            self.reporter.final_summary()

        except KeyboardInterrupt:
            self.kracker.found_flag["found"] = -1
            print(f"{LIGHT_YELLOW}Process interrupted.{RESET}")
        finally:
            print(f"{PURPLE}Program terminated.{RESET}")
            executor.shutdown

    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            results, chunk_count = task_result.result()  # Expecting a tuple
            self.reporter.summary_log["total_count"] += chunk_count

            # Process all matches in the results list
            for target_hash, pwned_pwd in results.items():
                matches = self.kracker.found_flag["matches"]
                if target_hash not in matches:
                    matches[target_hash] = pwned_pwd
                    self.kracker.found_flag["matches"] = matches
                    tqdm.write(f"{GREEN}[MATCH!] --> {pwned_pwd} --> {target_hash}{RESET}")
                    self.kracker.found_flag["found"] += 1

            return True, chunk_count
        
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count
