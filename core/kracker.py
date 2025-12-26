from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Event, Queue
import time
from tqdm import tqdm
from core.hash_handler import crack_chunk, init_worker, crack_range, init_worker_range
from core.brut_gen import get_brute_count
from core.mask_gen import get_mask_count, compile_mask_alphabets, get_mask_space_size
from core.rules_gen import get_rule_count
from utils.detector import Detector
from utils.file_io import (
    validate_password_file,
    load_target_hash,
    count_wordlist_entries,
)
from utils.config_prep import apply_defaults
from utils.logger import PURPLE, GREEN, LIGHT_YELLOW, RESET

# import pdb


class Kracker:
    def __init__(self, cfg):
        self.operation = cfg["operation"]  # dict, brut, mask, rule
        self.target_file = cfg["target_file"]
        self.hash_digest_with_metadata = load_target_hash(self.target_file)  # List of hashes to crack
        self.password_list_path = cfg.get("password_list_path")
        self.rules_file = cfg.get("rules_file")
        self.rule_wordlist = cfg.get("rule_wordlist")
        self.mask_pattern = cfg.get("mask_pattern")  # Mask-based attack
        self.custom_strings = cfg.get("custom_strings")  # Mask-based custom string to append
        self.brute_settings = cfg.get("brute_settings", {})
        self.max_expansions_per_word = cfg.get("max_expansions_per_word")
        self.max_candidates = cfg.get("max_candidates")
        self.rules = cfg.get("rules", [])
        self.base_words_processed = 0
        self.expanded_candidates = 0

        # Detect and initialize hash handler
        self.hash_type = Detector.detect(self.hash_digest_with_metadata)
        apply_defaults(cfg, self.hash_type)
        self.workers = cfg["workers"]
        self.batch_size = cfg["batch_size"]
        self.workers_defaulted = cfg["workers_defaulted"]
        self.batch_size_defaulted = cfg["batch_size_defaulted"]
        self.hash_handler = Detector.initialize(self.hash_digest_with_metadata, self.hash_type)
        self.preload_limit = self.workers * 2

        self.start_time = time.perf_counter()
        self.goal = len(self.hash_digest_with_metadata)  # Number of hashes in file to crack
        self.found_flag = {"found": 0, "goal": self.goal, "matches": {}}  # Track progress in main process
        self.stop_event = Event()


class BatchManager:
    def __init__(self, kracker):
        self.kracker = kracker
        self.batch_generator = None
        self.total_candidates = 0
        self.batch_queue = Queue(maxsize=kracker.preload_limit)  # Queue with a limit based on preload limit
        self.total_batches = 0
        self.remaining_batches = 0


    def initialize_batch_generator(self):
        if self.kracker.operation == "dict":
            invalid_lines = validate_password_file(self.kracker.password_list_path)
            if invalid_lines:
                print(f"Invalid lines detected: {invalid_lines}")
            total_words = count_wordlist_entries(self.kracker.password_list_path)
            self.batch_generator = self._range_generator(total_words, self.kracker.batch_size)
            self.total_candidates = total_words

        elif self.kracker.operation == "brut":
            total_space = get_brute_count(self.kracker.brute_settings)
            self.batch_generator = self._range_generator(total_space, self.kracker.batch_size)
            self.total_candidates = total_space

        elif self.kracker.operation == "mask":
            alphabets = compile_mask_alphabets(self.kracker.mask_pattern, self.kracker.custom_strings)
            total_space = get_mask_space_size(alphabets)
            self.batch_generator = self._range_generator(total_space, self.kracker.batch_size)
            self.total_candidates = total_space

        elif self.kracker.operation == "rule":
            if not self.kracker.password_list_path or not self.kracker.rules:
                raise ValueError("Rule mode requires a wordlist and at least one rule.")
            total_words = count_wordlist_entries(self.kracker.password_list_path)
            expansions_per_word = len(self.kracker.rules)
            if self.kracker.max_expansions_per_word is not None:
                expansions_per_word = min(expansions_per_word, self.kracker.max_expansions_per_word)
            if expansions_per_word <= 0:
                total_words = 0
            if self.kracker.max_candidates is not None and expansions_per_word > 0:
                max_base_words = (self.kracker.max_candidates + expansions_per_word - 1) // expansions_per_word
                total_words = min(total_words, max_base_words)
            self.batch_generator = self._range_generator(total_words, self.kracker.batch_size)
            self.total_candidates = get_rule_count(
                self.kracker.password_list_path,
                self.kracker.rules,
                max_expansions_per_word=self.kracker.max_expansions_per_word,
                max_candidates=self.kracker.max_candidates,
            )

        self.total_batches = -(-self.total_candidates // self.kracker.batch_size)
        self.remaining_batches = self.total_batches

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
                self.remaining_batches -= 1
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
    def __init__(self, kracker, batch_manager, reporter):
        self.kracker = kracker
        self.batch_manager = batch_manager
        self.reporter = reporter  # Reporter instance for logging


    def run(self):
        """Main loop to process password batches and handle matches."""
        print(self.reporter)  # Calls the __str__ method to print the configuration
        try:
            self.batch_manager.initialize_batch_generator()
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
                    self.kracker.password_list_path,
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
            self.batch_manager.preload_batches()

            futures = []  # Queue to hold active Future objects

            # Initialize tqdm with total number of batches
            with tqdm(
                desc=f"{PURPLE}Batch Processing{RESET}",
                total=self.batch_manager.total_batches,
                mininterval=0.1,
                smoothing=0.1,
                ncols=100,
                leave=True,
                ascii=True,
            ) as progress_bar:
                # Main processing loop
                while futures or self.batch_manager.remaining_batches > 0 or not self.batch_manager.batch_queue.empty():
                    # Submit tasks until the preload limit is reached
                    while len(futures) < self.kracker.preload_limit and not self.batch_manager.batch_queue.empty():
                        batch = self.batch_manager.get_batch()
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
                            elapsed = time.perf_counter() - self.kracker.start_time
                            verified = self.reporter.summary_log["total_count"]
                            rate = verified / elapsed if elapsed else 0
                            progress_bar.set_postfix_str(
                                f"verified={verified} rate={rate:,.0f}/s matches={self.kracker.found_flag['found']}"
                            )

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
                    if self.batch_manager.remaining_batches > 0 and self.batch_manager.batch_queue.empty():
                        self.batch_manager.preload_batches()

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
