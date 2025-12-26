from multiprocessing import Queue

from tqdm import tqdm

from core.brut_gen import get_brute_count
from core.mask_gen import compile_mask_alphabets, get_mask_space_size
from core.rules_gen import get_rule_count
from utils.file_io import validate_password_file, count_wordlist_entries
from utils.logger import LIGHT_YELLOW, RESET


class BatchManager:
    def __init__(self, kracker):
        self.kracker = kracker
        self.batch_generator = None
        self.total_candidates = 0
        self.batch_queue = Queue(maxsize=kracker.preload_limit)
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
