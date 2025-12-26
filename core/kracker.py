from multiprocessing import Event
import time
from utils.detector import Detector
from utils.file_io import load_target_hash
from utils.config_prep import apply_defaults

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
