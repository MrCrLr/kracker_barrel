import os, time
from core.brut_gen import get_brute_count
from core.mask_gen import get_mask_count
from utils.logger import display_summary, PURPLE, RESET
from utils.file_io import get_number_of_passwords


class Reporter:
    def __init__(self, kracker):
        self.kracker = kracker
        self.summary_log = self.initialize_summary_log()


    def __str__(self):
        return (
            f"\n{PURPLE}Kracker Configuration:{RESET}\n"
            f"  Operation: {self.kracker.operation}\n"
            f"  Target: {self.kracker.target_file}\n"
            f"  Hash type: {self.kracker.hash_type}\n"
            f"  Password list: {self.kracker.path_to_passwords}\n"
            f"  Batch size: {self.kracker.batch_size}\n"
            f"  Logical cores: {os.cpu_count()}\n"
            f"  Workers: {self.summary_log['workers']}\n"
            f"  Process PID: {os.getpid()}\n"
            f"  Preload limit: {self.kracker.preload_limit}\n"
        )


    def initialize_summary_log(self):
        if self.kracker.operation == "dict":
            number_of_passwords = get_number_of_passwords(self.kracker.path_to_passwords)
        elif self.kracker.operation == "brut":
            number_of_passwords = get_brute_count(self.kracker.brute_settings)
        elif self.kracker.operation == "mask":
            number_of_passwords = get_mask_count(self.kracker.mask_pattern, self.kracker.custom_strings)
        elif self.kracker.operation == "rule":
            number_of_passwords = 1

        total_batches = (number_of_passwords // self.kracker.batch_size) + 1
        
        return {
            "operation": self.kracker.operation,
            "input_file": self.kracker.target_file,
            "hash_type": self.kracker.hash_type,
            "hash_parameters": None,
            "file_scanned": self.kracker.path_to_passwords,
            "workers": self.kracker.workers,
            "batches": total_batches,
            "batch_size": self.kracker.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
        }


    def final_summary(self):
        """Display final summary after processing is completed."""
        # Retrieve hash parameters
        try:
            self.summary_log["hash_parameters"] = self.kracker.hash_handler.log_parameters()
        except AttributeError:
            self.summary_log["hash_parameters"] = "N/A"  # Default if no parameters are available

        # Construct the final message based on results
        if self.kracker.found_flag["found"] == 0:
            self.summary_log["message"] = (
                "No match found in word list."
            )
        elif self.kracker.found_flag["found"] <= self.kracker.found_flag["goal"] and self.kracker.found_flag["goal"] != 1:
            self.summary_log["message"] = (
                f"{self.kracker.found_flag['found']} of {self.kracker.found_flag['goal']} "
                "matches found in word list."
            )
        else:
            self.summary_log["message"] = (
                f"{self.kracker.found_flag['found']} of {self.kracker.found_flag['goal']} "
                "match found in word list."
            )

        self.summary_log["elapsed_time"] = time.perf_counter() - self.kracker.start_time
        display_summary(self.kracker.found_flag, self.summary_log)
