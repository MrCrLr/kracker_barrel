from concurrent.futures import ProcessPoolExecutor, as_completed
import time

from tqdm import tqdm

from core.hash_handler import crack_chunk, init_worker, crack_range, init_worker_range
from utils.logger import PURPLE, GREEN, LIGHT_YELLOW, RESET


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

    # Process the results from completed futures
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
