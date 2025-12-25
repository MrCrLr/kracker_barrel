import itertools


def load_rules(rules_file):
    """
    Load transformation rules from a file.
    Returns a list of rules.
    """
    with open(rules_file, "r") as file:
        return [line.strip() for line in file if line.strip() and not line.startswith("#")]  # Ignore empty lines and comments
    

def apply_rules(word, rules):
    """
    Apply transformation rules to a word based on the rules file.
    Returns a set of transformed words.
    """
    transformations = set()

    for rule in rules:
        if rule.startswith("APPEND "):  # Append a string
            to_append = rule.split(" ", 1)[1]
            transformations.add(word + to_append)
        elif rule.startswith("PREPEND "):  # Prepend a string
            to_prepend = rule.split(" ", 1)[1]
            transformations.add(to_prepend + word)
        elif rule == "CAPITALIZE":  # Capitalize the first letter
            transformations.add(word.capitalize())
        elif rule == "REVERSE":  # Reverse the word
            transformations.add(word[::-1])
        elif rule == "LEETSPEAK":  # Replace common characters with leetspeak
            leetspeak = word.replace("a", "@").replace("o", "0").replace("e", "3").replace("i", "1").replace("s", "$")
            transformations.add(leetspeak)
        else:
            print(f"Unknown rule: {rule}")

    return transformations


# Combine wordlists and apply rules
def combine_wordlists_with_rules(wordlist1, wordlist2=None, output_file="combined_with_rules.txt"):
    """
    Combine two wordlists and apply transformation rules to each word.
    Save results to the output file.
    """
    combined = set()

    # Load wordlists
    with open(wordlist1, "r") as file1:
        words1 = [line.strip() for line in file1]
    words2 = []
    if wordlist2:
        with open(wordlist2, "r") as file2:
            words2 = [line.strip() for line in file2]

    # Combine wordlists (if wordlist2 exists)
    if wordlist2:
        for word1, word2 in itertools.product(words1, words2):
            combined.add(f"{word1}{word2}")  # Simple concatenation
            combined.add(f"{word1}-{word2}")  # Hyphenated combination
    else:
        combined.update(words1)  # Use only words from wordlist1

    # Apply rules to combined words
    all_transformed = set()
    for word in combined:
        all_transformed.update(apply_rules(word))

    # Save results to the output file
    with open(output_file, "w") as output:
        for transformed_word in all_transformed:
            output.write(transformed_word + "\n")

    print(f"Combined and transformed wordlist saved to '{output_file}'.")

# Example usage
combine_wordlists_with_rules("../refs/500-worst-passwords.txt", "../refs/500-worst-passwords.txt")



def generate_candidates(wordlist1, rules, wordlist2=None):
    """
    Generate password candidates by applying rules to words from wordlists.
    """
    for word1 in wordlist1:
        # Apply transformations to words from wordlist1
        for transformed in apply_rules(word1, rules):
            yield transformed

        # Combine with wordlist2 (if provided)
        if wordlist2:
            for word2 in wordlist2:
                yield f"{word1}{word2}"
                yield f"{word2}{word1}"


def rule_based_attack(config):
    """
    Perform a rule-based attack using the configuration.
    """
    # Load inputs
    raise NotImplementedError("Rule-based attack is not implemented yet.")


def load_wordlist(_path):
    raise NotImplementedError("Rule-based attack helpers are not implemented yet.")


def load_hashes(_path):
    raise NotImplementedError("Rule-based attack helpers are not implemented yet.")


def verify_candidates(_candidates, _target_hashes, _hash_type):
    raise NotImplementedError("Rule-based attack helpers are not implemented yet.")


if __name__ == "__main__":
    combine_wordlists_with_rules("../refs/500-worst-passwords.txt", "../refs/500-worst-passwords.txt")
