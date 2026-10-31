# Password Similarity Detection with Bloom Filters

A command-line tool, written in C++, that rejects passwords which are *slightly modified versions*
of known weak passwords (`football` → `football2`, `password` → `pass@word`), not just exact matches.

Built for **CSCI262 System Security** (Group 33).

---

## The idea

Most password blacklists only do exact matching, so `football23` is blocked but `football24` sails
through. Attackers know this, and try small variations of leaked passwords first.

This project compares passwords by their **structure** instead:

```
password ──► pad with spaces ──► split into bi-grams ──► hash each bi-gram into a Bloom filter
                                                                      │
 candidate filter  ◄── OR all bi-gram filters together ◄─────────────┘
        │
        ▼
 compare with every dictionary filter (Jaccard · Dice · Cosine)
        │
        ▼
 max Dice ≥ 0.70  →  REJECT      otherwise  →  ACCEPT
```

1. **Bi-grams**: `" football2 "` becomes `" f", "fo", "oo", "ot", "tb", "ba", "al", "ll", "l2", "2 "`.
   Two passwords sharing most of their character pairs end up with similar filters.
2. **Bloom filter**: a 1000-bit array (`L = 1000`). Each bi-gram sets 20 bits (`k = 20`).
3. **Double hashing**: instead of 20 separate hash functions, two are used:
   `h_i(x) = (SHA-256(x) + i · MD5(x)) mod 1000` for `i = 0..19`
   (Kirsch & Mitzenmacher, 2006). MD5 is used only to generate bit positions, never for security.
4. **Similarity**, where `γ` is the number of bits set in both filters and `k1`, `k2` are the
   number of bits set in each:

   | Metric  | Formula                  |
   |---------|--------------------------|
   | Jaccard | `γ / (k1 + k2 − γ)`      |
   | Dice    | `2γ / (k1 + k2)`         |
   | Cosine  | `γ / √(k1 · k2)`         |

   **Dice is the decision metric**; the other two are printed for comparison.

## Build & run

Requirements: `g++` (C++17) and the OpenSSL development headers.

```bash
# Debian / Ubuntu
sudo apt install build-essential libssl-dev
# macOS (Homebrew)  ->  brew install openssl   (you may need to pass -I/-L flags)

make            # builds bin/password_checker
make run        # builds and starts the interactive prompt
make test       # runs the automated test cases
```

Enter a password of 8–10 characters, or `q` to quit. For each candidate the program prints the
Jaccard / Dice / Cosine score against every dictionary password, then the decision:

```
Enter password (8-10 chars): football2
...
MAX: football23 => 0.882353
Decision: REJECT

FINAL: REJECT
```

After every query it also prints the Bloom filters of the 17th (`football23`) and 55th
(`allahswt`) dictionary passwords, as required by the course specification.

## Example results

Produced by this code (see `tests/run_tests.sh`):

| Candidate    | Closest dictionary match | Max Dice | Decision |
|--------------|--------------------------|---------:|----------|
| `football23` | `football23` (exact)     | 1.0000   | REJECT   |
| `jasmine2`   | `jasmine2` (exact)       | 1.0000   | REJECT   |
| `princess9`  | `princess99`             | 0.9514   | REJECT   |
| `football2`  | `football23`             | 0.8824   | REJECT   |
| `football1`  | `football`               | 0.8613   | REJECT   |
| `pass@word`  | `password09`             | 0.7209   | REJECT   |
| `xk9_alpha`  | `alphabet`               | 0.5014   | ACCEPT   |
| `rainfall`   | `football`               | 0.4551   | ACCEPT   |
| `ch@mpion`   | `catriona`               | 0.4185   | ACCEPT   |
| `mysecure`   | `foreverme`              | 0.3663   | ACCEPT   |
| `Tr0ub4dor`  | `feyenoord`              | 0.3288   | ACCEPT   |

Dictionary statistics (204 passwords from a RockYou subset): average of 9.57 bi-grams per
password and about 170 set bits per filter (≈17% density). Comparing the dictionary against
itself, 12 password pairs score Dice ≥ 0.70, for example `password69`/`password09`,
`ronaldo17`/`ronaldo07` and `football23`/`football`.

## Project structure

```
.
├── src/main.cpp         # hashing, Bloom filters, bi-grams, similarity metrics, CLI
├── tests/run_tests.sh   # accept/reject regression tests
├── Makefile
├── LICENSE
└── README.md
```

## Limitations

- **Similarity ≠ strength.** `12345678` shares little structure with the dictionary, but it is
  still a terrible password. A real policy would also use entropy estimates and composition rules.
- **Narrow threshold margin.** On this small dictionary, the highest-scoring pair that stays
  *below* the threshold is `j1234567`/`123456798` at Dice 0.692, close to the 0.70 cut-off. The
  threshold was tuned on a small sample and would need recalibrating on a larger dataset.
- **Order-insensitive to reversals.** Bi-grams miss relations such as reversed passwords.
- **Dictionary is compiled into the binary** in plaintext, so the "store only filters" privacy
  benefit would require loading the dictionary from a file and discarding the strings.
- **Input length is limited** to 8–10 characters, matching the assignment.

## Ideas for future work

- Load the dictionary from a file instead of embedding it in `main.cpp`
- Show only the top-N matches instead of printing the full table
- Combine the three metrics into one score and calibrate the threshold on a larger dataset
- Replace the deprecated one-shot `MD5()` call with OpenSSL's EVP interface
- A small web front end for live demos

## Authors

CSCI262 Group 33: Renzo Caranto, Moosa Bahadur, Muhammad Ibrahim, Zidane Mustafa.

## Note on the dataset

The dictionary is a small subset of the publicly known RockYou password leak, used here purely
for educational security research.

## License

MIT, see [LICENSE](LICENSE).
