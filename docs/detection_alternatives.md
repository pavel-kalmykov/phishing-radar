# Typosquatting detection: choice of similarity metric

Rapid note on why the detector sticks with edit-distance but upgrades it
slightly, and why MinHash was considered and dropped for this specific job.

## Context

- 41 canonical brands (see `streaming/flink/brands.py`).
- Roughly 200 certs/sec through the CertStream firehose.
- Per cert, the detector examines a handful of hostname labels (SANs + primary)
  and checks each against every brand.
- Budget: stay inside a few ms per cert on a `shared-cpu-1x` Fly.io machine.

## Candidates and when each one wins

| Metric | Complexity | Catches | Misses | When it wins |
|---|---|---|---|---|
| Exact match after homoglyph normalisation (`0 -> o`, `1 -> l`, ...) | O(L) | `paypa1`, `amaz0n`, `micr0soft` | anything with a real typo | Scripted attacks that rely only on digit substitution |
| Levenshtein | O(B * L^2) | single-char insertions, deletions, substitutions | transpositions (2 edits), keyboard proximity | General baseline |
| Damerau-Levenshtein (OSA) | O(B * L^2) | everything Lev catches, plus transpositions (`paypla`, `amzaon`) as 1 edit | keyboard proximity | Actual human typos or kit-generated permutations |
| Jaro-Winkler | O(B * L) | prefix-preserving variants (`paypal-login-secure`, `paypal.support`) | middle-of-string edits | Attackers that keep the brand as a prefix |
| n-gram Jaccard | O(B * L) | partial overlap where order doesn't matter | very short SLDs (too few n-grams) | Long hostnames where position is noisy |
| MinHash + LSH (over character shingles) | O(L * K) signature + O(1) lookup amortised | same as Jaccard, scales to huge brand sets | short strings, exact-match cases | Millions of brands, millions of docs |

B = number of brands (~40), L = label length (~10-30), K = number of hashes.

## Why not MinHash here

MinHash with locality-sensitive hashing is the standard answer for
"similarity search over a very large set". It turns exact-Jaccard search from
O(|brands|) per query into O(1) amortised after an index build. That matters
when you have 100k+ things to compare against. We have 41.

Other costs of MinHash in this context:

1. **Short strings.** Character-shingle (k=3) signatures for a 7-char SLD have
   5 shingles. With a 100-hash signature most of the signal is noise. Jaccard
   on such small sets is very lumpy.
2. **No exact-match shortcut.** MinHash is probabilistic; it approximates
   Jaccard. For hits like `paypa1 -> paypal` we want a deterministic `yes`,
   not a `~0.87 probably`.
3. **Harder explanations.** `Levenshtein distance 1: paypa1 vs paypal` is
   legible in a log line. `MinHash Jaccard estimate 0.83` is not.
4. **Batch-oriented.** MinHash shines when you have an index and batch the
   queries. Our detector processes events one at a time off a Kafka topic.

The case where MinHash would actually help us is the opposite direction:
given a huge historical pile of flagged certs, cluster them by near-duplicate
subject matter to surface kits. That is a nice batch task for dbt / notebooks,
not the streaming hot path.

## What we actually ship

Keep the three-layer structure (homoglyph, brand-as-label, fuzzy SLD) and
upgrade the fuzzy layer:

1. `Levenshtein.distance` -> `DamerauLevenshtein.distance`. Single-character
   transpositions (`paypla`, `amzaon`) now cost 1 instead of 2. We keep the
   `distance <= 2` cutoff.
2. Add a cheap Jaro-Winkler screen for labels longer than 8 chars:
   `jw >= 0.92` after homoglyph normalisation flags things like
   `paypal-login-secure`. Lower score (1) since the signal is weaker.
3. Keep the homoglyph translation table but extend it with Unicode look-alikes
   (Cyrillic `а`, `е`, `о`, `р`, `с`, `у`) that commonly show up in IDN
   phishing.

The changes are contained in `streaming/flink/detectors.py`; the existing
pytest suite is updated to cover transpositions and prefix-preserving
variants.
