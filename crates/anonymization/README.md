# Data Anonymization

`Data anonymization` is the process of transforming data in such a way that it can no longer be used to identify individuals without the use of additional information. This is often done to protect the privacy of individuals whose data is being collected or processed.

Anonymization techniques can include removing identifying information such as names and addresses, replacing identifying information with pseudonyms, and aggregating data so that individual data points cannot be distinguished. It's important to note that while anonymization can reduce the risk of re-identification, it is not foolproof and must be used in conjunction with other security measures to fully protect personal data.

## Features

Cosmian anonymization provides multiple methods:

- **Hashing**: transforms data into a fixed-length representation that is difficult to reverse and provides a high level of anonymity. Use `anonymization::Hasher` to apply the various hash functions.

- **Noise Addition**: adds random noise to data in order to preserve privacy. Use `anonymization::NoiseGenerator` to apply various types of noise distributions to `float`, `integer`, and `date`.

- **Word Masking**: hides sensitive words in a text. Use `anonymization::WordMasker` to mask a list of words.

- **Word Tokenization**: removes sensitive words from text by replacing them with tokens. Use `anonymization::WordTokenizer` to replace a list of words.

- **Word Pattern Masking**: replaces a sensitive pattern in text with specific characters or strings. Use `anonymization::WordPatternMasker` to replace specified pattern regex with a replacement string.

- **Number Aggregation**: rounds numbers to a desired power of ten. This method is used to reduce the granularity of data and prevent re-identification of individuals. Use `anonymization::NumberAggregator` to round `float` and `int` values.

- **Date Aggregation**: rounds dates based on the specified time unit. This helps to preserve the general time frame of the original data while removing specific details that could potentially identify individuals. Use `anonymization::DateAggregator` to round `date`.

- **Number Scaling**: scales numerical data by a specified factor. This can be useful for anonymizing data while preserving its relative proportions. Use `anonymization::NumberScaler` to round `float` and `int` values.

## Date Format

***WARNING***: The anonymization functions date input is in RFC3339 string format which is slightly different from ISO format.

| ISO format                | RFC 3339                  |
|---------------------------|---------------------------|
| 2023-04-07T12:34:56       | 2023-04-07T12:34:56**Z**  |
| 2023-04-27T16:23:00+00:00 | 2023-04-27T16:23:00+00:00 |
| 2023-04-27T16:23:00+05:00 | 2023-04-27T16:23:00+05:00 |
| 2023-04-27T16:23:00-05:00 | 2023-04-27T16:23:00-05:00 |
