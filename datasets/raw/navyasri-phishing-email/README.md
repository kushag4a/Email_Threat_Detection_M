# 🛡️ Phishing Email Classification Dataset

This dataset is curated for fine-tuning LLMs on the task of phishing email detection. It originates from [this Kaggle dataset](https://www.kaggle.com/datasets/subhajournal/phishingemails) and has been transformed to better suit LLM-based classification tasks.

## 📦 Dataset Features

- Each row is a labeled email, with either:
  - `safe email` (label = 0)
  - `phishing email` (label = 1)
- The dataset includes metadata (sender, receiver, date, subject) and cleaned email body.
- Two main columns:
  - `Email Text`: Complete formatted text including metadata and message content.
  - `label`: Binary label indicating if the email is phishing.

## 🧠 LLM Fine-Tuning Ready

Processed using a `phishing_items.py` parser:
- Truncates or filters emails based on token limits for LLM input (between 30 and 250 tokens).
- Builds classification prompts in the format:
  
  ```
  Is the following email safe or phishing??

  [email content]

  Email type is: [safe email/phishing email]
  ```

- Optimized for models such as `meta-llama/Meta-Llama-3.1-8B`.

## 🧼 Preprocessing Highlights

- Removes non-informative characters (e.g., `=`, `>`, `\`) and extra whitespace.
- Tokenized with Hugging Face's `AutoTokenizer`.
- Discards overly short emails (under 120 characters or under 30 tokens).

## 🗂️ Example Usage

```python
from phishing_items import Item

item = Item(data_row)
if item.include:
    print(item.prompt)
```

## 📚 Source

- Original dataset: [Kaggle - Phishing Emails](https://www.kaggle.com/datasets/subhajournal/phishingemails)
- Transformed by: [your GitHub or Hugging Face handle]
