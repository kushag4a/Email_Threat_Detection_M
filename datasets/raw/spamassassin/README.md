---
license: unknown
---

# Dataset Card for the SpamAssassin public mail corpus

## Dataset Description

- **Homepage:** https://spamassassin.apache.org/old/publiccorpus/readme.html

### Dataset Summary

This is a selection of mail messages, suitable for use in testing spam filtering systems assembled by members of the SpamAssassin project.

### Supported Tasks and Leaderboards

[More Information Needed]

### Languages

[More Information Needed]

## Dataset Structure

### Data Instances

 - The `text` config normalizes all character sets to utf8 and dumps the
   MIME tree as a JSON list of lists.
 - The `unprocessed` config does not parse messages at all, leaving the
   full headers and content as binary.

### Data Fields

 - `label`: `spam` or `ham`
 - `group`: SpamAssassin has grouped these samples into categories
   {'hard_ham', 'spam_2', 'spam', 'easy_ham', 'easy_ham_2'}
 - `text`: normalized text of the message bodies
 - `raw`: full binary headers and contents of messages

### Data Splits

Only a _train_ split has been provided.

## Dataset Creation

### Curation Rationale

It is hoped this dataset can help verify that modern NLP tools can solve
old NLP problems.

### Source Data

#### Initial Data Collection and Normalization

[The upstream corpus description](https://spamassassin.apache.org/old/publiccorpus/readme.html)
goes into detail on collection methods.  The work here to recover text bodies
is largely done with [email.parser](https://docs.python.org/3/library/email.parser.html)
and [ftfy](https://pypi.org/project/ftfy/).

#### Who are the source language producers?

[More Information Needed]

### Annotations

#### Annotation process

[More Information Needed]

#### Who are the annotators?

[More Information Needed]

### Personal and Sensitive Information

[More Information Needed]

## Considerations for Using the Data

### Social Impact of Dataset

[More Information Needed]

### Discussion of Biases

[More Information Needed]

### Other Known Limitations

[More Information Needed]

## Additional Information

### Dataset Curators

[More Information Needed]

### Licensing Information

[More Information Needed]

### Citation Information

[More Information Needed]

### Contributions

[More Information Needed]