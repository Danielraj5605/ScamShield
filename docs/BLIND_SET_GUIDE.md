# Blind test set guide

A blind set is a fair exam: messages written by people who have not seen how ScamShield was built, scored once, with the results reported as they come out. It is the most credible single number you can show.

## What to collect

- At least 60 messages, ideally 100, split roughly half scam and half genuine.
- Several people (three or more), each writing no more than 30, so that no one person's style dominates.
- **Genuine messages should include hard ones:** bank debit and credit alerts, OTPs, delivery updates, utility and telecom bills, government notices, school or hospital notices, and personal messages that ask for money or urgently ask for a code.
- **Scam messages should cover different types:** KYC or account block, OTP requests, fake refund or UPI request, parcel fee, job or task offers, electricity cut-off, police or "digital arrest", prize or lottery, loan, investment, remote-access apps. Include some with **no link**.

## Rules

1. Write from messages you have actually seen or heard about. Do not copy from `data/templates/templates.json`, the datasets, or the examples on the website.
2. Remove personal data. Mask phone numbers (`9XXXXX1234`), card and account numbers, and real names.
3. Label each message honestly as `scam` or `genuine`, and do not change a label later because of how ScamShield rated it.
4. Do not run ScamShield on the messages while you are still writing them. That is what keeps the test blind.
5. Score the set **once**. Report the result even if it is worse than the other numbers.
6. If you later change the model because of mistakes found here, that set is no longer blind. Say so, and collect a new set for any new claim.

## File format

A CSV with exactly two columns, `text` and `label`. Labels are `scam` or `genuine`. Quote any text that contains a comma.

```
text,label
"Your electricity will be cut tonight. Call our officer on 9XXXXX1234 now",scam
"Rs 2,500 debited from A/c XX4521 on 12-Oct. Not you? Call the number on your card",genuine
```

A starting file with only the header is in `tests/blind/blind_template.csv`. Keep the real set out of git if it contains anything you would not want public.

## Run it on the server

From Git Bash on your laptop, copy the file, then score it:

```bash
scp -i ~/.ssh/l1cc_datathon blind.csv linux1@<SERVER_IP>:~/scamshield/blind.csv
ssh -i ~/.ssh/l1cc_datathon linux1@<SERVER_IP> 'cd ~/scamshield && PYTHONPATH=src .venv/bin/python -m scamshield blind blind.csv'
```

It prints how many scams were rated high risk and how many genuine messages were wrongly rated high risk, each with a 95 percent confidence interval, and lists every mistake in `reports/blind_s390x.json`. It also warns if any message matches training data.

## How to quote the result

State the number of messages, who wrote them, the date, and the interval. For example: "On 100 messages written by three team members who had not seen the training data, X of Y scams were rated high risk (95 percent interval A to B) and Z of W genuine messages were wrongly rated high risk." Do not round up, and do not drop the interval.
