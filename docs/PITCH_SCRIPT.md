# Pitch and demo script (5 minutes)

Every number in this script is measured and comes from `reports/` or `docs/evidence/`. Do not add a claim that is not in those files. If the allowed time differs, scale each section and keep the order.

## Before you present (10 minutes)

- [ ] Server app is running: `ssh -i E:\ssh-keys\l1cc_datathon linux1@<SERVER_IP> "~/scamshield/start_demo.sh"`
- [ ] Tunnel is open in its own window: `ssh -N -L 8000:127.0.0.1:8000 -i E:\ssh-keys\l1cc_datathon linux1@<SERVER_IP>`
- [ ] http://127.0.0.1:8000 loads, and the footer says "Running on IBM LinuxONE (s390x)"
- [ ] A second terminal is already logged in to the server, with `uname -m` ready to run
- [ ] Browser zoom at 125 percent, notifications off, other tabs closed
- [ ] Recorded backup demo is open in another tab (see "If something fails")
- [ ] Run each demo message once so the first click is fast

## Timeline

| Time | Section | Slide |
|---|---|---|
| 0:00 | The problem | 2 |
| 0:40 | Why current tools fall short | 3 |
| 1:00 | What ScamShield does | 4 |
| 1:20 | Live demo | 5 |
| 3:00 | How it works | 6 |
| 3:40 | Why IBM LinuxONE | 7 |
| 4:15 | Results and limits | 8 |
| 4:45 | Responsible AI, next steps, close | 9 to 11 |

## What to say

**The problem (0:00).** "A message arrives. It says your KYC expires today, or your parcel is held, or the police have a case against you. These messages copy banks, couriers and officials, and they work best on people who are not used to spotting them: older people and first-time smartphone users. Once someone shares an OTP or approves a UPI request, the money is usually gone." If a team member has a real story from their own family, tell that instead, in their own words. Do not invent one.

**Why current tools fall short (0:40).** "A spam filter says 'spam' but not why, so nobody learns anything. Many link checkers upload the message or link to an outside service, which means private conversations leave the phone."

**What ScamShield does (1:00).** "You paste a message. In milliseconds you get a risk level, the reasons in plain words, your own message with the risky words marked, and the steps to take. It never stores the message and never opens a link."

**Live demo (1:20).** Run these in order and say one sentence for each.
1. Terminal: `uname -m` shows s390x. "This is the IBM mainframe the whole system runs on."
2. Click **Genuine bank OTP**. Result: low. "A real OTP message says not to share it, and has no link. Many filters get this wrong. We test for it specifically."
3. Click **Fake KYC alert**. Result: high. Point at the marked link. "The link pretends to be SBI, but the real address is something else."
4. Click **Digital arrest call**. Result: high with no link. "Not every scam has a link. This one pressures you with a threat. Real officials do not arrest anyone over a call."
5. Point at **What to do now**, then press **Copy summary**. "A family member can paste this into a chat."
6. Open **Technical details**. "Each model's score is visible. Nothing is hidden."

**How it works (3:00).** "The text is cleaned first, so disguised letters are read as the word they imitate. Four checks run side by side: two wording models, one of them a small neural network trained from scratch; a link model that judges the address only; and 23 signals for known patterns. A small model combines them, and five safety rules always force a high-risk result, such as asking for your OTP."

**Why IBM LinuxONE (3:40).** "Everything ran on the mainframe: data preparation, training in about 11 minutes, testing, and serving. All 74 tests pass there. We also scored 10,000 new messages on it: about 590 to 600 messages a second on one processor, and about 1,015 to 1,025 with two, across two runs. A third processor did not help reliably on this 3-processor virtual machine. The server has an on-chip AI accelerator, but our models run on the ordinary processors, so we do not claim it. The use case is a bank or telecom scanning messages next to its own systems, without sending them to an outside cloud. We trained on the server itself because the mainframe stores numbers differently from a laptop, so a model file trained elsewhere can be misread."

**Results and limits (4:15).** "On 916 unseen public messages, 96.9 percent of scams were rated high risk and 0.5 percent of genuine messages were wrongly rated high. On 461 Indian-context messages the team wrote, all scams were caught but 6.2 percent of genuine messages were over-flagged. About 4.5 percent of genuine bank messages were over-flagged on the main test. The Indian-context set was written by us, so it is not fully independent." Show slide 8. Say the limit before a judge has to ask.

**Close (4:45).** "ScamShield does not block anything and can be wrong, so it advises, it does not decide. Next steps: more real messages, regional languages, screenshot input, and a bank-side batch service. The code, the evidence and the measured results are public."

## If something fails

- **Tunnel drops:** reconnect with the tunnel command above, refresh the page. Keep going.
- **Server app not responding:** run `start_demo.sh` again and wait 8 seconds.
- **No network at all:** play the recorded demo and say clearly that it is a recording.
- **Never** improvise a number. If asked something you do not have, say "we have not measured that".

## Likely questions and honest answers

| Question | Answer |
|---|---|
| Does it really run on IBM Z? | Yes. The training log, test log, platform fingerprint and benchmark in `docs/evidence/` were produced on the LinuxONE VM (s390x, big-endian). The app refuses to load models trained on a different architecture. |
| Why not just ask a large language model? | An LLM would send private messages to an outside service and is slower. Ours checks in a few milliseconds on the server. Our own comparison against an LLM is not run yet, because it needs an API key. We do not claim a result for it. |
| Is the data real? | Public datasets (UCI SMS, a Mendeley smishing set, PhiUSIIL URLs) plus 144 message templates written by the team for Indian-style messages. The templates are labelled synthetic everywhere. |
| What about false alarms on real bank messages? | About 4.5 percent of genuine bank messages were rated high risk on the main test, 0.6 percent on average over five other splits. We report it because a filter that cries wolf on a real bank message loses trust. |
| Does the neural network beat a simple model? | On public data the full system and a simple TF-IDF model score about the same (0.987 vs 0.988 PR-AUC). The combination helps on the Indian-context set (0.997 vs 0.967). |
| Why IBM Z for this? | The realistic deployment is a bank or telecom scoring messages at volume beside its systems. We measured throughput on the mainframe. We did not test at bank scale and do not claim to. |
| Does it use the Telum accelerator? | No. The accelerator is visible to the VM, but our models run on the ordinary processors. |
| How do you protect privacy? | The message is held in memory and discarded, logs hold only length, level and timing, feedback stores a one-way hash, links are never opened, and the site loads nothing from outside. The privacy page lists it exactly. |
| What did you build versus reuse? | The models, signals, ensemble, interface and evaluation are ours. We use public datasets, scikit-learn, PyTorch, Flask, and the Inter and IBM Plex Mono typefaces. Everything reused is listed in NOTICE. |
| Could scammers beat it? | Yes. Rules are public in an open repository, and new scripts with no familiar warning signs can be missed. The learned models reduce this but do not remove it. |
