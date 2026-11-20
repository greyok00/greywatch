# responderd — Responderd (auto-responder)

Source: the GreyWatch responder lane records, curated into gw-tools.

WHAT IT IS: The auto-responder. When a scanner flags a file (YARA hit,
ClamAV detection), responderd executes the response — quarantining the
file, recording the hash and the rule that fired — and posts the
decision card asking what to do with it: keep locked away, put it back,
or delete for good. It is the tool most of the inbox's decision cards
actually come from.

WHAT ITS WARNINGS MEAN: a quarantine row names the file, its SHA-256 and
the signature that matched (Win.Trojan.*, Eicar-Test-Signature). The
action already happened — the card only asks about the file's future.
Restore is a conscious undo; the second identical quarantine creates its
own card keyed by path so nothing stale auto-answers it.

HEURISTICS:
- Eicar-Test-Signature rows are the test file, not an infection —
  deleting it is fine; it exists to prove the pipeline works.
- Real-signature hits in /tmp, Downloads or mail attachments: keep
  quarantined unless the owner recognizes the file; restore is the
  exception, decided by a person, from the card.
- The same path quarantined repeatedly means whatever recreates the file
  is still running — answer the newest card, then find the creator
  (scheduled job, browser helper, sync client) before restoring.
- Quarantine never executes the file it holds: restoring IS the risk,
  so a restore answer is always owner-made, never auto-filled.
