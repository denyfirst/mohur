# Mohur's policies

Two pages, written once, here:

| File | What | In the app | Microsoft Store field |
|---|---|---|---|
| [privacy.md](privacy.md) | What each part of Mohur keeps, and Mohur's promises | **Privacy**, on the join screen and when no conversation is open | Privacy policy URL |
| [terms.md](terms.md) | Terms of use; joining accepts them | **Terms of use**, in the same two places | Additional license terms (the link), and the description |

The app ships both files and shows them itself, offline. It contains no
address of denyfirst's, so it never connects to the website to show them.

## For denyfirst's website

- Publish both pages with the same words; the layout is the website's. The
  Store needs one stable address for each. Suggested:
  `https://denyfirst.dev/mohur/privacy` and `https://denyfirst.dev/mohur/terms`.
- Give each promise in privacy.md an anchor with its ID, such as
  `#mohur-servers-carry-only-ciphertext`, so a link to one promise keeps
  working when its wording improves.
- Mohur's entry in denyfirst's list of products:
  - Name: Mohur
  - What: Encrypted messages between organizations that each run their own server.
  - Promises: the six under "What Mohur promises" in privacy.md, each with its
    ID, its sentence and its "How you check it". They only narrow
    denyfirst's own promises and do not repeat them.
- denyfirst's own promises are not copied here. privacy.md links to
  `https://denyfirst.dev/privacy` for them and for what happens to mail sent
  to hello@denyfirst.dev, so that page must keep saying it.
- Everything on the pages must be true the day they are published. In
  particular, "Our test organization" describes the server for Microsoft's
  testers, which has to be running before the first Store submission.

## Changing them

- English, plain words, and a new "Last changed" date.
- Only `#`, `##` and `###` headings, paragraphs, `- ` lists (a continuation
  line starts with two spaces), `**bold**`, `` `code` `` and `[text](https://…)`
  links. That is what the app shows; `client/test/policy.test.mjs` fails on
  anything else, so a page never reads differently in the app and online.
- A promise needs a "How you check it" that names a test or a place in the
  source, and the test must exist.
- When a change matters to the people using Mohur, say so in the release notes.
