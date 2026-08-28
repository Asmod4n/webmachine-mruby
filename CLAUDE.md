# Regeln fuer dieses Repo

## Zwei Branches, mehr nicht (2026-08-28)

Es gibt genau zwei Branches:

- `next` - hier laeuft die gesamte Entwicklung.
- `master` - hier landet nur, was als Feature fertig ist.

Kein Themen-, Bench- oder Experiment-Branch daneben. Wer etwas
ausprobiert, probiert es auf `next` aus. Ist ein Feature fertig,
wandert es nach `master` - und erst dann.

Vor dem Push pruefen, dass es bei den zweien bleibt:

    git ls-remote --heads origin   # nur master und next

## Keine Session-URLs

Eine Claude-Session-URL (`https://claude.ai/code/session_...`, ob als
`Claude-Session:`-Trailer oder nackt) gehoert an keine Stelle, die das
Repo verlaesst oder in ihm bleibt: Commit-Messages, PR-Titel und
-Bodies, Issue- und Review-Kommentare, Code-Kommentare, Doku. Das gilt
auch dort, wo ein Werkzeug-Default sie vorsieht. `Co-Authored-By:`
bleibt erlaubt.

    git log --format='%B' <range> | grep -c 'claude.ai/code/session'

muss 0 sein.

## Keine Bang-Methoden

Keine Methoden mit `!`. Oeffentliche Faehigkeitsfragen sind
`?`-Praedikate (Muster: `KTLS::Socket#ktls_available?`).
