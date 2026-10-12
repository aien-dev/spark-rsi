# Canary qualification run

Mode: correct
Revision: 52d831249eb2d0960d6b21093bdcb9cadb7bd260
Verdict: AS PREDICTED (quota admitted = true, predicted = true)

| Item | Value |
|---|---|
| cycle id | cycle-2abc6c8bd0794b1681c5c3d90228258d |
| proposal | prop-108fc8bf5a3c4b0ab339dd33c18f81f6 (UnslopSanitization, README.md) |
| canary applicable / eligible | true / true |
| refusal | none |
| identity binding digest | 37ad7245245e5d06a4084a820b314c849c96a61c8365e3a407bef726b533f76d |
| executable digest | 870722da2227135d0d53c1575a8f2ca5dcf41c630415d4dda389073af0f2341e |
| workload digest | d21ca53e23457bd1da84e0cc2115999208312eea03f30616a5c3d46e97e39bab |
| sealed log digest | 656369180cb7b506457b03037cddd65005d66f2e73f21e7a07cb01123541306a |
| commitment block hash | 7a2bc9e5c69064930251c4b08680dbe52f70d4fc1f1bf599929fe7164133d738 |
| execution | planned 10, issued 10, verified 10, wrong 0, timeout 0, invalid 0, closed 0, rejections 0, ready true, reverted false, first failure None |
| quota | admitted true (counted Some(10) of target 10) |
| safety envelope | passed true: signed canary evaluation receipt issued |
| envelope note | the safety envelope evaluated through aien_probe::DeterministicReferenceBackend; this is a reference evaluation and does not establish production safety |
| promotion gate | passed false: no pinned judge public key (judge_public_key_hex); promotion fails closed |
| cycle success | false |
| durable generation | false |

A passing correct run qualifies the canary execution pipeline. It does not qualify RSI's ability to improve itself, and it does not qualify the safety envelope as a production evaluator.
