# Canary qualification run

Mode: wrong_answer
Revision: 52d831249eb2d0960d6b21093bdcb9cadb7bd260
Verdict: AS PREDICTED (quota admitted = false, predicted = false)

| Item | Value |
|---|---|
| cycle id | cycle-04fb260dc0f64107aa6428f6a0bc3d51 |
| proposal | prop-dc0bf12ad61f4a94b1e6aca4e46e87fb (UnslopSanitization, README.md) |
| canary applicable / eligible | true / true |
| refusal | none |
| identity binding digest | 56a90553b18cc678bb1512faab5d25d9e1cb85c70bea9a86cc07036a3a2b7523 |
| executable digest | 870722da2227135d0d53c1575a8f2ca5dcf41c630415d4dda389073af0f2341e |
| workload digest | d21ca53e23457bd1da84e0cc2115999208312eea03f30616a5c3d46e97e39bab |
| sealed log digest | 63cf4282a17e0b6ce3997a7fd0d7e306fce064be42c2995c9df0e575d1c3f05d |
| commitment block hash | 46895b6b874f00a970821d42cdeb8de2ae319e9840764b2247c6a830aee9ce86 |
| execution | planned 10, issued 3, verified 2, wrong 1, timeout 0, invalid 0, closed 0, rejections 0, ready true, reverted true, first failure Some("req-003: WrongResult") |
| quota | admitted false (counted None of target 10): canary observed a WrongResult on request req-003; the candidate is not promotable (first failure: req-003: WrongResult) |
| safety envelope | not reached |
| envelope note | none |
| promotion gate | not reached |
| cycle success | false |
| durable generation | false |

A passing correct run qualifies the canary execution pipeline. It does not qualify RSI's ability to improve itself, and it does not qualify the safety envelope as a production evaluator.
