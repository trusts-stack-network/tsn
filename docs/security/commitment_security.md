# Security of the Commitments

## Introduction

Les commitments are une partie essentielle of the cryptographie usede in notre projet. Ils permettent de garantir l'integrity and la confidentiality of the data. Dans this document, nous allons presentsr les threats and les mitigations relateds to commitments.

## Threats

* Attacks de timing : les timing attacks peuvent permettre to un attacker de deduce of the informations on data sensibles en analysant le temps mis by operations cryptographics.
* Overflow : les overflow peuvent permettre to un attacker de corrompre les data or de create of the conditions de concurrence.
* Utilisation incorrect de zeroize : the use incorrect de zeroize can permettre to un attacker de recover of the informations sensibles.

## Mitigations

* Utilisation de comparaisons constants pour avoid les timing attacks.
* Utilisation de calculs secures pour avoid les overflow.
* Utilisation correct de zeroize for secrets.

## Tests and Fuzzers

* The tests de property are useds pour verify que les commitments are binding.
* The tests de regression are useds pour verify que les overflow are manageds correctly and que les secrets are correctly zeroed.
* Les fuzzers are useds pour tester les inputs externals and garantir que les commitments are robusts.