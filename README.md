# Algorand 2FA Multisig

https://2famsig.k8s.aramid.finance/swagger/index.html


https://forum.algorand.org/t/2fa-feature-is-needed-asap-for-all-transactions-and-account-recovery/9091/16?u=scholtz

Use case: 2FA Auth. Multisig with 3 accounts, where one is owned by user and stored in cold storage, second is owned by user and stored in hot wallet, and third account owned by trusted service where which approves the tx if 2FA auth (Google auth) is processed successfully. Threshold for multisig is 2, so that service cannot do any txs, and if service go off user can rekey with the cold storage account.

