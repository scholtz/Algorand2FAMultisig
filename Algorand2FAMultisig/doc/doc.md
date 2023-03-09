# Algorand 2FA Sevice API

Use [ARC14](https://github.com/scholtz/AlgorandAuthenticationDotNet) for authentication.

Use case: 2FA Auth. Multisig with 3 accounts, where one is owned by user and stored in cold storage, second is owned by user and stored in hot wallet, and third account owned by trusted service where which approves the tx if 2FA auth (Google auth) is processed successfully. Threshold for multisig is 2, so that service cannot do any txs, and if service go off user can rekey with the cold storage account.

