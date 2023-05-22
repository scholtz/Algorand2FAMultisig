using Algorand.Algod.Model.Transactions;
using Algorand;

namespace Algorand2FAMultisig.MsigExtension
{
    /// <summary>
    /// MsigExtension
    /// </summary>
    public static class MsigExtension
    {
        #region Multisignature support
        /// <summary>
        /// CreateUnsignedMultisigTransaction creates a multisig transaction from the input tx and the multisig account.
        /// </summary>
        /// <param name="from">sign as this multisignature account</param>
        /// <param name="tx">the transaction to sign</param>
        /// <returns>SignedTransaction a partially signed multisig transaction</returns>
        public static SignedTransaction CreateUnsignedMultisigTransaction(this MultisigAddress from, Transaction tx) //throws NoSuchAlgorithmException
        {
            // check that from addr of tx matches multisig preimage
            if (!tx.Sender.ToString().Equals(from.ToString()))
            {
                throw new ArgumentException("Transaction sender does not match multisig account");
            }

            // now, create the multisignature
            MultisigSignature mSig = new(from.version, from.threshold);
            for (int i = 0; i < from.publicKeys.Count; i++)
            {
                mSig.Subsigs.Add(new MultisigSubsig(from.publicKeys[i]));
            }
            return new SignedTransaction(tx, null, mSig, null, null);
        }
        /// <summary>
        /// SignMultisigTransaction creates a multisig transaction from the input and the multisig account.
        /// </summary>
        /// <param name="account">Account to sign it with</param>
        /// <param name="from">sign as this multisignature account</param>
        /// <param name="tx">the transaction to sign</param>
        /// <returns>SignedTransaction a partially signed multisig transaction</returns>
        public static SignedTransaction SignMultisigTransaction(this Algorand.Algod.Model.Account account, MultisigAddress from, Transaction tx) //throws NoSuchAlgorithmException
        {
            // check that from addr of tx matches multisig preimage
            if (!tx.Sender.ToString().Equals(from.ToString()))
            {
                throw new ArgumentException("Transaction sender does not match multisig account");
            }
            // check that account secret key is in multisig pk list
            var myPK = account.KeyPair.PublicKey;
            byte[] myEncoded = myPK.GetEncoded();
            int myI = -1;
            for (int i = 0; i < from.publicKeys.Count; i++)
                if (Enumerable.SequenceEqual(myEncoded, from.publicKeys[i].GetEncoded()))
                {
                    myI = i;
                    break;
                }

            if (myI == -1)
            {
                throw new ArgumentException("Multisig account does not contain this secret key");
            }
            // now, create the multisignature
            SignedTransaction txSig = tx.Sign(account);
            MultisigSignature mSig = new(from.version, from.threshold);
            for (int i = 0; i < from.publicKeys.Count; i++)
            {
                if (i == myI)
                {
                    mSig.Subsigs.Add(new MultisigSubsig(myEncoded, txSig.Sig.Bytes));
                }
                else
                {
                    mSig.Subsigs.Add(new MultisigSubsig(from.publicKeys[i]));
                }
            }
            return new SignedTransaction(tx, null, mSig, null, null);
        }
        /// <summary>
        /// MergeMultisigTransactions merges the given (partially) signed multisig transactions.
        /// </summary>
        /// <param name="txs">partially signed multisig transactions to merge. Underlying transactions may be mutated.</param>
        /// <returns>merged multisig transaction</returns>
        public static SignedTransaction MergeMultisigTransactions(params SignedTransaction[] txs)
        {
            if (txs.Length < 2)
            {
                throw new ArgumentException("cannot merge a single transaction");
            }
            SignedTransaction merged = txs.FirstOrDefault(txs => txs.MSig?.Version != null);
            if (merged == null) throw new ArgumentException("At least one transaction must have multisig configuration");
            var emptySig = new Signature();
            for (int i = 0; i < txs.Length; i++)
            {
                // check that multisig parameters match
                SignedTransaction tx = txs[i];

                if (tx.MSig != null) // check only signed
                {
                    if (tx.MSig.Version != merged.MSig.Version ||
                        tx.MSig.Threshold != merged.MSig.Threshold)
                    {
                        throw new ArgumentException("transaction msig parameters do not match");
                    }
                }
                for (int j = 0; j < merged.MSig.Subsigs.Count; j++)
                {
                    MultisigSubsig myMsig = merged.MSig.Subsigs[j];
                    if (myMsig.sig != null && !myMsig.sig.Equals(emptySig)) continue; // skip if this tx is already signed
                    if (tx.MSig != null)
                    {
                        MultisigSubsig theirMsig = tx.MSig.Subsigs[j];
                        if (!theirMsig.key.Equals(myMsig.key))
                        {
                            throw new ArgumentException("transaction msig public keys do not match");
                        }
                        if (myMsig.sig.Equals(emptySig))
                        {
                            myMsig.sig = theirMsig.sig;
                        }
                        else if (!myMsig.sig.Equals(theirMsig.sig) &&
                              !theirMsig.sig.Equals(emptySig))
                        {
                            throw new ArgumentException("transaction msig has mismatched signatures");
                        }
                        merged.MSig.Subsigs[j] = myMsig;
                    }
                    else
                    {
                        // check if we should merge non msig signature

                        if (tx.AuthAddr != null)
                        {
                            // fill in if we have information on who signed the tx
                            if (merged.MSig.Subsigs[j].key.GetEncoded().SequenceEqual(tx.AuthAddr.Bytes))
                            {
                                merged.MSig.Subsigs[j].sig = tx.Sig;
                            }
                        }

                    }
                }
            }
            return merged;
        }

        /// <summary>
        /// From algosdk lib
        /// </summary>
        /// <param name="txs"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static SignedTransaction MergeMultisigTransactions2(params SignedTransaction[] txs)
        {
            if (txs.Length < 2)
            {
                throw new ArgumentException("cannot merge a single transaction");
            }

            SignedTransaction signedTransaction = txs.FirstOrDefault(txs => txs.MSig != null);
            foreach (SignedTransaction signedTransaction2 in txs)
            {
                if (signedTransaction2.MSig != null) // check only signed
                {
                    if (signedTransaction2.MSig.Version != signedTransaction.MSig.Version || signedTransaction2.MSig.Threshold != signedTransaction.MSig.Threshold)
                    {
                        throw new ArgumentException("transaction msig parameters do not match");
                    }
                }

                for (int j = 0; j < signedTransaction2.MSig.Subsigs.Count; j++)
                {
                    MultisigSubsig multisigSubsig = signedTransaction.MSig.Subsigs[j];
                    MultisigSubsig multisigSubsig2 = signedTransaction2.MSig.Subsigs[j];
                    if (!multisigSubsig2.key.Equals(multisigSubsig.key))
                    {
                        throw new ArgumentException("transaction msig public keys do not match");
                    }

                    if (multisigSubsig.sig.Equals(new Signature()))
                    {
                        multisigSubsig.sig = multisigSubsig2.sig;
                    }
                    else if (!multisigSubsig.sig.Equals(multisigSubsig2.sig) && !multisigSubsig2.sig.Equals(new Signature()))
                    {
                        throw new ArgumentException("transaction msig has mismatched signatures");
                    }

                    signedTransaction.MSig.Subsigs[j] = multisigSubsig;
                }
            }

            return signedTransaction;
        }
        /// <summary>
        /// AppendMultisigTransaction appends our signature to the given multisig transaction.
        /// </summary>
        /// <param name="account">Account from which to add the signature</param>
        /// <param name="from">the multisig public identity we are signing for</param>
        /// <param name="signedTx">the partially signed msig tx to which to append signature</param>
        /// <returns>merged multisig transaction</returns>
        public static SignedTransaction AppendMultisigTransaction(this Algorand.Algod.Model.Account account, MultisigAddress from, SignedTransaction signedTx)
        {
            SignedTransaction sTx = account.SignMultisigTransaction(from, signedTx.Tx);
            return MergeMultisigTransactions(sTx, signedTx);
        }

        #endregion
    }
}
