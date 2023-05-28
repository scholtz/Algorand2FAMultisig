using Algorand.Algod.Model.Transactions;
using Algorand;
using Algorand2FAMultisig.Controllers;
using Algorand2FAMultisig.Repository.Implementation;
using Algorand2FAMultisig.Repository.Interface;
using Castle.Core.Configuration;
using Castle.Core.Logging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework.Internal;
using System.Reflection;
using Algorand.Algod;
using System.Security.Claims;
using Google.Authenticator;
using Newtonsoft.Json;
using Algorand.Utils;
using Algorand2FAMultisig.MsigExtension;
using Microsoft.AspNetCore.Identity;
using Algorand2FAMultisig.Repository.Implementation.Storage;

namespace Algorand2FAMultisigTests
{
    public class MultisigControllerTests
    {
        private readonly MultisigController _controller;
        private readonly static string secret = "the string you want to return";
        private readonly static string primaryAccount = "BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ";
        private readonly static string secondaryAccount = "G56BAIRDZAJHERKPWDJSAKBW67MTIC5ZLGW26OWLLNITQVWLUZMLF5U7QA";
        private readonly static string twoFaAccount = "PXOHOGCCUXQE5BFGF5Y5UII57GYIDX3STI3YFWRAVMFANZUERBPJN2M4CU";//"K6WWQVKWZ33WADKKX6BZOWVV5R2VI237LCXOBR24AWUH7IABLUHS2H36EE";
        private readonly List<string> Accounts;
        private readonly Algorand2FAMultisig.Model.Multisig MsigConfig;
        private readonly MultisigAddress MultiAddress;
        private readonly StorageMock storage;
        public MultisigControllerTests()
        {
            var configuration = new Mock<Microsoft.Extensions.Configuration.IConfiguration>();
            configuration.SetupGet(x => x["Algo:Mnemonic"]).Returns(secret);
            configuration.SetupGet(x => x["Algo:TwoFactorName"]).Returns("TwoFactorTestName");

            Accounts = new List<string>() { twoFaAccount, primaryAccount, secondaryAccount };
            Accounts.Sort();
            MsigConfig = new Algorand2FAMultisig.Model.Multisig()
            {
                Signators = Accounts.ToArray(),
                Threshold = 2,
                Version = 1
            };
            MultiAddress = new MultisigAddress(1, 2, new List<byte[]> { new Address(MsigConfig.Signators[0]).Bytes, new Address(MsigConfig.Signators[1]).Bytes, new Address(MsigConfig.Signators[2]).Bytes });

            var logger = new Mock<ILogger<MultisigController>>();
            var authApp = new GoogleAuthenticatorApp(configuration.Object);
            storage = new StorageMock();
            _controller = new MultisigController(logger.Object, configuration.Object, authApp, storage);
            _controller.SetAuthUser(primaryAccount);
        }

        [SetUp]
        public void Setup()
        {
            storage.Clear();
            _controller.Clear();
        }

        [Test]
        public void SetupGoogleAuthenticatorJsonTest()
        {
            var ret = _controller.SetupAuthenticator("title", secondaryAccount);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.That(resultObj, Is.Not.Null);
        }

        [Test]
        public void GetAddressTest()
        {
            var ret = _controller.GetAddress(secondaryAccount);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo(twoFaAccount));
        }
        [Test]
        public async Task SignValidateTwoFactorPINBase64MsgPackTxTest()
        {
            var ret = _controller.SetupAuthenticator("title", secondaryAccount);
            var key = MultisigController.ComputeSHA256Hash($"{twoFaAccount}-{secret}");
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.That(resultObj, Is.Not.Null);
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);

            var httpClient = HttpClientConfigurator.ConfigureHttpClient("https://testnet-api.algonode.cloud", "aa");
            var algodApiInstance = new DefaultApi(httpClient);
            var transParams = await algodApiInstance.TransactionParamsAsync();
            transParams.LastRound = 1;
            var address = new Address(primaryAccount);
            var tx1 = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(MultiAddress.ToAddress(), address, 0, "#ARC14", transParams);
            var msigTx = MultiAddress.CreateUnsignedMultisigTransaction(tx1);
            var tx1MessagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(msigTx);
            var signRet = _controller.PasswordAccountSignMsig("Password123", tx1MessagePack);
            var signResult = signRet.Result as OkObjectResult;
            Assert.That(signResult, Is.Not.Null);
            var signResultObj = Convert.ToBase64String(signResult.Value as byte[]);
            Assert.That(signResultObj, Is.EqualTo("gqRtc2lng6ZzdWJzaWeTgqJwa8QgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyhc8RAZLwRJ0DzYpJkwgNMli/PEUQ+8whWZ36Flb4QccjWN2AW000IMMkzPjan1Z15Sydr8O5kOYSgdvlmegyaE3N4AYGicGvEIDd8ECIjyBJyRU+w0yAoNvfZNAu5Wa2vOstbUThWy6ZYgaJwa8Qgfdx3GEKl4E6Epi9x2iEd+bCB33KaN4LaIKsKBuaEiF6jdGhyAqF2AaN0eG6Jo2ZlZc0D6KJmdgGjZ2VurHRlc3RuZXQtdjEuMKJnaMQgSGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiKibHbNA+mkbm90ZcQGI0FSQzE0o3JjdsQgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyjc25kxCBMROaWXXOI7SMPB2d4seWd896mpnJaK21x0nuYRzOntKR0eXBlo3BheQ=="));

            var sign2FARet = _controller.SignWithTwoFactorPINMsigTx(pin, Convert.FromBase64String(signResultObj), secondaryAccount);
            var sign2FAResult = sign2FARet.Result as OkObjectResult;
            Assert.That(sign2FAResult, Is.Not.Null);
            var sign2FAResultObj = Convert.ToBase64String(sign2FAResult.Value as byte[]);
            Assert.That(sign2FAResultObj, Is.EqualTo("gqRtc2lng6ZzdWJzaWeTgqJwa8QgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyhc8RAZLwRJ0DzYpJkwgNMli/PEUQ+8whWZ36Flb4QccjWN2AW000IMMkzPjan1Z15Sydr8O5kOYSgdvlmegyaE3N4AYGicGvEIDd8ECIjyBJyRU+w0yAoNvfZNAu5Wa2vOstbUThWy6ZYgqJwa8Qgfdx3GEKl4E6Epi9x2iEd+bCB33KaN4LaIKsKBuaEiF6hc8RAfaRTyTvTz8wCBXhlI6x6RoEO0TrZ5ro1219BwHSSeqA56Cjp8piiuTn/8insy27PkgtEY7/71AmuKaFyA2ezCqN0aHICoXYBo3R4bomjZmVlzQPoomZ2AaNnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds0D6aRub3RlxAYjQVJDMTSjcmN2xCAMk5Xe++NlZLRIhDQ1QL4xUJudaD3SUilxIJiolSvx/KNzbmTEIExE5pZdc4jtIw8HZ3ix5Z3z3qamclorbXHSe5hHM6e0pHR5cGWjcGF5"));

        }

        [Test]
        public void PasswordAccountAddressTest()
        {
            var ret = _controller.PasswordAccountAddress("Password123");
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ"));
        }

        [Test]
        public async Task PasswordAccountSignTest()
        {
            var httpClient = HttpClientConfigurator.ConfigureHttpClient("https://testnet-api.algonode.cloud", "aa");
            DefaultApi algodApiInstance = new(httpClient);
            var transParams = await algodApiInstance.TransactionParamsAsync();
            transParams.LastRound = 1;

            var address = new Address("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ");
            var tx1 = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(address, address, 0, "#ARC14", transParams);
            var tx1MessagePack = Algorand.Utils.Encoder.EncodeToMsgPackOrdered(tx1);

            var ret = _controller.PasswordAccountSign("Password123", tx1MessagePack);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = Convert.ToBase64String(result.Value as byte[]);

            Assert.That(resultObj, Is.EqualTo("gqNzaWfEQJjAdWQPV0Rk5iKFXOT0mIsvdABNMeCD1CqtrJVOML+A3POht7KD7IrxvJswU4rurhC/nCvZA47TvbTyDgHWxwijdHhuiaNmZWXNA+iiZnYBo2dlbqx0ZXN0bmV0LXYxLjCiZ2jEIEhjtRiks8hOyBDyLU8QgcsPcfBZp6wg3sYvf3DlCToiomx2zQPppG5vdGXEBiNBUkMxNKNyY3bEIAyTld7742VktEiENDVAvjFQm51oPdJSKXEgmKiVK/H8o3NuZMQgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fykdHlwZaNwYXk="));
        }

        [Test]
        public void MyAddressTest()
        {
            var ret = _controller.MyAddress();
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo(primaryAccount));
        }
        [Test]
        public void TestValidateTwoFactorPINTest()
        {
            var ret = _controller.SetupAuthenticator("title", secondaryAccount);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.That(resultObj, Is.Not.Null);


            var key = MultisigController.ComputeSHA256Hash($"{twoFaAccount}-{secret}");
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);
            var retPinVerify = _controller.TestValidateTwoFactorPIN(pin, secondaryAccount);
            var resultPinVerify = retPinVerify.Result as OkObjectResult;
            Assert.That(resultPinVerify, Is.Not.Null);
            var resultObjPinVerify = Convert.ToBoolean(resultPinVerify.Value);
            Assert.That(resultObjPinVerify, Is.True);

        }
        [Test]
        public void TestValidateTwoFactorWrongPINTest()
        {
            var ret = _controller.SetupAuthenticator("title", secondaryAccount);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.That(resultObj, Is.Not.Null);


            var key = MultisigController.ComputeSHA256Hash($"BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ-{secret}");
            TwoFactorAuthenticator tfa = new();
            if (true)
            {
                var pin = tfa.GetCurrentPIN(key);
                var num = Convert.ToUInt64(pin);
                var wrongPin = (++num).ToString();
                var retPinVerify = _controller.TestValidateTwoFactorPIN(wrongPin, secondaryAccount);
                var resultPinVerify = retPinVerify.Result as OkObjectResult;
                Assert.That(resultPinVerify, Is.Not.Null);
                var resultObjPinVerify = Convert.ToBoolean(resultPinVerify.Value);
                Assert.That(resultObjPinVerify, Is.False);
            }
            // even after the pin is entered correctly within 60 seconds after invalid pin, the result must be negative
            if (true)
            {
                var pin = tfa.GetCurrentPIN(key);
                var retPinVerify = _controller.TestValidateTwoFactorPIN(pin, secondaryAccount);
                var resultPinVerify = retPinVerify.Result as OkObjectResult;
                Assert.That(resultPinVerify, Is.Not.Null);
                var resultObjPinVerify = Convert.ToBoolean(resultPinVerify.Value);
                Assert.That(resultObjPinVerify, Is.False);
            }
        }

        [Test]
        public async Task MsigTest()
        {
            var ALGOD_API_ADDR = "https://testnet-api.algonode.cloud/";
            var ALGOD_API_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

            // This boilerplate creates an Account object with a private key represented by a mnemnonic.
            //
            //   If using Sandbox, please use the following commands to replace the below mnemonic:
            //   ./sandbox goal account list
            //   ./sandbox goal account export -a <address>
            var acc1 = new Algorand.Algod.Model.Account("gravity maid again grass ozone execute exotic vapor fringe snack club monitor where jar pyramid receive tattoo science scene high sound degree bless above good");
            var acc2 = new Algorand.Algod.Model.Account("move sell junior vast verb stove bracket filter place child fame bone story science miss injury put cancel already session cheap furnace void able minimum");
            var acc3 = new Algorand.Algod.Model.Account("pencil ostrich net alpha need vivid elevator gadget bundle meadow flash hamster pig young ten clown before grace arch tennis absent knock peanut ability alarm");
            var randomAccount = new Algorand.Algod.Model.Account();

            var httpClient = HttpClientConfigurator.ConfigureHttpClient(ALGOD_API_ADDR, ALGOD_API_TOKEN);
            var algodApiInstance = new DefaultApi(httpClient);

            // A multisig address is the hash of the following information
            // Note that the second argument (2) means in this case "2 of 3 signatures are required"
            var multiAddress = new MultisigAddress(1, 2, new List<byte[]> { acc1.Address.Bytes, acc2.Address.Bytes, acc3.Address.Bytes });

            // Send *to* the multisig address
            var transParams = await algodApiInstance.TransactionParamsAsync();
            var payment = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(acc1.Address, multiAddress.ToAddress(), 100000, "to multsig", transParams);
            var signedTx = payment.Sign(acc1);
            var tx = await Utils.SubmitTransaction(algodApiInstance, signedTx);
            await Utils.WaitTransactionToComplete(algodApiInstance, tx.Txid);

            // now to send *from* the multi-address we need a certain number of signatures specified by the threshold
            transParams = await algodApiInstance.TransactionParamsAsync();
            var payment2 = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(multiAddress.ToAddress(), randomAccount.Address, 100000, "from multisig", transParams);

            // sign with 2 addresses (2 of 3 threshold)
            var signedTx1 = payment2.Sign(multiAddress, acc1);
            var signedTx2 = payment2.Sign(multiAddress, acc2);
            signedTx = SignedTransaction.MergeMultisigTransactions(signedTx1, signedTx2);

            tx = await Utils.SubmitTransaction(algodApiInstance, signedTx);
            var result = await Utils.WaitTransactionToComplete(algodApiInstance, tx.Txid);
            Assert.That(result, Is.Not.Null);
            // now let's check the account received the amount
            var accountInfo = await algodApiInstance.AccountInformationAsync(randomAccount.Address.ToString(), null, null);
            Console.WriteLine($"For account address {randomAccount.Address} the account balance is {accountInfo.Amount}");
        }


        [Test]
        public void ConfirmSetupAuthenticatorTest()
        {
            var ret = _controller.SetupAuthenticator("title", secondaryAccount);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.That(resultObj, Is.Not.Null);


            var key = MultisigController.ComputeSHA256Hash($"{twoFaAccount}-{secret}");
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);

            var confirmRet = _controller.ConfirmSetupAuthenticator(pin, secondaryAccount);
            var confirmResult = confirmRet.Result as OkObjectResult;
            Assert.That(confirmResult, Is.Not.Null);

            // second attempt must fail because the storage is there 
            ret = _controller.SetupAuthenticator("title", secondaryAccount);
            result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Null);

            confirmRet =  _controller.ConfirmSetupAuthenticator(pin, secondaryAccount); 
            confirmResult = confirmRet.Result as OkObjectResult;
            Assert.That(confirmResult, Is.Null);

        }

    }
}