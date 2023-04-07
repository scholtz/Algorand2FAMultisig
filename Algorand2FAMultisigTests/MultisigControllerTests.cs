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

namespace Algorand2FAMultisigTests
{
    public class MultisigControllerTests
    {
        private readonly MultisigController _controller;
        private readonly string secret = "the string you want to return";

        public MultisigControllerTests()
        {
            var configuration = new Mock<Microsoft.Extensions.Configuration.IConfiguration>();
            configuration.SetupGet(x => x["Algo:Mnemonic"]).Returns(secret);
            configuration.SetupGet(x => x["Algo:TwoFactorName"]).Returns("TwoFactorTestName");

            var authUser = "BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ";
            var logger = new Mock<ILogger<MultisigController>>();
            var authApp = new GoogleAuthenticatorApp(configuration.Object);
            _controller = new MultisigController(logger.Object, configuration.Object, authApp, authUser);
        }

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void SetupGoogleAuthenticatorJsonTest()
        {
            var ret = _controller.SetupGoogleAuthenticatorJson("title");
            var result = ret.Result as OkObjectResult;
            Assert.IsNotNull(result);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.IsNotNull(resultObj);
        }

        [Test]
        public async Task SignValidateTwoFactorPINBase64MsgPackTxTest()
        {
            var ret = _controller.SetupGoogleAuthenticatorJson("title");
            var key = MultisigController.ComputeSHA256Hash($"BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ-{secret}");
            var result = ret.Result as OkObjectResult;
            Assert.IsNotNull(result);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.IsNotNull(resultObj);
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);

            var msig = new Algorand2FAMultisig.Model.Multisig()
            {
                Signators = new string[]
                {
                    "BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ",
                    "BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ",
                }
                ,
                Threshold = 2,
                Version = 1
            };
            MultisigAddress multiAddress = new MultisigAddress(1, 2, new List<byte[]> { new Address("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ").Bytes, new Address("BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ").Bytes });
            

            var httpClient = HttpClientConfigurator.ConfigureHttpClient("https://testnet-api.algonode.cloud", "aa");
            DefaultApi algodApiInstance = new DefaultApi(httpClient);
            var transParams = await algodApiInstance.TransactionParamsAsync();
            transParams.LastRound = 1;
            var address = new Address("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ");
            var tx1 = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(multiAddress.ToAddress(), address, 0, "#ARC14", transParams);
            var tx1MessagePack = Convert.ToBase64String(Algorand.Utils.Encoder.EncodeToMsgPackOrdered(tx1));

            var signRet = _controller.PasswordAccountSign("Password123", tx1MessagePack);
            var signResult = signRet.Result as OkObjectResult;
            Assert.That(signResult, Is.Not.Null);
            var signResultObj = signResult.Value?.ToString();
            Assert.That(signResultObj, Is.EqualTo("g6RzZ25yxCAMk5Xe++NlZLRIhDQ1QL4xUJudaD3SUilxIJiolSvx/KNzaWfEQLbzdbslI6Y+YQqX6Fnlzu1aroNG1Cvbf2tEiTCGfniRQTM3yP2SAvm+4eWpUecBm7YyMh9rTcJizI86umuHBg6jdHhuiqNhbXQAo2ZlZc0D6KJmdgGjZ2VurHRlc3RuZXQtdjEuMKJnaMQgSGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiKibHbNA+mkbm90ZcQGI0FSQzE0o3JjdsQgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyjc25kxCDCP9PFlhmbYhVL8kCQqr36kWCS7iMELyXW26vx4OdxG6R0eXBlo3BheQ=="));

            var sign2FARet = _controller.SignValidateTwoFactorPINBase64MsgPackTx(pin, JsonConvert.SerializeObject(msig), signResultObj);
            var sign2FAResult = sign2FARet.Result as OkObjectResult;
            Assert.That(sign2FAResult, Is.Not.Null);
            var sign2FAResultObj = sign2FAResult.Value?.ToString();
            Assert.That(sign2FAResultObj, Is.EqualTo("gqRtc2lng6ZzdWJzaWeSgqJwa8QgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyhc8RAtvN1uyUjpj5hCpfoWeXO7Vqug0bUK9t/a0SJMIZ+eJFBMzfI/ZIC+b7h5alR5wGbtjIyH2tNwmLMjzq6a4cGDoKicGvEIAjQIG4GUjVhR+8MlRMOAEqEefexUK/TBHJyu2KtHLrmoXPEQBJtVmgFdg9hAZwR+P4NAmm0DmSH/3VZjmemmxc/S/pLr352npHPpNLUVcZP4cT6QWd2e0UnbcpHZfiHY0EcTwqjdGhyAqF2AaN0eG6Ko2FtdACjZmVlzQPoomZ2AaNnZW6sdGVzdG5ldC12MS4womdoxCBIY7UYpLPITsgQ8i1PEIHLD3HwWaesIN7GL39w5Qk6IqJsds0D6aRub3RlxAYjQVJDMTSjcmN2xCAMk5Xe++NlZLRIhDQ1QL4xUJudaD3SUilxIJiolSvx/KNzbmTEIMI/08WWGZtiFUvyQJCqvfqRYJLuIwQvJdbbq/Hg53EbpHR5cGWjcGF5"));

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
            DefaultApi algodApiInstance = new DefaultApi(httpClient);
            var transParams = await algodApiInstance.TransactionParamsAsync();
            transParams.LastRound = 1;

            var address = new Address("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ");
            var tx1 = PaymentTransaction.GetPaymentTransactionFromNetworkTransactionParameters(address, address, 0, "#ARC14", transParams);
            var tx1MessagePack = Convert.ToBase64String(Algorand.Utils.Encoder.EncodeToMsgPackOrdered(tx1));

            var ret = _controller.PasswordAccountSign("Password123", tx1MessagePack);
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo("gqNzaWfEQH3U/ohHq2LOYXD/V41/BgDdw3yu+JknjW9fIR5gewcYsKmudgpXOZhgbb/hJXmeQboh/kbnQyj2x2xv9109XAyjdHhuiqNhbXQAo2ZlZc0D6KJmdgGjZ2VurHRlc3RuZXQtdjEuMKJnaMQgSGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiKibHbNA+mkbm90ZcQGI0FSQzE0o3JjdsQgDJOV3vvjZWS0SIQ0NUC+MVCbnWg90lIpcSCYqJUr8fyjc25kxCAMk5Xe++NlZLRIhDQ1QL4xUJudaD3SUilxIJiolSvx/KR0eXBlo3BheQ=="));
        }

        [Test]
        public void MyAddressTest()
        {
            var ret = _controller.MyAddress();
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo("BSJZLXX34NSWJNCIQQ2DKQF6GFIJXHLIHXJFEKLRECMKRFJL6H6MY4ZJXQ"));
        }
        [Test]
        public void GetAddressTest()
        {
            var ret = _controller.GetAddress();
            var result = ret.Result as OkObjectResult;
            Assert.That(result, Is.Not.Null);
            var resultObj = result.Value?.ToString();
            Assert.That(resultObj, Is.EqualTo("BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ"));
        }
        [Test]
        public void TestValidateTwoFactorPINTest()
        {
            var ret = _controller.SetupGoogleAuthenticatorJson("title");
            var result = ret.Result as OkObjectResult;
            Assert.IsNotNull(result);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.IsNotNull(resultObj);


            var key = MultisigController.ComputeSHA256Hash($"BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ-{secret}");
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);
            var retPinVerify = _controller.TestValidateTwoFactorPIN(pin);
            var resultPinVerify = retPinVerify.Result as OkObjectResult;
            Assert.IsNotNull(resultPinVerify);
            var resultObjPinVerify = Convert.ToBoolean(resultPinVerify.Value);
            Assert.That(resultObjPinVerify, Is.True);

        }
        [Test]
        public void TestValidateTwoFactorWrongPINTest()
        {
            var ret = _controller.SetupGoogleAuthenticatorJson("title");
            var result = ret.Result as OkObjectResult;
            Assert.IsNotNull(result);
            var resultObj = result.Value as Algorand2FAMultisig.Model.SetupReturn;
            Assert.IsNotNull(resultObj);


            var key = MultisigController.ComputeSHA256Hash($"BDICA3QGKI2WCR7PBSKRGDQAJKCHT55RKCX5GBDSOK5WFLI4XLTAALXTMQ-{secret}");
            TwoFactorAuthenticator tfa = new();
            var pin = tfa.GetCurrentPIN(key);
            var num = Convert.ToUInt64(pin);
            var wrongPin = (++num).ToString();
            var retPinVerify = _controller.TestValidateTwoFactorPIN(wrongPin);
            var resultPinVerify = retPinVerify.Result as OkObjectResult;
            Assert.IsNotNull(resultPinVerify);
            var resultObjPinVerify = Convert.ToBoolean(resultPinVerify.Value);
            Assert.That(resultObjPinVerify, Is.False);

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
            DefaultApi algodApiInstance = new DefaultApi(httpClient);

            // A multisig address is the hash of the following information
            // Note that the second argument (2) means in this case "2 of 3 signatures are required"
            MultisigAddress multiAddress = new MultisigAddress(1, 2, new List<byte[]> { acc1.Address.Bytes, acc2.Address.Bytes, acc3.Address.Bytes });

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

            // now let's check the account received the amount
            var accountInfo = await algodApiInstance.AccountInformationAsync(randomAccount.Address.ToString(), null, null);
            Console.WriteLine($"For account address {randomAccount.Address} the account balance is {accountInfo.Amount}");
        }
    }
}