using Algorand2FAMultisig.Controllers;
using Algorand2FAMultisig.Repository.Implementation.Storage;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Algorand2FAMultisigTests
{
    public class StorageTests
    {

        [Test]
        public void TestStorage()
        {
            var configuration = new Mock<Microsoft.Extensions.Configuration.IConfiguration>();
            var logger = new Mock<ILogger<StorageFile>>();
            var storage = new StorageFile(logger.Object, configuration.Object);
            Assert.IsNotNull(storage);
            var acc1 = new Algorand.Algod.Model.Account();
            var acc2 = new Algorand.Algod.Model.Account();
            var acc3 = new Algorand.Algod.Model.Account();


            var getRet = storage.Exists(acc1.Address.EncodeAsString(), acc2.Address.EncodeAsString(), acc3.Address.EncodeAsString());
            Assert.IsFalse(getRet);

            var saveRet = storage.Save(acc1.Address.EncodeAsString(), acc2.Address.EncodeAsString(), acc3.Address.EncodeAsString());
            Assert.IsTrue(saveRet);

            getRet = storage.Exists(acc1.Address.EncodeAsString(), acc2.Address.EncodeAsString(), acc3.Address.EncodeAsString());
            Assert.IsTrue(getRet);


        }
    }
}
