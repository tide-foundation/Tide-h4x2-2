using H4x2_Node.Controllers;
using H4x2_Node.Entities;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using H4x2_TinySDK.Tools;
using System.Numerics;
using System.Runtime;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace H4x2_Node.Flows
{
    public class Create
    {
        public static CreatePrismResponse Prism(string uid, Point point, BigInteger orkPrivate)
        {
            BigInteger prism = Utils.RandomBigInt();
            Point applied = PRISM.Apply(point, prism);

            CreatePrismState state = new CreatePrismState
            {
                Prism = prism.ToString(),
                UID = uid
            };

            string encryptedState = AES.Encrypt(JsonSerializer.Serialize(state), orkPrivate);

            CreatePrismResponse response = new CreatePrismResponse
            {
                point = applied.ToBase64(),
                encryptedState = encryptedState
            };
            return response;
        }

        public static (User, CreateAccountResponse) Account(string uid_claim, string encryptedState, Point prismPub, Key orkKey)
        {
            CreatePrismState? state = JsonSerializer.Deserialize<CreatePrismState>(AES.Decrypt(encryptedState, orkKey.Priv));

            if (!state.UID.Equals(uid_claim)) throw new Exception("Create Account: UID claims does not equal that inside of AuthData");

            BigInteger CVK = Utils.RandomBigInt();
            byte[] prismAuthi = SHA256.HashData((prismPub * orkKey.Priv).ToByteArray());
            string encryptedCVK = AES.Encrypt(CVK.ToString(), prismAuthi);

            byte[] toSign = Encoding.ASCII.GetBytes(state.UID);

            string signedUID = orkKey.Sign(toSign);

            User user = new User
            {
                UID = state.UID,
                Prismi = state.Prism,
                CVKi = CVK.ToString(),
                PrismAuthi = Convert.ToBase64String(prismAuthi)
            };

            CreateAccountResponse response = new CreateAccountResponse
            {
                encryptedCVK = encryptedCVK,
                signedUID = signedUID
            };
            return (user, response);
        }
    }

    public class CreatePrismResponse
    {
        public string point { get; set; }
        public string encryptedState { get; set; }
    }
    public class CreateAccountResponse
    {
        public string encryptedCVK { get; set; }
        public string signedUID { get; set; }
    }
    public class CreatePrismState
    {
        public string UID { get; set; } 
        public string Prism { get; set; }
    }
}
