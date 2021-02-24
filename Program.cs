using System;
using System.Drawing;
using System.Globalization;
using System.Net.Mime;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using libsignal;
using libsignal.ecc;
using libsignal.util;
using libsignalservice.configuration;
using libsignalservice.util;
using ZXing;

namespace SignalPhoneDummy
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Private information, only known to owner
            const string ikPrivate = "<insert private IK (hex)>";
            const string ikPublic = "<insert public IK (hex)>";
            const string profile = null; // Optional (may be null), only affects fetching of profile info
            
            // Known by server
            const string number = "<insert full phone number, e.g. +123456789>";
            const string username = "<insert API username (some GUID-like string)>";
            const string password = "<insert API password>";
            
            // OWA for the phone, OWD for the desktop client
            const string userAgent = "OWA";
            
            // Defaults to 1 for the primary phone
            const int deviceId = 1;

            var man = new libsignalservice.SignalServiceAccountManager(
                new SignalServiceConfiguration(new SignalServiceUrl[] { new SignalServiceUrl("https://textsecure-service.whispersystems.org") }, null),
                username,
                password,
                deviceId,
                userAgent,
                number
            );

            // Load keys
            var ikPriv = new DjbECPrivateKey(ConvertHexStringToByteArray(ikPrivate));
            var ikPub = new IdentityKey(new DjbECPublicKey(ConvertHexStringToByteArray(ikPublic)));
            var ik = new IdentityKeyPair(ikPub, ikPriv);
            var prof = profile != null ? ConvertHexStringToByteArray(profile) : null;

            // Parse QR code
            Console.Write("Enter path for QR code image: ");
            string qrPath = Console.ReadLine();
            var reader = new BarcodeReader();
            var qrData = reader.Decode((Bitmap)Image.FromFile(qrPath));
            var match = Regex.Match(qrData.Text, "tsdevice:/\\?uuid=(.*?)&pub_key=(.*)");
            
            string uuid = match.Groups[1].Value;
            string provKey = match.Groups[2].Value.Replace("%2B", "+").Replace("%2F", "/");
            
            var provKeyBytes = Base64.Decode(provKey);
            if(provKeyBytes.Length == 33)
                provKeyBytes = ByteUtil.split(provKeyBytes, 1, 32)[1];
            var prov = new DjbECPublicKey(provKeyBytes);

            // Run device registration protocol
            string code = await man.GetNewDeviceVerificationCode(CancellationToken.None);
            await man.AddDevice(CancellationToken.None, uuid, prov, ik, prof, code);
        }
        
        static byte[] ConvertHexStringToByteArray(string hexString)
        {
            byte[] data = new byte[hexString.Length / 2];
            for(int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            if(data.Length == 33)
            {
                return ByteUtil.split(data, 1, 32)[1];
            }
            return data;
        }
    }
}