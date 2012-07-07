using System;
using System.IO;
using System.Collections;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.OpenSsl;

namespace ReisJr.BouncyCastle.Examples
{
    public class SignatureInfo2
    {
        static CmsSignedData ReadPem(String filename)
        {
            StreamReader sR = new StreamReader(filename);
            PemReader pR = new PemReader(sR);

            Org.BouncyCastle.Asn1.Cms.ContentInfo cI = (Org.BouncyCastle.Asn1.Cms.ContentInfo) pR.ReadObject();

            sR.Close();

            CmsSignedData cms = new CmsSignedData(cI);

            return cms;
        }

        static X509Certificate ReadCertificate(String filename)
        {
            X509CertificateParser certParser = new X509CertificateParser();

            Stream stream = new FileStream(filename, FileMode.Open);
            X509Certificate cert = certParser.ReadCertificate(stream);
            stream.Close();
            
            return cert;
        }

        static String ToHexString(byte[] byteArray)
        {
            byte[] hexEncodedArray = Org.BouncyCastle.Utilities.Encoders.Hex.Encode(
                byteArray, 0, byteArray.Length);
            String hexEncoded = Encoding.Default.GetString(hexEncodedArray);

            return hexEncoded;
        }

        static void Asn1Print(byte[] encoded)
        {
            Asn1Sequence seq = (Asn1Sequence)Asn1Sequence.FromByteArray(encoded);
            Console.WriteLine(Org.BouncyCastle.Asn1.Utilities.Asn1Dump.DumpAsString(seq));
        }

        static void Main(string[] args)
        {
            CmsSignedData cms = ReadPem("..\\..\\signed.pem");            
            
            SignerInformationStore signerStore = cms.GetSignerInfos();
            
            // Get included certificates
            IX509Store cmsCertificates = cms.GetCertificates("Collection");

            ICollection signers = signerStore.GetSigners();

            foreach (SignerInformation signer in signers)
            {                
                X509Certificate cert = GetCertificate(signer, cmsCertificates);

                // Need to call Verify() first to use GetContentDigest()                
                bool valid = signer.Verify(cert);

                Console.WriteLine("Is Signature Valid ? " + valid);
                Console.WriteLine("Digest: " + ToHexString(signer.GetContentDigest()).ToUpper());
                Console.WriteLine("Enc Alg Oid: " + signer.EncryptionAlgOid);
                Console.WriteLine("Digest Alg Oid: " + signer.DigestAlgorithmID.ObjectID);
                Console.WriteLine("Signature: " + ToHexString(signer.GetSignature()).ToUpper());

                Console.WriteLine("\nSigner Info: \n");

                Asn1Print(signer.ToSignerInfo().GetDerEncoded());
            }

            Console.ReadLine();
        }

        private static X509Certificate GetCertificate(SignerInformation signer, IX509Store cmsCertificates)
        {
            X509Certificate cert = null;

            // Create a selector with the information necessary to 
            // find the signer certificate          
            X509CertStoreSelector sel = new X509CertStoreSelector();
            sel.Issuer = signer.SignerID.Issuer;
            sel.SerialNumber = signer.SignerID.SerialNumber;

            // Try find a match
            IList certificatesFound = new ArrayList( cmsCertificates.GetMatches(sel) );

            if (certificatesFound.Count > 0) // Match found
            {
                // Load certificate from CMS

                Console.WriteLine("Loading signer's certificate from CMS...");

                cert = (X509Certificate)certificatesFound[0];
            }
            else 
            {
                // Load certificate from file

                Console.WriteLine("Loading signer's certificate from file...");
                
                ReadCertificate("..\\..\\example.cer");
            }
            return cert;
        }
    }
}
