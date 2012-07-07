using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using System.Collections;

namespace ReisJr.BouncyCastle.Utils
{
    public class CertificateUtils
    {
        public static X509Certificate LoadCertificate(string filename)
        {
            X509CertificateParser certParser = new X509CertificateParser();
            FileStream fs = new FileStream(filename, FileMode.Open);
            X509Certificate cert = certParser.ReadCertificate(fs);
            fs.Close();

            return cert;
        }

        public static List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
        {
            List<string> ocspUrls = new List<string>();

            try
            {
                Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }

                // For a strange reason I cannot acess the aia.AccessDescription[].
                // Hope it will be fixed in the next version (1.5).
                // AuthorityInformationAccess aia = AuthorityInformationAccess.GetInstance(obj);
                
                // Switched to manual parse
                Asn1Sequence s = (Asn1Sequence) obj;
                IEnumerator elements = s.GetEnumerator();

                while (elements.MoveNext())
                {
                    Asn1Sequence element = (Asn1Sequence) elements.Current;
                    DerObjectIdentifier oid = (DerObjectIdentifier) element[0];

                    if (oid.Id.Equals("1.3.6.1.5.5.7.48.1")) // Is Ocsp?
                    {
                        Asn1TaggedObject taggedObject = (Asn1TaggedObject)element[1];
                        GeneralName gn = (GeneralName)GeneralName.GetInstance(taggedObject);
                        ocspUrls.Add(((DerIA5String)DerIA5String.GetInstance(gn.Name)).GetString());
                    }
                }
            }
            catch (Exception e)
            {
                throw new Exception("Error parsing AIA.", e);
            }

            return ocspUrls;
        }

        protected static Asn1Object GetExtensionValue(X509Certificate cert,
                string oid)
        {
            if (cert == null)
            {
                return null;
            }

            byte[] bytes = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            Asn1InputStream aIn = new Asn1InputStream(bytes);

            return aIn.ReadObject();
        }

    }
}
