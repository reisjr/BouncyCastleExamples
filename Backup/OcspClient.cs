using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using ReisJr.BouncyCastle.Utils;

namespace ReisJr.BouncyCastle.Examples
{
    public class OcspClient
    {
        public enum CertificateStatus { Good, Revoked, Unknown };

        private readonly int MaxClockSkew = 36000000;

        public CertificateStatus Query(X509Certificate eeCert, X509Certificate issuerCert)
        {        
            // Query the first Ocsp Url found in certificate
            List<string> urls = CertificateUtils.GetAuthorityInformationAccessOcspUrl(eeCert);

            if (urls.Count == 0)
            {
                throw new Exception("No OCSP url found in ee certificate.");
            }

            string url = urls[0];

            Console.WriteLine("Querying '" + url + "'...");

            OcspReq req = GenerateOcspRequest(issuerCert, eeCert.SerialNumber);
            
            byte[] binaryResp = IoUtils.PostData(url, req.GetEncoded(), "application/ocsp-request", "application/ocsp-response");

            return ProcessOcspResponse(eeCert, issuerCert, binaryResp);
        }

        private CertificateStatus ProcessOcspResponse(X509Certificate eeCert, X509Certificate issuerCert, byte[] binaryResp)
        {
            OcspResp r = new OcspResp(binaryResp);
            CertificateStatus cStatus = CertificateStatus.Unknown;

            switch (r.Status)
            {
                case OcspRespStatus.Successful:
                    BasicOcspResp or = (BasicOcspResp)r.GetResponseObject();

                    ValidateResponse(or, issuerCert);

                    if (or.Responses.Length == 1)
                    {
                        SingleResp resp = or.Responses[0];

                        ValidateCertificateId(issuerCert, eeCert, resp.GetCertID());
                        ValidateThisUpdate(resp);
                        ValidateNextUpdate(resp);

                        Object certificateStatus = resp.GetCertStatus();

                        if (certificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            cStatus = CertificateStatus.Good;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            cStatus = CertificateStatus.Revoked;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            cStatus = CertificateStatus.Unknown;
                        }
                    }
                    break;
                default:
                    throw new Exception("Unknow status '" + r.Status + "'.");
            }

            return cStatus;
        }

        private void ValidateResponse(BasicOcspResp or, X509Certificate issuerCert)
        {
            ValidateResponseSignature(or, issuerCert.GetPublicKey());
            ValidateSignerAuthorization(issuerCert, or.GetCerts()[0]);  
        }

        //3. The identity of the signer matches the intended recipient of the
        //request.
        //4. The signer is currently authorized to sign the response.
        private void ValidateSignerAuthorization(X509Certificate issuerCert, X509Certificate signerCert)
        {
            // This code just check if the signer certificate is the same that issued the ee certificate
            // See RFC 2560 for more information
            if (!(issuerCert.IssuerDN.Equivalent(signerCert.IssuerDN) && issuerCert.SerialNumber.Equals(signerCert.SerialNumber)))
            {
                throw new Exception("Invalid OCSP signer");
            }
        }

        //2. The signature on the response is valid;
        private void ValidateResponseSignature(BasicOcspResp or, Org.BouncyCastle.Crypto.AsymmetricKeyParameter asymmetricKeyParameter)
        {
            if (!or.Verify(asymmetricKeyParameter))
            {
                throw new Exception("Invalid OCSP signature");
            }
        }

        //6. When available, the time at or before which newer information will
        //be available about the status of the certificate (nextUpdate) is
        //greater than the current time.
        private void ValidateNextUpdate(SingleResp resp)
        {
            if( resp.NextUpdate != null && resp.NextUpdate.Value != null && resp.NextUpdate.Value.Ticks <= DateTime.Now.Ticks) {
                throw new Exception("Invalid next update.");
             }
        }

        //5. The time at which the status being indicated is known to be
        //correct (thisUpdate) is sufficiently recent.
        private void ValidateThisUpdate(SingleResp resp)
        {
            if (Math.Abs(resp.ThisUpdate.Ticks - DateTime.Now.Ticks) > MaxClockSkew)
            {
                throw new Exception("Max clock skew reached.");
            }
        }

        //1. The certificate identified in a received response corresponds to
        //that which was identified in the corresponding request;
        private void ValidateCertificateId(X509Certificate issuerCert, X509Certificate eeCert, CertificateID certificateId)
        {
            CertificateID expectedId = new CertificateID(CertificateID.HashSha1, issuerCert, eeCert.SerialNumber);

            if (!expectedId.SerialNumber.Equals(certificateId.SerialNumber))
            {
                throw new Exception("Invalid certificate ID in response");
            }

            if (!Org.BouncyCastle.Utilities.Arrays.AreEqual(expectedId.GetIssuerNameHash(), certificateId.GetIssuerNameHash()))
            {
                throw new Exception("Invalid certificate Issuer in response");
            }
            
        }

        private OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
        {
            CertificateID id = new CertificateID(CertificateID.HashSha1, issuerCert, serialNumber);
            return GenerateOcspRequest(id);
        }

        private OcspReq GenerateOcspRequest(CertificateID id)
        {
            OcspReqGenerator ocspRequestGenerator = new OcspReqGenerator();

            ocspRequestGenerator.AddRequest(id);

            BigInteger nonce = BigInteger.ValueOf(new DateTime().Ticks);

            ArrayList oids = new ArrayList();
            Hashtable values = new Hashtable();
            
            oids.Add(OcspObjectIdentifiers.PkixOcsp);
            
            Asn1OctetString asn1 = new DerOctetString(new DerOctetString(new byte[] { 1, 3, 6, 1, 5, 5, 7, 48, 1, 1 }));
            
            values.Add(OcspObjectIdentifiers.PkixOcsp, new X509Extension(false, asn1));
            ocspRequestGenerator.SetRequestExtensions(new X509Extensions(oids, values));

            return ocspRequestGenerator.Generate();
        }

    }
}
