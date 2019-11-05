using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace XMLPractice
{
    class Program
    {
        static void Main(string[] args)
        {
            var currDir = Directory.GetCurrentDirectory();
            var inputXMLsDirectory = Path.GetFullPath(Path.Combine(currDir, @"..\..\..\", "XMLDocstosign"));
            bool success = LoadXmlFiles(inputXMLsDirectory);
            string outputPath;

            string methodName = "uploadFile";
            MakeWebServiceCall(methodName, "C:\\Users\\GR-002\\Desktop\\efakturafile\\BG130441375_9800000000_20121122_signed.xml");

            if (success)
            {
                outputPath = ZipFiles(inputXMLsDirectory);
            }


        }

        private static void MakeWebServiceCall(string methodName, string attachmentName)
        {

            var url = "https://demo.efaktura.bg/soap/billerFiles.php";
            var action = "uploadFile";

            //Create Soap Envelope
            XmlDocument soapEnvelopeXml = CreateSoapEnvelope(attachmentName);
            HttpWebRequest webRequest = CreateWebRequest(url, action, attachmentName);
            InsertSoapEnvelopeIntoWebRequest(soapEnvelopeXml, webRequest);
            // begin async call to web request.

            using (HttpWebResponse response = (HttpWebResponse)webRequest.GetResponse())
            {
                using (StreamReader rd = new StreamReader(response.GetResponseStream()))
                {
                    string soapResult = rd.ReadToEnd();
                    Console.WriteLine(soapResult);
                }
            }


        }

        private static HttpWebRequest CreateWebRequest(string url, string action, string attachmentName)
        {
            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(url);

            webRequest.Method = "POST";
            //this is to include mime types(attachments)
            webRequest.ContentType = "multipart/related;type=text/xml; boundary=---------------------------7da24f2e50046";
            webRequest.Date = DateTime.UtcNow;
            webRequest.Accept = "text/xml";
            webRequest.Headers.Add(@"SOAPAction", action);
            webRequest.Headers.Add("Content-Disposition: attachment");
            webRequest.Headers.Add("Content-Transfer-Encoding: base64");
            //encoded file content
            var fileCont = "cid:" + EncodeZipContentToBase64(attachmentName);
            webRequest.Headers.Add($"Content-ID:{fileCont}");

            return webRequest;
        }

        private static XmlDocument CreateSoapEnvelope(string attachmentName)
        {
            //Convert name to base64
            var fileNameEncoded = EncodeStringToBase64(attachmentName);
            var authorizationIdEncoded = EncodeStringToBase64("C61582-B73K47EJ54");
            var authorizationKeyEncoded = EncodeStringToBase64("TWTXBP-HNEZ9J-74EV8Z-QM5J9T");
            XmlDocument soapEnvelopeDocument = new XmlDocument();
            soapEnvelopeDocument.LoadXml($@"<?xml version=""1.0"" encoding=""UTF-8""?><SOAP-ENV:Envelope xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:SOAP-ENC=""http://schemas.xmlsoap.org/soap/encoding/"" SOAP-ENV:encodingStyle=""http://schemas.xmlsoap.org/soap/encoding/"" xmlns:ns4=""https://efaktura.bg/soap/""><SOAP-ENV:Body><ns4:uploadFile><ns4:authorizationId>{authorizationIdEncoded}</ns4:authorizationId><ns4:authorizationKey>{authorizationKeyEncoded}</ns4:authorizationKey><ns4:fileName>{fileNameEncoded}</ns4:fileName></ns4:uploadFile></SOAP-ENV:Body></SOAP-ENV:Envelope>");
            //            doc.LoadXml(soapRequest.ToString());
            return soapEnvelopeDocument;
        }

        private static void InsertSoapEnvelopeIntoWebRequest(XmlDocument soapEnvelopeXml, HttpWebRequest webRequest)
        {
            using (Stream stream = webRequest.GetRequestStream())
            {
                StringWriter sw = new StringWriter();
                XmlTextWriter tx = new XmlTextWriter(sw);
                soapEnvelopeXml.WriteTo(tx);

                string str = sw.ToString();

                Console.WriteLine(soapEnvelopeXml.ToString());
                ASCIIEncoding Encode = new ASCIIEncoding();
                var arr = Encode.GetBytes(EncodeStringToBase64(str));
                stream.Write(arr, 0, arr.Length);
            }
        }

        public static string EncodeStringToBase64(string plainTextBytes)
        {
            var plainText = System.Text.Encoding.UTF8.GetBytes(plainTextBytes);
            return System.Convert.ToBase64String(plainText);
        }

        public static string EncodeZipContentToBase64(string attachmentName)
        {
            using (FileStream fs = new FileStream(attachmentName, FileMode.Open, FileAccess.Read))
            {
                byte[] filebytes = new byte[fs.Length];
                fs.Read(filebytes, 0, Convert.ToInt32(fs.Length));
                return Convert.ToBase64String(filebytes);
            }
        }

        //Generate xml based on the C# object from the database
        public static bool LoadXmlFiles(string targetDirectory)
        {
            bool success = true;
            // Process the list of files found in the directory.
            //We assume files are of type.xml in the folder
            try
            {

                string[] fileEntries = Directory.GetFiles(targetDirectory);

                var certificate = GetDefaultCertificateStoredOnTheCard();

                foreach (string fileName in fileEntries)
                {
                    try
                    {
                        XmlDocument xmlDoc = new XmlDocument();
                        xmlDoc.PreserveWhitespace = true;
                        xmlDoc.Load(fileName);
                        SignXmlDocumentWithCertificate(xmlDoc, certificate);
                        //  Console.WriteLine($"{fileName} XML file signed.");
                        var currDir2 = Directory.GetCurrentDirectory();
                        var threedirectories = Path.GetFullPath(Path.Combine(currDir2, @"..\..\..\XMLDocstosign\SignedDocs"));
                        var lastIndex = fileName.LastIndexOf("\\");
                        var newFileName = fileName.Substring(lastIndex, fileName.Length - lastIndex - 4);
                        var xmlsignedDoc = threedirectories + newFileName + "_signed.xml";
                        Console.WriteLine(xmlsignedDoc);
                        //   Console.WriteLine(xmlsignedDoc);
                        xmlDoc.Save(xmlsignedDoc);

                        success = true;
                    }

                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        success = false;
                    }
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                success = false;
            }

            return success;
        }

        public static void SignXmlDocumentWithCertificate(XmlDocument xmlDoc, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(xmlDoc);
            //we will sign it with private key
            signedXml.SigningKey = cert.PrivateKey;

            if (cert.PrivateKey == null)
            {
                throw new ArgumentException("Please make sure the application for electronic signatures is installed, so the private key can be obtained from the smart card!");
            }
            Reference reference = new Reference();
            //sign the entire doc
            reference.Uri = "";
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            signedXml.AddReference(reference);

            //PublicKey part
            RSACryptoServiceProvider rsaprovider = (RSACryptoServiceProvider)cert.PublicKey.Key;
            RSAKeyValue rkv = new RSAKeyValue(rsaprovider);


            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            //We add the public key here
            keyInfo.AddClause(rkv);

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
        }

        public static X509Certificate2 GetDefaultCertificateStoredOnTheCard()
        {
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, true);

            // by thumbprint, there is only one
            certs = certs.Find(X509FindType.FindByThumbprint, "6BB4F9D483206F44A992799541114536579CF2B3", true);

            if (certs.Count == 0)
            {
                throw new ArgumentException("Please insert smart card to obtain certificate.");
            }
            X509Certificate2 cert = certs[0];

            RSACryptoServiceProvider key;

            if (cert.HasPrivateKey)
            {
                // software cert
                key = cert.PrivateKey as RSACryptoServiceProvider;

            }
            else
            {
                // certificate from smartcard
                CspParameters csp = new CspParameters(1, "Microsoft Base Smart Card Crypto Provider");
                csp.Flags = CspProviderFlags.UseDefaultKeyContainer;
                key = new RSACryptoServiceProvider(csp);
            }

            return cert;
        }

        public static string ZipFiles(string inputXMLsDirectory)
        {
            string extractPath = inputXMLsDirectory + @"\..\results.zip";
            var signedDocsFolder = inputXMLsDirectory + @".\SignedDocs";

            int fileCount = Directory.GetFiles(signedDocsFolder).Length;

            if (fileCount > 2)
            {
                try
                {
                    ZipFile.CreateFromDirectory(signedDocsFolder, extractPath);
                }
                catch (IOException)
                {
                    Console.WriteLine("Zip file has already been created. Please delete file if you want to make a new one.");
                }
                return extractPath;
            }
            else
            {
                return signedDocsFolder;
            }
        }
    }
}
