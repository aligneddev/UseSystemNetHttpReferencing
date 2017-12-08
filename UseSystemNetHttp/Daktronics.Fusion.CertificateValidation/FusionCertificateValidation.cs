using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// ReSharper disable once CheckNamespace
namespace Daktronics.Fusion
{
	public static class FusionCertificateValidation
	{
		private static readonly X509Certificate2[] DaktronicsFusionCertificateAuthorityPublicCertificates =
		{
			new X509Certificate2(Encoding.UTF8.GetBytes(DaktronicsFusionCAPublicCertificate)), // Daktronics Fusion CA certificate (uses SHA1 for signature algorithm)
			new X509Certificate2(Encoding.UTF8.GetBytes(DaktronicsFusionCA2PublicCertificate)) // Daktronics Fusion CA 2 certificate (uses SHA256 for signature algorithm)
		};

		private static readonly HashSet<string> DaktronicsFusionCertificateAuthorityThumbprints =
			new HashSet<string>(
				DaktronicsFusionCertificateAuthorityPublicCertificates.Select(certificate => certificate.Thumbprint),
				StringComparer.OrdinalIgnoreCase);

		private static readonly ConcurrentDictionary<string, X509ChainStatusFlags> CertificateValidationCache =
			new ConcurrentDictionary<string, X509ChainStatusFlags>();

		/// <summary>
		/// Custom server SSL certificate validation callback method to trust certificates issued by the
		/// Daktronics Fusion root certificate authority
		/// </summary>
		public static bool ServicePointManager_ServerCertificateValidationCallback(object sender,
			X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
		{
			var serverCertificate = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

			// SSL error flag not handled by this callback is the RemoteCertificateNotAvailable flag;
			// return false immediately if it is specified
			if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
				return false;

			// If the SSL error flags contains the RemoteCertificateNameMismatch flag, attempt to handle it here;
			// because .NET doesn't automatically check the request URI host against IP addresses in
			// the subject alternative names certificate extension, check the host against the IP addresses here
			if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch)
			    && sender is WebRequest webRequest
			    && SubjectAlternativeNames.FromCertificate(serverCertificate).IPAddresses.Contains(webRequest.RequestUri.Host))
			{
				// Remove the Certificate name mismatch error flag from the SSL error flags if the request URI host
				// matches an IP address in the subject alternative names extension
				sslPolicyErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
			}

			// Since the only other SSL error flag handled by this callback is the RemoteCertificateChainErrors flag,
			// if different error flags remain, return false (since this callback won't be able to handle them);
			// if no error flags remain, return true (the certificate is valid)
			if (sslPolicyErrors != SslPolicyErrors.RemoteCertificateChainErrors)
				return sslPolicyErrors == SslPolicyErrors.None;

			return ValidateCertificate(serverCertificate, out var _);
		}

		private const X509ChainStatusFlags ChainStatusFlagsToIgnore = X509ChainStatusFlags.RevocationStatusUnknown |
		                                                              X509ChainStatusFlags.OfflineRevocation;

		public static bool ValidateCertificate(X509Certificate2 certificate, out X509ChainStatusFlags chainStatusFlags)
		{
			if (certificate == null) throw new ArgumentNullException(nameof(certificate));

			var thumbprint = certificate.Thumbprint;

			// If the result of previous validation has been cached, return it
			// ReSharper disable once AssignNullToNotNullAttribute
			if (CertificateValidationCache.TryGetValue(thumbprint, out chainStatusFlags))
				return chainStatusFlags == X509ChainStatusFlags.NoError;

			var certificateChain = new X509Chain
			{
				ChainPolicy =
				{
					RevocationFlag = X509RevocationFlag.EntireChain
				}
			};
			certificateChain.ChainPolicy.ExtraStore.AddRange(DaktronicsFusionCertificateAuthorityPublicCertificates);
			certificateChain.Build(certificate);

			// Certificate is considered valid if all the certificate chain elements either contain only ignored flags
			// or the chain element certificate's thumbprint matches the thumbprint of a Fusion root CA certificate
			chainStatusFlags =
				certificateChain.ChainElements.Cast<X509ChainElement>()
					.Where(
						chainElement =>
							!DaktronicsFusionCertificateAuthorityThumbprints.Contains(chainElement.Certificate.Thumbprint))
					.Select(
						chainElement =>
							chainElement.ChainElementStatus.Aggregate(X509ChainStatusFlags.NoError,
								(statusFlags, status) => statusFlags | status.Status)
							& ~ChainStatusFlagsToIgnore)
					.FirstOrDefault(statusFlags => statusFlags != X509ChainStatusFlags.NoError);

			// Cache the validation result
			CertificateValidationCache.TryAdd(thumbprint, chainStatusFlags);

			return chainStatusFlags == X509ChainStatusFlags.NoError;
		}

		// ReSharper disable once InconsistentNaming
		private const string DaktronicsFusionCAPublicCertificate =
@"-----BEGIN CERTIFICATE-----
MIIFLTCCA5WgAwIBAgIJAKJ4IlR5rRVAMA0GCSqGSIb3DQEBBQUAMGwxCzAJBgNV
BAYTAlVTMRUwEwYDVQQIEwxTb3V0aCBEYWtvdGExEjAQBgNVBAcTCUJyb29raW5n
czETMBEGA1UEChMKRGFrdHJvbmljczEdMBsGA1UEAxMURGFrdHJvbmljcyBGdXNp
b24gQ0EwHhcNMTAwMjI1MTcwNDM5WhcNNDAwMjE4MTcwNDM5WjBsMQswCQYDVQQG
EwJVUzEVMBMGA1UECBMMU291dGggRGFrb3RhMRIwEAYDVQQHEwlCcm9va2luZ3Mx
EzARBgNVBAoTCkRha3Ryb25pY3MxHTAbBgNVBAMTFERha3Ryb25pY3MgRnVzaW9u
IENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAlZkgKrmdguMRjUsf
biHUQKDa3I2wpu2RyKeezekMgjHQoii0texOEdJp6DGCU53haO2oa12WDwU15NMj
wJ6a22pZmFaMYUnCnr9Br7ZSRTcdZN9v5Ig/lc+8xGsVZUKJfsCjV98RszLn/EDr
1lt72myGOBcsauhJfZrcPIvRk57pNUAhDEeUSgeO7e9PMa16KlL1HP/7A/GH464k
qt6q8IsEzaMgdW+c+AtAhXFQlFrZjghSfPIuOIDP0rw3AVNTqIBweYlpe/8JLosT
Z//SUd69Dl6ACbeW9XnP/KJOBHVsbQYBo+icC7Yjw785LkASYUeUThJ/ZUUeXm15
Ybu7/sYaLzlSA8rIFCV94zj9C7QoLYxoi3Vk62lFXQGImNInWUIsRR6el9G6QGfy
r64Et5aMRnQe9XR1RoEx9fesCE2boycSxqMFgpW7NXjJVZbnCNba2DS1TeokvAFz
xjxD+Rsy9uHaXVwzVJDGdmio/Eg0GmQuEHC+mmZmNLhcS1NxAgMBAAGjgdEwgc4w
HQYDVR0OBBYEFFEueKDvSfYM2kHYjFXbZg/1c/92MIGeBgNVHSMEgZYwgZOAFFEu
eKDvSfYM2kHYjFXbZg/1c/92oXCkbjBsMQswCQYDVQQGEwJVUzEVMBMGA1UECBMM
U291dGggRGFrb3RhMRIwEAYDVQQHEwlCcm9va2luZ3MxEzARBgNVBAoTCkRha3Ry
b25pY3MxHTAbBgNVBAMTFERha3Ryb25pY3MgRnVzaW9uIENBggkAongiVHmtFUAw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAYEAWdgb14Ru0QFok8qqzDXv
lddJ27715IYhOnnceO3KIZ5ibafpYWxWK8OZmarvKy2linEHyz2pFvOAwJKjZk8I
popYmjQ0OvySWcKZ+dKURMmzuhz+nneobSQt+nXhYa0zcUesNdGaaeeV9/BG2WgZ
R02m6k4t+V/P4fJcvndib6FRm6enda3lOj4R24F6TYuxSUjZBq1JkLOoe6bINE9R
2N1GkdpKUtIa6OLM9qYE7Yi+WzZp/8TY7gaNtvYavqxz9sLD1M7SHd7n5VhzslN+
tx4VIL5hyaKIUFrnKabSGPVSB0qvaaKh62IN0IgIC/K+eLEV4g6NwpdVjZp2l/We
Cjbtc0Tsci4tCARYeVXLexPwPopx9sHqnm5CixngZ0oS0FWKMkd6NIw1X8he9Y7i
rJmxmcYr8IHkGR1NdQOkDfZmdSe+/gaAiKC2LvLFBHm5iFA1f7kH61PRqROlOY2y
b2ERI++J1lAF1nF8wEf+PzSJeeVcWOQ7h/vyX0hpYhmg
-----END CERTIFICATE-----";

		// ReSharper disable once InconsistentNaming
		private const string DaktronicsFusionCA2PublicCertificate =
@"-----BEGIN CERTIFICATE-----
MIIFsjCCA5qgAwIBAgIJAOshH58sBr3ZMA0GCSqGSIb3DQEBCwUAMG4xCzAJBgNV
BAYTAlVTMRUwEwYDVQQIEwxTb3V0aCBEYWtvdGExEjAQBgNVBAcTCUJyb29raW5n
czETMBEGA1UEChMKRGFrdHJvbmljczEfMB0GA1UEAxMWRGFrdHJvbmljcyBGdXNp
b24gQ0EgMjAeFw0xNzA4MTgxODUyMzVaFw00NzA4MTExODUyMzVaMG4xCzAJBgNV
BAYTAlVTMRUwEwYDVQQIEwxTb3V0aCBEYWtvdGExEjAQBgNVBAcTCUJyb29raW5n
czETMBEGA1UEChMKRGFrdHJvbmljczEfMB0GA1UEAxMWRGFrdHJvbmljcyBGdXNp
b24gQ0EgMjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKhFOaMpuBO7
nIj3A+BTNkn9B69fSuZDPGwvDOkp/lINsRCLjsylyGcZikGHk5ubAP0sz/iy7ZVu
pBbyG6lU9VGjckrXoUVu2FC3T7efFHfBm47Bl/0HhJc73/u9XMgKx4FpazLqbD0w
JUmJufdfWHh6wxsMm7EFw/QikjtSlu8NeLBsbPInH5bUHRmhcUy9LGf78GQrWJ7F
X4PHxP62i3mylPkTjfB9OSysnnC+PF3YbqW2NbhGSXTepaGoMVfRWC9ZEO0PmTzB
S6DDEUoDW/lBiRRYWpFlNdRVCu0yyAKz12XO6FrOCZqR0qPRDecR5+A5RBe2kGuA
ujyXHkwgADFwQgJJtmt7KzhoD/k/SxSylvsilvMP+RgoxgQ3TUnebOAh4LqFK4yS
Eu518ne9iHZGXIrgRY7C0wsRmecsvHJj2jcsEX1BcuQxw4cy7n//kP6CxA6qp+S4
50rLu8aiwz3/V531AWAPwIFZauosYsEEjPN0vfQQ2MzY2aB3FyTK9wegplkLlU3T
QZWRvd4H5BJCfOqPD8+T02cfUKE/nzaR7jAuhoTfcIx1ywg8mDrOl1aohZ331Gto
8GMkS9SRoKNiyeyiRLOv7WqZfEAIrukVljoBHsL5wo4nXUlL3+3o/t6gEDPng7iU
pQkVXgQx6bFgjx4aCeFt+nsHaDy3iGptAgMBAAGjUzBRMB0GA1UdDgQWBBSxmyzI
AF651bDFft4t53RN8AiW0TAfBgNVHSMEGDAWgBSxmyzIAF651bDFft4t53RN8AiW
0TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAAarMc+Uw16iGQ
4s7r4bjmzzi6cuAqefUqR49WkHMaxpx3FznUTP3YGd5Ya1ZUZT8QzMoJ8semtOYH
7yyGJMg1GdwuSGL/XWdhdPMcSCoX8I+n5kJF3o1sdlvZaHtNPDAcZv2+lt3bHtmK
7TMXCRBkM7Km5agvcWYTPzqzM5mXoetbUe57Xu1zfl1R+pUev/QvCZzHTE8nqOJQ
pMTa5TeRJhSx0qxeuz+xt94lNGebD2nVin4u7C2bVkqJLj3JaGoeStve+c9YimUA
I+6WfJYm2tPeJfFJKsSsrXiBE99UV+k2R7S7GqyJTOARfr1rFROzz6JEPULLu6Lu
3PNUBER/iwAjRz6hwtwotcTqT4Mn5bMAhAvrhzfSKfAm1PwCVwlYXJeVpdl1nEke
tiYdUMeQGwdkO+f5/53wRWkTjJ/6HEjuQT8NfVcQi2gFRVxeEj9rn1yCqMoikbRw
/VNQS6DsFMfkUy/G08J5/7qZyewmKU/bgfb3YDeH77meC33xqP4DfY4j9ZBd4L0v
zTkr4EQeFVD0eyFWvmKQEMHyzLB46OD5YEW2IWOTl3XPcxrWFrxNWOe5dvAbpDFs
wz0EpkUq+C7sXeFSdQU06W6EfDZPtEvqwxMyfGEON8x4qOr2sYucxUDzxt2JDs+v
ijBPtP237ReGIjvCMcj1pzv3CYkD5g==
-----END CERTIFICATE-----";
	}
}