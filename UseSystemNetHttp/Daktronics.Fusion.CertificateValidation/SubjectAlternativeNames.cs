using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Daktronics.Fusion
{
	public sealed class SubjectAlternativeNames : IEquatable<SubjectAlternativeNames>
	{
		public static readonly SubjectAlternativeNames Empty =
			new SubjectAlternativeNames(Enumerable.Empty<string>(), Enumerable.Empty<string>());

		// Subject Alternative Name certificate extension object identifier (OID):
		// http://www.oid-info.com/get/2.5.29.17
		private const string SubjectAlternativeNameCertificateExtensionOid = "2.5.29.17";

		public SubjectAlternativeNames(IEnumerable<string> dnsNames, IEnumerable<string> ipAddresses)
		{
			this.DnsNames =
				dnsNames?.Where(dnsName => !string.IsNullOrWhiteSpace(dnsName)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ??
				throw new ArgumentNullException(nameof(dnsNames));

			this.IPAddresses =
				ipAddresses?.Distinct().Where(ipString => IPAddress.TryParse(ipString, out IPAddress _)).ToArray() ??
				throw new ArgumentNullException(nameof(ipAddresses));

			this.lazyAlternativeNames =
				new Lazy<IReadOnlyCollection<string>>(() => this.DnsNames.Concat(this.IPAddresses).ToArray());
		}

		public static SubjectAlternativeNames FromCertificate(X509Certificate2 certificate)
		{
			if (certificate == null) throw new ArgumentNullException(nameof(certificate));

			var subjectAlternativeNameExtension =
				certificate.Extensions.Cast<X509Extension>()
					.FirstOrDefault(
						extension =>
							extension.Oid.Value == SubjectAlternativeNameCertificateExtensionOid);

			if (subjectAlternativeNameExtension == null)
				return Empty;

			var dnsNames = new List<string>();
			var ipAddresses = new List<string>();

			foreach (
				var line in
				subjectAlternativeNameExtension.Format(multiLine: true)
					.Split("\r\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries))
			{
				var parts = line.Split('=');

				switch (parts[0])
				{
					case "DNS Name":
					{
						dnsNames.Add(parts[1]);
						break;
					}
					case "IP Address":
					{
						ipAddresses.Add(parts[1]);
						break;
					}
					default:
						continue;
				}
			}

			return new SubjectAlternativeNames(dnsNames, ipAddresses);
		}

		public IReadOnlyCollection<string> DnsNames { get; }

		// ReSharper disable once InconsistentNaming
		public IReadOnlyCollection<string> IPAddresses { get; }

		private readonly Lazy<IReadOnlyCollection<string>> lazyAlternativeNames;
		public IReadOnlyCollection<string> AlternativeNames => this.lazyAlternativeNames.Value;

		public bool Contains(SubjectAlternativeNames subjectAlternativeNames)
		{
			if (ReferenceEquals(this, subjectAlternativeNames))
				return true;

			if (subjectAlternativeNames == null)
				return false;

			return
				subjectAlternativeNames.DnsNames.All(
					dnsName => this.DnsNames.Contains(dnsName, StringComparer.OrdinalIgnoreCase))
				&&
				subjectAlternativeNames.IPAddresses.All(
					ipAddress => this.IPAddresses.Contains(ipAddress, StringComparer.OrdinalIgnoreCase));
		}

		public bool Equals(SubjectAlternativeNames other)
			=> this == other;

		public static bool operator ==(SubjectAlternativeNames leftHandSide, SubjectAlternativeNames rightHandSide)
		{
			if (ReferenceEquals(leftHandSide, rightHandSide))
				return true;

			if (ReferenceEquals(leftHandSide, null) ||
				ReferenceEquals(rightHandSide, null))
			{
				return false;
			}

			return
				leftHandSide.AlternativeNames.OrderBy(alternativeName => alternativeName)
					.SequenceEqual(rightHandSide.AlternativeNames.OrderBy(alternativeName => alternativeName),
						StringComparer.OrdinalIgnoreCase);
		}

		public static bool operator !=(SubjectAlternativeNames leftHandSide, SubjectAlternativeNames rightHandSide)
			=> !(leftHandSide == rightHandSide);

		public override bool Equals(object obj)
			=> this == obj as SubjectAlternativeNames;

		public override int GetHashCode()
			=> this.DnsNames.GetHashCode() ^ this.IPAddresses.GetHashCode();

		public override string ToString()
			=> string.Join(",", this.AlternativeNames);
	}
}