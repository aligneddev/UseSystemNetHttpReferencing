using System;
using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UseSystemNetHttp.Test
{
	[TestClass]
	public class UseSystemNetHttpTests
	{
		[TestMethod]
		[ExpectedException(typeof(ArgumentNullException))]
		public void Constructor_NullClient_ThrowsException()
		{
			var x = new UseSystemNetHttp(null);
		}

		[TestMethod]
		public void Constructor_GetsClient_Works()
		{
			var x = new UseSystemNetHttp(new HttpClient());
		}
	}
}
