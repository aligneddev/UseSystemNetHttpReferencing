using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace UseSystemNetHttp
{
    public class UseSystemNetHttp
    {
	    private readonly HttpClient _httpClient;

	    public UseSystemNetHttp(HttpClient httpClient)
	    {
		    _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
	    }
    }
}
