using System.Net.Http;

namespace UseSystemNetHttp
{
    public class UseSystemNetHttp
    {
	    private readonly HttpClient _httpClient;

	    public UseSystemNetHttp(HttpClient httpClient)
	    {
		    _httpClient = httpClient;
	    }
    }
}
