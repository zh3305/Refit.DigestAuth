using System.Net;

namespace Refit.DigestAuth.Test;

public interface HaiKangISAPI
{

    [Get("/ISAPI/AccessControl/CaptureCardInfo?format=json")]
    Task<string> CaptureCardInfo( );

}

class Program
{
    public static async Task Main(string[] args)
    {
        var api = RestService.For<HaiKangISAPI>(
            new HttpClient(
                new DigestAuthHandler(new NetworkCredential(){UserName = "admin",Password = "xxxxx"})
                )
            {
                BaseAddress = new Uri("http://192.168.0.214")
            }
        );
        var data = await api.CaptureCardInfo();
        Console.WriteLine(data);
        Console.ReadKey();
    }
}