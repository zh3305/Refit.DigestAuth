# Refit  Digest Authentication  
using by @[CallumHoughton18](https://github.com/CallumHoughton18)  https://github.com/CallumHoughton18/csharp-dotnet-digest-authentication

RefitDigestAuth [![NuGet](https://img.shields.io/nuget/v/RefitDigestAuth.svg?style=flat-square)](https://www.nuget.org/packages/RefitDigestAuth)



## Example Usage

```c#
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
```

