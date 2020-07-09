using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Miqo.EncryptedJsonConfiguration;

namespace SampleWebAPI
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) {
            //var key = Convert.FromBase64String(Environment.GetEnvironmentVariable("SECRET_SAUCE"));
            var key = Convert.FromBase64String("A4HKnoCR/bdUOhogBi3EJpsEboYabtTy010eAoV8wKA=");

            return Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    config.AddEncryptedJsonFile("settings.ejson", key);
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
        }
    }
}
