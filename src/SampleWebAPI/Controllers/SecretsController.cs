using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SampleWebAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SecretsController : ControllerBase
    {
        private readonly AppSettings _settings;

        public SecretsController(AppSettings settings)
        {
            _settings = settings;
        }

        [HttpGet]
        public IActionResult Get()
        {
            return Ok(
                new {
                    secrets = new
                    {
                        address = _settings.Address,
                        username = _settings.Username,
                        password = _settings.Password
                    }
                });
        }
    }
}
