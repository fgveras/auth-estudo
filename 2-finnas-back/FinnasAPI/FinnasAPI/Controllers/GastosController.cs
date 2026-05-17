using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using FinnasAPI.Services;

namespace FinnasAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class GastosController : ControllerBase
    {

        [HttpPut("AdicionarGasto")]
        public IActionResult AdicionarGasto()
        {

            return Ok();
        }
    }
}