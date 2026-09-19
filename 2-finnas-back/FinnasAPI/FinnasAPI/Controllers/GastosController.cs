using FinnasAPI.Services;
using FinnasDbService;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.WebSockets;

namespace FinnasAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class GastosController : ControllerBase
    {

        [HttpPost("create-gasto")]
        public IActionResult Creategasto([FromBody] GastoRecord record)
        {
            var service = new GastoDbService();
            int ret = 0;

            try
            {
                ret = service.CreateOrUpdate(record);
            }
            catch (WebSocketException)
            {
                throw;
            }
            catch (Exception)
            {
                throw;
            }

            return Ok(ret);
        }

        [HttpPut("update-gasto")]
        public IActionResult Updategasto([FromBody] GastoRecord record)
        {
            var service = new GastoDbService();
            int ret = 0;

            try
            {
                ret = service.CreateOrUpdate(record);
            }
            catch (WebSocketException)
            {
                throw;
            }
            catch (Exception)
            {
                throw;
            }

            return Ok(ret);
        }

        [HttpGet("get-gasto")]
        public IActionResult Getgasto([FromQuery] int id)
        {
            var service = new GastoDbService();

            var ret = new GastoRecord();

            try
            {
                ret = service.Get(id);
            }
            catch (WebSocketException)
            {
                throw;
            }
            catch (Exception)
            {
                throw;
            }

            return Ok(ret);

        }

        [HttpDelete("delete-gasto")]
        public IActionResult Deletegasto([FromQuery] int id)
        {
            var service = new GastoDbService();

            try
            {
                service.Delete(id);
            }
            catch (WebSocketException)
            {
                throw;
            }
            catch (Exception)
            {
                throw;
            }

            return Ok(HttpStatusCode.Accepted);
        }

    }
}