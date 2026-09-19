using FinnasDbService;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.WebSockets;
using System.Text.Json;

namespace FinnasAPI.Controllers 
{
    [ApiController]
    [Route("api/[controller]")]
    public class CredoresController : ControllerBase
    {
        [HttpPost("create-credor")]
        public IActionResult CreateCredor([FromBody] CredoresRecord record)
        {
            var service = new CredoresDbService();
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

        [HttpPut("update-credor")]
        public IActionResult UpdateCredor([FromBody] CredoresRecord record)
        {
            var service = new CredoresDbService();
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

        [HttpGet("get-credor")]
        public IActionResult GetCredor([FromQuery] int id)
        {
            var service = new CredoresDbService();

            var ret = new CredoresRecord();            

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

        [HttpDelete("delete-credor")]
        public IActionResult DeleteCredor([FromQuery] int id)
        {
            var service = new CredoresDbService();

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

            return Ok(HttpStatusCode.NoContent);
        }
    }
}