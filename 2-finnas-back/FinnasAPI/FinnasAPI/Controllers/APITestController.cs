using FinnasDbService;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace FinnasAPI.Controllers 
{
    [ApiController]
    [Route("api/[controller]")]
    public class APITestController : ControllerBase
    {
        [HttpGet("CreateCredor")]
        public IActionResult CreateCredor()
        {
            var service = new CredoresDbService();

            int outParam = service.CreateOrUpdate(new CredoresRecord
            {
                Id = 0,
                IsActive = true,
                NomeCredor = "Test Credor backend 2",
                IsPessoaFisica = false,
                IsRecorrente = false,
                IsInstFin = false,
                CodigoInstFin = "",
                DhCriacao = DateTime.Now,
                DhAtualizacao = DateTime.Now
            });

            return Ok(outParam);
        }

        [HttpGet("UpdateCredor")]
        public IActionResult UpdateCredor([FromBody] CredoresRecord record)
        {
            var service = new CredoresDbService();

            int outParam = service.CreateOrUpdate(record);

            return Ok(outParam);
        }

        [HttpGet("GetCreador")]
        public IActionResult GetCredor([FromQuery] int id)
        {
            var service = new CredoresDbService();

            var record = service.Get(id);

            var teste = JsonSerializer.Serialize(record);

            return Ok(teste);
        }

        [HttpGet("DeleteCredor")]
        public IActionResult DeleteCredor([FromQuery] int id)
        {
            var service = new CredoresDbService();

            service.Delete(id);            

            return Ok();
        }
    }
}