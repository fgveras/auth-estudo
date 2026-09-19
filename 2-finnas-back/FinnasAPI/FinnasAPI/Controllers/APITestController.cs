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
        public IActionResult UpdateCredor()
        {
            var service = new CredoresDbService();

            int outParam = service.CreateOrUpdate(new CredoresRecord
            {
                Id = 8,
                IsActive = true,
                NomeCredor = "Teste Update Backend",
                IsPessoaFisica = false,
                IsRecorrente = false,
                IsInstFin = false,
                CodigoInstFin = null,
                DhCriacao = DateTime.Now,
                DhAtualizacao = DateTime.Now
            });

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
    }
}