using Microsoft.Data.SqlClient;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.Serialization;
using System.Data;

namespace FinnasDbService
{
    [DataContract]
    public class GastoRecord
    {
        [DataMember]
        [Required]
        public int Id { get; set; }

        [DataMember]
        public int UserId { get; set; }

        [DataMember]
        public bool Ativo { get; set; }

        [DataMember]
        [Required]
        [Column("ValorTotal", TypeName = "decimal(18,2)")]
        public decimal ValorTotal { get; set; }

        [DataMember]
        [Column("CredorId")]
        public int? CredorId { get; set; }

        [DataMember]
        [MaxLength(300)]
        [Column("CredorTexto")]
        public string? CredorTexto { get; set; }

        [DataMember]
        [MaxLength(600)]
        [Column("Motivo")]
        public string? Motivo { get; set; }

        [DataMember]
        [Required]
        [Column("Parcelado")]
        public bool Parcelado { get; set; }

        [DataMember]
        [Column("QtdParcelas")]
        public int? QtdParcelas { get; set; }

        [DataMember]
        [Column("FormasPagamento")]
        public int? FormasPagamento { get; set; }

        [DataMember]
        [Required]
        [Column("CriadoEm")]
        public DateTime CriadoEm { get; set; }

        [DataMember]
        [Column("AtualizadoEm")]
        public DateTime? AtualizadoEm { get; set; }

        public GastoRecord()
        {
            Id = 0;
            UserId = 0;
            Ativo = false;
            ValorTotal = 0m;
            CredorId = null;
            CredorTexto = null;
            Motivo = null;
            Parcelado = false;
            QtdParcelas = null;
            FormasPagamento = null;
            CriadoEm = DateTime.UtcNow;
            AtualizadoEm = null;
        }
    }

    public class GastoDbService()
    {

        public SqlParameter[] SetParameters(GastoRecord record)
        {
            return [
                new SqlParameter("@UserId", SqlDbType.Int) { Value = record.UserId },
                new SqlParameter("@Ativo", SqlDbType.Bit) { Value = record.Ativo },
                new SqlParameter("@ValorTotal", SqlDbType.Decimal) { Value = record.ValorTotal },
                new SqlParameter("@CredorId", SqlDbType.Int) { Value = record.CredorId },
                new SqlParameter("@CredorTexto", SqlDbType.NVarChar, 300) { Value = record.CredorTexto },
                new SqlParameter("@Motivo", SqlDbType.NVarChar, 600) { Value = record.Motivo },
                new SqlParameter("@Parcelado", SqlDbType.Bit) { Value = record.Parcelado },
                new SqlParameter("@QtdParcelas", SqlDbType.Int) { Value = record.QtdParcelas },
                new SqlParameter("@FormasPagamento", SqlDbType.Int) { Value = record.FormasPagamento },
                new SqlParameter("@CriadoEm", SqlDbType.DateTime) { Value = record.CriadoEm },
                new SqlParameter("@AtualizadoEm", SqlDbType.DateTime) { Value = record.AtualizadoEm },
            ];
        }


        public int Create()
        {
            return 0;
        }

        public int Update()
        {
            return 0;
        }

        public GastoRecord Get()
        {
            return new GastoRecord();
        }

        public void Delete()
        {

        }

    }
}
