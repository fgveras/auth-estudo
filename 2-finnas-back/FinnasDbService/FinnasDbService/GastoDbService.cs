using Microsoft.Data.SqlClient;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.Serialization;
using System.Data;
using Microsoft.Graph.Me.RegisteredDevices;

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
        public bool IsActive { get; set; }

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
        [Column("FormasPagamentoId")]
        public int? FormasPagamentoId { get; set; }

        [DataMember]
        [Required]
        [Column("DhCriacao")]
        public DateTime DhCriacao { get; set; }

        [DataMember]
        [Column("DhAtualizacao")]
        public DateTime? DhAtualizacao { get; set; }

        [DataMember]
        [Column("DhAtualizacao")]
        public DateTime? DtProximaParcela { get; set; }

        public GastoRecord()
        {
            Id = 0;
            UserId = 0;
            IsActive = false;
            ValorTotal = 0m;
            CredorId = null;
            CredorTexto = null;
            Motivo = null;
            Parcelado = false;
            QtdParcelas = null;
            FormasPagamentoId = null;
            DhCriacao = DateTime.UtcNow;
            DhAtualizacao = null;
            DtProximaParcela = null;
        }
    }

    public class GastoDbService()
    {
        private string _table = "Gastos";
        private string _connectionString = $@"Server=(localdb)\MSSQLLocalDB;Database=finnas_db2;Trusted_Connection=True;TrustServerCertificate=True;";
        private string _command = string.Empty;

        public GastoRecord? Get(int id)
        {

            _command = $@"SELECT * FROM {this._table} WHERE id = @id";


            using (SqlConnection connection = new SqlConnection(this._connectionString))
            using (SqlCommand command = new SqlCommand(_command, connection))
            {
                try
                {
                    command.Parameters.Add("@Id", SqlDbType.Int).Value = id;

                    connection.Open();

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            return new GastoRecord()
                            {
                                Id = reader.GetInt32(0),
                                UserId = reader.GetInt32(1),
                                IsActive = reader.GetBoolean(2),
                                ValorTotal = reader.GetDecimal(3),
                                CredorId = reader.GetInt32(4),
                                CredorTexto = reader.GetString(5),
                                Motivo = reader.GetString(6),
                                Parcelado = reader.GetBoolean(7),
                                QtdParcelas = reader.GetInt32(8),
                                FormasPagamentoId = reader.GetInt32(9),
                                DhCriacao = reader.GetDateTime(10),
                                DhAtualizacao = reader.GetDateTime(11),
                                DtProximaParcela = reader.GetDateTime(12)
                            };

                        };
                    }
                }
                catch (Exception)
                {
                    throw;
                }
            }

            return null;
        }

        public int CreateOrUpdate(GastoRecord record)
        {
            return record.Id == 0 ? Create(record) : Update(record);
        }

        public void Delete(int id)
        {
            this._command = $@"DELETE FROM {this._table} WHERE Id = @Id";

            using (SqlConnection cnn = new SqlConnection(this._connectionString))
            using (SqlCommand cmd = new SqlCommand(this._command, cnn))
            {
                cmd.Parameters.Add("@Id", SqlDbType.Int).Value = id;

                cnn.Open();
                cmd.ExecuteNonQuery();
            }
        }

        private int Create(GastoRecord record)
        {
            this._command = $@"
				INSERT INTO {this._table} (
	                UserId
	                , IsActive
	                , ValorTotal 
	                , CredorId 
	                , CredorTexto 
	                , Motivo
	                , Parcelado
                    , QtdParcelas
	                , FormasPagamentoId
	                , DhCriacao 
	                , DhAtualizacao 
	                , DtProximaParcela
				)
				VALUES (
                    @UserId
	                , @IsActive
	                , @ValorTotal 
	                , @CredorId 
	                , @CredorTexto 
	                , @Motivo
	                , @Parcelado
                    , @QtdParcelas
	                , @FormasPagamentoId
	                , @DhCriacao 
	                , @DhAtualizacao 
	                , @DtProximaParcela
				)
				SELECT SCOPE_IDENTITY();";

            using (SqlConnection connection = new SqlConnection(this._connectionString))
            using (SqlCommand command = new SqlCommand(this._command, connection))
            {
                try
                {
                    command.Parameters.Clear();

                    command.Parameters.Add("@UserId", SqlDbType.Int).Value = record.UserId;
                    command.Parameters.Add("@IsActive", SqlDbType.Bit).Value = record.IsActive;
                    command.Parameters.Add("@ValorTotal", SqlDbType.Decimal).Value = record.ValorTotal;
                    command.Parameters.Add("@CredorId", SqlDbType.Int).Value = record.CredorId;
                    command.Parameters.Add("@CredorTexto", SqlDbType.NVarChar, 100).Value = record.CredorTexto;
                    command.Parameters.Add("@Motivo", SqlDbType.NVarChar, 100).Value = record.Motivo;
                    command.Parameters.Add("@Parcelado", SqlDbType.Bit).Value = record.Parcelado;
                    command.Parameters.Add("@QtdParcelas", SqlDbType.Int).Value = record.QtdParcelas;
                    command.Parameters.Add("@FormasPagamentoId", SqlDbType.Int).Value = record.FormasPagamentoId;
                    command.Parameters.Add("@DhCriacao", SqlDbType.DateTime).Value = DateTime.Now;
                    command.Parameters.Add("@DhAtualizacao", SqlDbType.DateTime).Value = DateTime.Now;
                    command.Parameters.Add("@DtProximaParcela", SqlDbType.DateTime).Value = DateTime.Now;

                    connection.Open();
                    object result = command.ExecuteScalar();

                    if (!(result is null) && (result != DBNull.Value))
                    {
                        return Convert.ToInt32(result);
                    }

                    return 0;
                }
                catch (SqlException)
                {
                    throw;
                }
            }
        }

        private int Update(GastoRecord record)
        {
            _command = $@"
				UPDATE {this._table} SET 
	                UserId =  @UserId
	                , IsActive = @IsActive
	                , ValorTotal =  @ValorTotal
	                , CredorId =  @CredorId
	                , CredorTexto =  @CredorTexto
	                , Motivo = @Motivo
	                , Parcelado = @Parcelado
                    , QtdParcelas = @QtdParcelas
	                , FormasPagamentoId = @FormasPagamentoId
	                , DhCriacao =  @DhCriacao
	                , DhAtualizacao =  @DhAtualizacao
	                , DtProximaParcela = @DtProximaParcela
                WHERE
	                Id = @Id";

            using (SqlConnection connection = new SqlConnection(this._connectionString))
            using (SqlCommand command = new SqlCommand(_command, connection))
            {
                try
                {
                    command.Parameters.Clear();

                    command.Parameters.Add("@Id", SqlDbType.Int).Value = record.Id;
                    command.Parameters.Add("@UserId", SqlDbType.Int).Value = record.UserId;
                    command.Parameters.Add("@IsActive", SqlDbType.Bit).Value = record.IsActive;
                    command.Parameters.Add("@ValorTotal", SqlDbType.Decimal).Value = record.ValorTotal;
                    command.Parameters.Add("@CredorId", SqlDbType.Int).Value = record.CredorId;
                    command.Parameters.Add("@CredorTexto", SqlDbType.NVarChar, 100).Value = record.CredorTexto;
                    command.Parameters.Add("@Motivo", SqlDbType.NVarChar, 100).Value = record.Motivo;
                    command.Parameters.Add("@Parcelado", SqlDbType.Bit).Value = record.Parcelado;
                    command.Parameters.Add("@QtdParcelas", SqlDbType.Int).Value = record.QtdParcelas;
                    command.Parameters.Add("@FormasPagamentoId", SqlDbType.Int).Value = record.FormasPagamentoId;
                    command.Parameters.Add("@DhCriacao", SqlDbType.DateTime).Value = DateTime.Now;
                    command.Parameters.Add("@DhAtualizacao", SqlDbType.DateTime).Value = DateTime.Now;
                    command.Parameters.Add("@DtProximaParcela", SqlDbType.DateTime).Value = record.DtProximaParcela;

                    connection.Open();
                    command.ExecuteNonQuery();

                    return 0;
                }
                catch (SqlException)
                {
                    throw;
                }
            }
        }

    }
}
