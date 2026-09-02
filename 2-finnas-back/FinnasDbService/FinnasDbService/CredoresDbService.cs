using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Graph.Drives.Item.Items.Item.Workbook.Names.Item.RangeNamespace.ColumnsBeforeWithCount;
using Microsoft.Graph.Models.ExternalConnectors;
using System.Data;
using System.Runtime.Serialization;

namespace FinnasDbService
{
    [DataContract]
    public class CredoresRecord
    {
		[DataMember]
		public int Id { get; set; }

        [DataMember]
		public bool IsActive { get; set; }
		
		[DataMember]
		public string NomeCredor  { get; set; }
		
		[DataMember]
		public bool IsPessoaFisica  { get; set; }
		
		[DataMember]
		public bool IsRecorrente  { get; set; }
		
		[DataMember]
		public bool IsInstFin  { get; set; }
		
		[DataMember]
		public string CodigoInstFin  { get; set; }
		
		[DataMember]
		public DateTime DhCriacao  { get; set; }
		
		[DataMember]
		public DateTime DhAtualizacao  { get; set; }

		public CredoresRecord()
		{
			Id = 0;
			IsActive = false;
			IsPessoaFisica = false;
			IsRecorrente = false;
			IsInstFin = false;
			DhCriacao = DateTime.MinValue;
			DhAtualizacao = DateTime.MinValue;
		}
    }

	public class CredoresDbService()
	{

		private string _table = "Credores";

        public CredoresRecord Get()
		{
			return new CredoresRecord();
        }

		public int CreateOrUpdate(CredoresRecord record)
		{
			return record.Id == 0 ? Create(record) : Update();  
		}

		public void Delete()
		{

		}

		private int Create(CredoresRecord record)
		{
            string connectioString = "Server=(localdb)\\MSSQLLocalDB;Database=finnas_db2;Trusted_Connection=True;TrustServerCertificate=True;";

            string query = $@"
				INSERT INTO {_table} (
					IsActive
					, NomeCredor
					, IsPessoaFisica
					, IsRecorrente
					, IsInstFin
					, CodigoInstFin
					, DhCriacao
					, DhAtualizacao
				)
				VALUES (
					@IsActive
					, @NomeCredor
					, @IsPessoaFisica
					, @IsRecorrente
					, @IsInstFin
					, @CodigoInstFin
					, @DhCriacao
					, @DhAtualizacao
				)
				SELECT SCOPE_IDENTITY();";
            
            using (SqlConnection connection = new SqlConnection(connectioString))
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.Add("@IsActive", SqlDbType.Bit).Value = record.IsActive;
                command.Parameters.Add("@NomeCredor", SqlDbType.NVarChar, 100).Value = record.NomeCredor;
                command.Parameters.Add("@IsPessoaFisica", SqlDbType.Bit).Value = record.IsPessoaFisica;
                command.Parameters.Add("@IsRecorrente", SqlDbType.Bit).Value = record.IsRecorrente;
                command.Parameters.Add("@IsInstFin", SqlDbType.Bit).Value = record.IsInstFin;
                command.Parameters.Add("@CodigoInstFin", SqlDbType.NVarChar, 50).Value = record.CodigoInstFin;
                command.Parameters.Add("@DhCriacao", SqlDbType.DateTime2).Value = record.DhCriacao;
                command.Parameters.Add("@DhAtualizacao", SqlDbType.DateTime2).Value = record.DhAtualizacao;
				
                try
                {             
                    connection.Open();
                    object result = command.ExecuteScalar();                    

					if(!(result is null) && (result != DBNull.Value))
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

		private int Update()
		{
            return 100;
        }

		private void CreateParameter(string name, SqlDbType type, object value)
		{
            
        }
	}
}