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
		public string? CodigoInstFin  { get; set; }
		
		[DataMember]
		public DateTime? DhCriacao  { get; set; }
		
		[DataMember]
		public DateTime? DhAtualizacao  { get; set; }

		public CredoresRecord()
		{
			Id = 0;
			IsActive = false;
			IsPessoaFisica = false;
			IsRecorrente = false;
			IsInstFin = false;
			CodigoInstFin = null;
            DhCriacao = DateTime.MinValue;
			DhAtualizacao = DateTime.MinValue;
		}
    }

	public class CredoresDbService()
	{

		private string _table = "Credores";
		private string _connectionString = $@"Server=(localdb)\MSSQLLocalDB;Database=finnas_db2;Trusted_Connection=True;TrustServerCertificate=True;";
		private string _command = string.Empty;
		
        public CredoresRecord Get(int id)
		{

			_command = $@"SELECT * FROM Credores WHERE id = @id";


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
							return new CredoresRecord()
							{
								Id = reader.GetInt32(0)
								, IsActive = reader.GetBoolean(1)
								, NomeCredor = reader.GetString(2)
								, IsPessoaFisica = reader.GetBoolean(3)
								, IsRecorrente = reader.GetBoolean(4)
								, IsInstFin = reader.GetBoolean(5)
								, CodigoInstFin = reader.GetString(6)
								, DhCriacao = reader.GetDateTime(7)
								, DhAtualizacao = reader.GetDateTime(8)
							};

						};
					}
                }
				catch (Exception)
				{

					throw;
				}
			}

            return new CredoresRecord();
        }

		public int CreateOrUpdate(CredoresRecord record)
		{
			return record.Id == 0 ? Create(record) : Update(record);  
		}

		public void Delete(int id)
		{
			this._command = $@"DELETE FROM {this._table} WHERE Id = @Id";


            using (SqlConnection cnn = new SqlConnection(this._connectionString))
			using(SqlCommand cmd = new SqlCommand(this._command, cnn))
			{
				cmd.Parameters.Add("@Id", SqlDbType.Int).Value = id;
				
				cnn.Open();
				cmd.ExecuteNonQuery();
			}
		}

		private int Create(CredoresRecord record)
		{            
            this._command = $@"
				INSERT INTO {this._table} (
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
            
            using (SqlConnection connection = new SqlConnection(this._connectionString))
            using (SqlCommand command = new SqlCommand(this._command, connection))
            {
                try
                {             
					command.Parameters.Add("@IsActive", SqlDbType.Bit).Value = record.IsActive;
					command.Parameters.Add("@NomeCredor", SqlDbType.NVarChar, 100).Value = record.NomeCredor;
					command.Parameters.Add("@IsPessoaFisica", SqlDbType.Bit).Value = record.IsPessoaFisica;
					command.Parameters.Add("@IsRecorrente", SqlDbType.Bit).Value = record.IsRecorrente;
					command.Parameters.Add("@IsInstFin", SqlDbType.Bit).Value = record.IsInstFin;
					command.Parameters.Add("@CodigoInstFin", SqlDbType.NVarChar, 50).Value = record.CodigoInstFin;
					command.Parameters.Add("@DhCriacao", SqlDbType.DateTime).Value = DateTime.Now;
					command.Parameters.Add("@DhAtualizacao", SqlDbType.DateTime).Value = DateTime.Now;
				
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

		private int Update(CredoresRecord record)
		{
			_command = $@"
				UPDATE CREDORES SET 
					IsActive = @IsActive
					, NomeCredor =  @NomeCredor
					, IsPessoaFisica =  @IsPessoaFisica
					, IsRecorrente =  @IsRecorrente
					, IsInstFin =  @IsInstFin
					, CodigoInstFin = @CodigoInstFin					
					, DhAtualizacao =  @DhAtualizacao
				WHERE
					Id = @Id";

            using (SqlConnection connection = new SqlConnection(this._connectionString))
            using (SqlCommand command = new SqlCommand(_command, connection))
            {
                try
                {
					command.Parameters.Add("@Id", SqlDbType.Int).Value = record.Id;
					command.Parameters.Add("@IsActive", SqlDbType.Bit).Value = record.IsActive;
					command.Parameters.Add("@NomeCredor", SqlDbType.NVarChar, 100).Value = record.NomeCredor;
					command.Parameters.Add("@IsPessoaFisica", SqlDbType.Bit).Value = record.IsPessoaFisica;
					command.Parameters.Add("@IsRecorrente", SqlDbType.Bit).Value = record.IsRecorrente;
					command.Parameters.Add("@IsInstFin", SqlDbType.Bit).Value = record.IsInstFin;
					command.Parameters.Add("@CodigoInstFin", SqlDbType.NVarChar, 50).Value = record.CodigoInstFin;					
					command.Parameters.Add("@DhAtualizacao", SqlDbType.DateTime2).Value = DateTime.Now;

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

		private void CreateParameter(string name, SqlDbType type, object value)
		{
            
        }
	}
}