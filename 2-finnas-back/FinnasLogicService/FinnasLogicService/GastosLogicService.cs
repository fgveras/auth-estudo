using InfraDbService;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Data.SqlClient;
using FinnasDbService;
using System.Data;

namespace FinnasLogicService
{
    public class GastosLogicService : DbServices
    {
        public List<CredoresRecord> GetCredoresCombobox()
        {
            var list = new List<CredoresRecord>();

            string command = $@"SELECT * FROM Credores";

            var combobox = Query(command, null);

            if (combobox is null) return new List<CredoresRecord>();

            foreach(DataRow row in combobox.Rows)
            {
                var record = new CredoresRecord();

                list.Add(new CredoresRecord()
                {
                    Id = Convert.ToInt32(row["Id"]),
                    NomeCredor = row["NomeCredor"].ToString(),
                });
            }

            return list;
        }        
    }

}
