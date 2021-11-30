using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtSample.Models
{
    public class UserModel
    {
        public int Id { get; set; }
        public string Nom { get; set; }
        public string Prenom { get;set; }
        public string Login { get; set; }

        public string MotDePasse { get; set; }

        public string Token { get; set; }


    }
}
