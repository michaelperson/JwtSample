using JwtSample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtSample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TokenController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public TokenController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        //Pour le login
        [HttpPost]
        [AllowAnonymous]
        public IActionResult Login(string Login, string MotDePasse)
        {
            //vérifier si les champs sont remplis
            if(string.IsNullOrEmpty(Login) || string.IsNullOrEmpty(MotDePasse))
            {
                return NotFound(new { Login, MotDePasse });
            }
            //Récupération du user dans la db pour vérifier
            //Mode test ==> on considère ok
            //Création d'un userModel pour le retour
            UserModel user = new UserModel()
            {
                Id = 1,
                Login = Login,
                MotDePasse = MotDePasse,
                Nom = "PlusDeBiere",
                Prenom = "Roger"
            };

            //Création du Token et le retour vers le client
            user.Token = GenerateToken(user);

            //Permet le content négotiation et donc permet d'utiliser par défaut le système
            //de négociation COrs concernant l'origne et le content type
            //Maximise l'interopérabilité
            //!!!CORS doivent être configuré!!!
            return new OkObjectResult(user);
        }

        private string GenerateToken(UserModel user)
        {
            //1- Instanciation de l'objet permettant de créer le Token après configuration
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            //2- Récupérer la clé de signature
            Byte[] SigningKey = Encoding.UTF8.GetBytes(_configuration["jwt:key"]);

            //3- Composition de mon token via un Descripteur de sécurité
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor()
            {
                //3.1 La signature basée sur la clé
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(SigningKey),
                                                            SecurityAlgorithms.HmacSha512),

                //3.2 Date D'expiration
                Expires = DateTime.Now.AddMinutes(30),

                //3.3 issuer et l'audience
                Issuer = _configuration["jwt:issuer"],
                Audience = _configuration["jwt:audience"],

                //3.4 Ajout Payload (Claims) suivant vos besoins :)
                Subject = new ClaimsIdentity
                (
                    new List<Claim>
                    {
                        //3.4.1 GUID qui identifie de manière notre token pour éviter le "replay"
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        //3.4.2 Custom Claim
                        new Claim("Id", user.Id.ToString() ), 
                        //3.4.3 Ajout du nom dans les claims
                        new Claim(JwtRegisteredClaimNames.FamilyName, user.Nom),
                        //3.4.4 Ajout d'un rôle
                        new Claim("Rôles","Admin")
                    }
                  )
            };

            //4 - Générer le token de sécurité
           SecurityToken token =  jwtHandler.CreateToken(tokenDescriptor);

            //5 - Ecriture du Token en string
            string strJWT = jwtHandler.WriteToken(token);

            //6 - On retourne le token 
            return strJWT;
        }
    }
}
