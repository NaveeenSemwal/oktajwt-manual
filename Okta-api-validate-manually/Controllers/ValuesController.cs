using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Okta_api_validate_manually.Controllers
{

    /// <summary>
    /// https://developer.okta.com/code/dotnet/jwt-validation
    /// </summary>


    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        // Replace with your authorization server URL:
        string issuer = "https://dev-678346.oktapreview.com/oauth2/default";

        private static async Task<JwtSecurityToken> ValidateToken(string token, string issuer, IConfigurationManager<OpenIdConnectConfiguration> configurationManager, CancellationToken ct = default(CancellationToken))
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                // Allow for some drift in server time
                // (a lower value is better; we recommend five minutes or less)
                ClockSkew = TimeSpan.FromMinutes(5),
                // See additional validation for aud below
                ValidateAudience =true,
                ValidAudience= "api://default"
            };

            try
            {
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);

                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException ex)
            {
                // Logging, etc.

                return null;
            }
        }

        // GET api/values
        [HttpGet]
        public async Task<IEnumerable<string>> Get()
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
              issuer + "/.well-known/oauth-authorization-server",
              new OpenIdConnectConfigurationRetriever(),
              new HttpDocumentRetriever());

          
           
            var accessToken = "eyJraWQiOiJDWWFkV2FRMGZaakxmNkhoN3YzeG41QjdYOGM3bXdDcEtUSkI3N3dBTUY4IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULndNYWMtbHNxZG96Ui1EYXhHOF9vNmlQVHlOY3R6S3VfS2g1UTBjV2d2MTgiLCJpc3MiOiJodHRwczovL2Rldi02NzgzNDYub2t0YXByZXZpZXcuY29tL29hdXRoMi9kZWZhdWx0IiwiYXVkIjoiYXBpOi8vZGVmYXVsdCIsImlhdCI6MTUzNTg3NTY4MSwiZXhwIjoxNTM1ODc5MjgxLCJjaWQiOiIwb2FnM2I3bmxjNXBaaHJlNjBoNyIsInNjcCI6WyJhY2Nlc3NfdG9rZW4iXSwic3ViIjoiMG9hZzNiN25sYzVwWmhyZTYwaDcifQ.J2CClYH1SxkgM20BIAhp0tvvSiHi3pmlUN8uR1m-6jpvH_DVK44Ulx2caKcZynIbuo7c6RgLCjgeluYuEw4wQ8_iE01Qex_edws-VilAnLbFlocg3DrRw9_4jGGXs8u9hf7O8EubZ9_J9aHN7nWzNKUJmXsOfHHJQBMqlBkKPoC_aB6g8R1ZIZAgxKIA6vOrBEWOmg8lDgnaYb4laQwm23qYUZRPNbL_sga9P_fXytmVorWConzdPkRAuHpHzsiiXENKr5zOZH2dwHAKGt1fxhIdgeCx6SOVtJ7yzoSx1SZBv02Ytb_tGkj05U30Hq-9gfGQ9kzxpyUjnox5ZYjJrQ";

            var validatedToken = await ValidateToken(accessToken, issuer, configurationManager);
            // Validate client ID
            var expectedClientId = "0oag3b7nlc5pZhre60h7"; // This Application's Client ID
            var clientIdMatches = validatedToken.Payload.TryGetValue("cid", out var rawCid)
                && rawCid.ToString() == expectedClientId;

            if (!clientIdMatches)
            {
                throw new SecurityTokenValidationException("The cid claim was invalid.");
            }

            foreach (var claim in validatedToken.Claims)
            {
                Console.WriteLine($"{claim.Type}\t{claim.Value}");
            }

            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
